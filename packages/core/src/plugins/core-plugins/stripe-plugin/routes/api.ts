import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { RbacService } from '../../../../services/rbac'
import { PluginService } from '../../../../services'
import { SubscriptionService } from '../services/subscription-service'
import { StripeEventService } from '../services/stripe-event-service'
import { StripeAPI } from '../services/stripe-api'
import type { Bindings, Variables } from '../../../../app'
import type {
  StripePluginSettings,
  StripeEvent,
  StripeSubscriptionObject,
  StripeCheckoutSession,
  StripeInvoice,
  SubscriptionStatus,
  SubscriptionFilters
} from '../types'
import { DEFAULT_SETTINGS } from '../types'

const apiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// ============================================================================
// Helpers
// ============================================================================

async function getSettings(db: any): Promise<StripePluginSettings> {
  try {
    const pluginService = new PluginService(db)
    const plugin = await pluginService.getPlugin('stripe')
    if (plugin?.settings) {
      const settings = typeof plugin.settings === 'string' ? JSON.parse(plugin.settings) : plugin.settings
      return { ...DEFAULT_SETTINGS, ...settings }
    }
  } catch { /* ignore */ }
  return DEFAULT_SETTINGS
}

function mapStripeStatus(status: string): SubscriptionStatus {
  const map: Record<string, SubscriptionStatus> = {
    active: 'active',
    canceled: 'canceled',
    past_due: 'past_due',
    trialing: 'trialing',
    unpaid: 'unpaid',
    paused: 'paused',
    incomplete: 'incomplete',
    incomplete_expired: 'incomplete_expired'
  }
  return map[status] || 'incomplete'
}

// ============================================================================
// Webhook — No auth, verified by Stripe signature
// ============================================================================

apiRoutes.post('/webhook', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)

  if (!settings.stripeWebhookSecret) {
    return c.json({ error: 'Webhook secret not configured' }, 500)
  }

  // Must read raw body for signature verification
  const rawBody = await c.req.text()
  const sigHeader = c.req.header('stripe-signature') || ''

  const stripeApi = new StripeAPI(settings.stripeSecretKey)
  const isValid = await stripeApi.verifyWebhookSignature(rawBody, sigHeader, settings.stripeWebhookSecret)

  if (!isValid) {
    return c.json({ error: 'Invalid signature' }, 400)
  }

  const event: StripeEvent = JSON.parse(rawBody)
  const subscriptionService = new SubscriptionService(db)
  const eventService = new StripeEventService(db)
  await Promise.all([subscriptionService.ensureTable(), eventService.ensureTable()])

  // Determine object ID and type for the event log
  const obj = event.data.object as any
  const objectId = obj?.id || ''
  const objectType = obj?.object || event.type.split('.')[0] || ''

  try {
    switch (event.type) {
      case 'customer.subscription.created': {
        const sub = event.data.object as unknown as StripeSubscriptionObject
        const userId = sub.metadata?.sonicjs_user_id || await subscriptionService.getUserIdByStripeCustomer(sub.customer) || ''

        await subscriptionService.create({
          userId,
          stripeCustomerId: sub.customer,
          stripeSubscriptionId: sub.id,
          stripePriceId: sub.items.data[0]?.price.id || '',
          status: mapStripeStatus(sub.status),
          currentPeriodStart: sub.current_period_start,
          currentPeriodEnd: sub.current_period_end,
          cancelAtPeriodEnd: sub.cancel_at_period_end
        })

        console.log(`[Stripe] Subscription created: ${sub.id}`)
        break
      }

      case 'customer.subscription.updated': {
        const sub = event.data.object as unknown as StripeSubscriptionObject
        await subscriptionService.updateByStripeId(sub.id, {
          status: mapStripeStatus(sub.status),
          stripePriceId: sub.items.data[0]?.price.id || undefined,
          currentPeriodStart: sub.current_period_start,
          currentPeriodEnd: sub.current_period_end,
          cancelAtPeriodEnd: sub.cancel_at_period_end
        })

        console.log(`[Stripe] Subscription updated: ${sub.id} -> ${sub.status}`)
        break
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object as unknown as StripeSubscriptionObject
        await subscriptionService.updateByStripeId(sub.id, {
          status: 'canceled'
        })

        console.log(`[Stripe] Subscription deleted: ${sub.id}`)
        break
      }

      case 'checkout.session.completed': {
        const session = event.data.object as unknown as StripeCheckoutSession
        const userId = session.metadata?.sonicjs_user_id

        if (userId && session.subscription) {
          const existing = await subscriptionService.getByStripeSubscriptionId(session.subscription)
          if (existing && !existing.userId) {
            await subscriptionService.updateByStripeId(session.subscription, {
              userId
            } as any)
          }
        }

        console.log(`[Stripe] Checkout completed: ${session.id}`)
        break
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object as unknown as StripeInvoice
        if (invoice.subscription) {
          await subscriptionService.updateByStripeId(invoice.subscription, {
            status: 'active'
          })
        }
        console.log(`[Stripe] Payment succeeded for invoice: ${invoice.id}`)
        break
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object as unknown as StripeInvoice
        if (invoice.subscription) {
          await subscriptionService.updateByStripeId(invoice.subscription, {
            status: 'past_due'
          })
        }
        console.log(`[Stripe] Payment failed for invoice: ${invoice.id}`)
        break
      }

      default:
        console.log(`[Stripe] Unhandled event type: ${event.type}`)
        await eventService.log({
          stripeEventId: event.id,
          type: event.type,
          objectId,
          objectType,
          data: event.data.object as any,
          status: 'ignored'
        })
        return c.json({ received: true })
    }

    // Log successfully processed event
    await eventService.log({
      stripeEventId: event.id,
      type: event.type,
      objectId,
      objectType,
      data: event.data.object as any,
      status: 'processed'
    })
  } catch (error) {
    // Log failed event
    await eventService.log({
      stripeEventId: event.id,
      type: event.type,
      objectId,
      objectType,
      data: event.data.object as any,
      status: 'failed',
      error: error instanceof Error ? error.message : String(error)
    }).catch(() => {}) // Don't let logging failure mask the real error

    console.error(`[Stripe] Error processing webhook event ${event.type}:`, error)
    return c.json({ error: 'Webhook processing failed' }, 500)
  }

  return c.json({ received: true })
})

// ============================================================================
// Authenticated API Routes
// ============================================================================

// Create checkout session for current user
apiRoutes.post('/create-checkout-session', requireAuth(), async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const settings = await getSettings(db)
  if (!settings.stripeSecretKey) {
    return c.json({ error: 'Stripe not configured' }, 500)
  }

  const body = await c.req.json().catch(() => ({})) as { priceId?: string }
  const priceId = body.priceId || settings.stripePriceId
  if (!priceId) {
    return c.json({ error: 'No price ID specified' }, 400)
  }

  const stripeApi = new StripeAPI(settings.stripeSecretKey)
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  // Check if user already has a Stripe customer ID
  const existingSub = await subscriptionService.getByUserId(user.userId)
  let customerId = existingSub?.stripeCustomerId

  if (!customerId) {
    // Try to find existing customer by email, or create one
    const existing = await stripeApi.findCustomerByEmail(user.email)
    if (existing) {
      customerId = existing.id
    } else {
      const customer = await stripeApi.createCustomer({
        email: user.email,
        metadata: { sonicjs_user_id: user.userId }
      })
      customerId = customer.id
    }
  }

  const origin = new URL(c.req.url).origin
  const session = await stripeApi.createCheckoutSession({
    priceId,
    customerId,
    successUrl: `${origin}${settings.successUrl}?session_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${origin}${settings.cancelUrl}`,
    metadata: { sonicjs_user_id: user.userId }
  })

  return c.json({ sessionId: session.id, url: session.url })
})

// Get current user's subscription
apiRoutes.get('/subscription', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const db = c.env.DB
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  const subscription = await subscriptionService.getByUserId(user.userId)
  if (!subscription) {
    return c.json({ subscription: null })
  }

  return c.json({ subscription })
})

// ============================================================================
// Admin API Routes
// ============================================================================

// List all subscriptions (admin only)
apiRoutes.get('/subscriptions', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) return c.json({ error: 'Access denied' }, 403)

  const db = c.env.DB
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  const filters: SubscriptionFilters = {
    status: c.req.query('status') as SubscriptionStatus | undefined,
    page: c.req.query('page') ? parseInt(c.req.query('page')!) : 1,
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    sortBy: (c.req.query('sortBy') as any) || 'created_at',
    sortOrder: (c.req.query('sortOrder') as any) || 'desc'
  }

  const result = await subscriptionService.list(filters)
  return c.json(result)
})

// Get subscription stats (admin only)
apiRoutes.get('/stats', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) return c.json({ error: 'Access denied' }, 403)

  const db = c.env.DB
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  const stats = await subscriptionService.getStats()
  return c.json(stats)
})

// ============================================================================
// Sync Subscriptions from Stripe API
// ============================================================================

apiRoutes.post('/sync-subscriptions', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) return c.json({ error: 'Access denied' }, 403)

  const db = c.env.DB
  const settings = await getSettings(db)

  if (!settings.stripeSecretKey) {
    return c.json({ error: 'Stripe secret key not configured' }, 400)
  }

  const stripeApi = new StripeAPI(settings.stripeSecretKey)
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  try {
    const allSubs = await stripeApi.listAllSubscriptions()
    let synced = 0
    let errors = 0

    for (const sub of allSubs) {
      try {
        const userId = sub.metadata?.sonicjs_user_id || await subscriptionService.getUserIdByStripeCustomer(sub.customer) || ''
        await subscriptionService.upsert({
          userId,
          stripeCustomerId: typeof sub.customer === 'string' ? sub.customer : sub.customer.id,
          stripeSubscriptionId: sub.id,
          stripePriceId: sub.items?.data?.[0]?.price?.id || '',
          status: mapStripeStatus(sub.status),
          currentPeriodStart: sub.current_period_start,
          currentPeriodEnd: sub.current_period_end,
          cancelAtPeriodEnd: sub.cancel_at_period_end
        })
        synced++
      } catch (err) {
        console.error(`[Stripe Sync] Failed to upsert subscription ${sub.id}:`, err)
        errors++
      }
    }

    return c.json({
      success: true,
      total: allSubs.length,
      synced,
      errors
    })
  } catch (error) {
    console.error('[Stripe Sync] Error:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Sync failed'
    }, 500)
  }
})

// ============================================================================
// Stripe Events Log
// ============================================================================

apiRoutes.get('/events', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) return c.json({ error: 'Access denied' }, 403)

  const db = c.env.DB
  const eventService = new StripeEventService(db)
  await eventService.ensureTable()

  const filters = {
    type: c.req.query('type') || undefined,
    status: c.req.query('status') as any || undefined,
    objectId: c.req.query('objectId') || undefined,
    page: c.req.query('page') ? parseInt(c.req.query('page')!) : 1,
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50
  }

  const [result, stats, types] = await Promise.all([
    eventService.list(filters),
    eventService.getStats(),
    eventService.getDistinctTypes()
  ])

  return c.json({ ...result, stats, types })
})

export { apiRoutes as stripeApiRoutes }
