import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { RbacService } from '../../../../services/rbac'
import { PluginService } from '../../../../services'
import { SubscriptionService } from '../services/subscription-service'
import { StripeEventService } from '../services/stripe-event-service'
import { renderSubscriptionsPage } from '../components/subscriptions-page'
import { renderEventsPage } from '../components/events-page'
import { renderStripeTabBar } from '../components/tab-bar'
import type { Bindings, Variables } from '../../../../app'
import type { StripePluginSettings, SubscriptionStatus } from '../types'
import { DEFAULT_SETTINGS } from '../types'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())

// Check admin role
adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
    return c.text('Access denied', 403)
  }
  return next()
})

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

// Subscriptions dashboard
adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const subscriptionService = new SubscriptionService(db)
  await subscriptionService.ensureTable()

  const page = parseInt(c.req.query('page') || '1')
  const limit = 50
  const statusFilter = c.req.query('status') as SubscriptionStatus | undefined

  const [{ subscriptions, total }, stats] = await Promise.all([
    subscriptionService.list({ status: statusFilter, page, limit }),
    subscriptionService.getStats()
  ])

  const totalPages = Math.ceil(total / limit)

  const html = renderSubscriptionsPage({
    subscriptions: subscriptions as any,
    stats,
    filters: { status: statusFilter, page, totalPages },
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems')
  })

  return c.html(html)
})

// Events log page
adminRoutes.get('/events', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const eventService = new StripeEventService(db)
  await eventService.ensureTable()

  const page = parseInt(c.req.query('page') || '1')
  const limit = 50
  const typeFilter = c.req.query('type') || undefined
  const statusFilter = c.req.query('status') as 'processed' | 'failed' | 'ignored' | undefined

  const [{ events, total }, stats, types] = await Promise.all([
    eventService.list({ type: typeFilter, status: statusFilter, page, limit }),
    eventService.getStats(),
    eventService.getDistinctTypes()
  ])

  const totalPages = Math.ceil(total / limit)

  const html = renderEventsPage({
    events,
    stats,
    types,
    filters: { type: typeFilter, status: statusFilter, page, totalPages },
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems')
  })

  return c.html(html)
})

// Settings page
adminRoutes.get('/settings', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const settings = await getSettings(db)

  const { renderAdminLayoutCatalyst } = await import('../../../../templates/layouts/admin-layout-catalyst.template')

  const content = `
    <div>
      <div class="mb-6">
        <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Stripe</h1>
        <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
          Configure your Stripe API keys and checkout options.
        </p>
      </div>

      ${renderStripeTabBar('/admin/plugins/stripe/settings')}

      <div id="settings-message" class="hidden mb-4 rounded-lg p-4 text-sm"></div>

      <form id="stripe-settings-form" class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm divide-y divide-zinc-950/5 dark:divide-white/5">
        <div class="p-6 space-y-5">
          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Publishable Key</label>
            <input type="text" name="stripePublishableKey" value="${settings.stripePublishableKey}"
              placeholder="pk_..."
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Your Stripe publishable key (starts with pk_)</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Secret Key</label>
            <input type="password" name="stripeSecretKey" value="${settings.stripeSecretKey}"
              placeholder="sk_..."
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Your Stripe secret API key (starts with sk_)</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Webhook Signing Secret</label>
            <input type="password" name="stripeWebhookSecret" value="${settings.stripeWebhookSecret}"
              placeholder="whsec_..."
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Stripe webhook endpoint signing secret (starts with whsec_)</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Default Price ID</label>
            <input type="text" name="stripePriceId" value="${settings.stripePriceId || ''}"
              placeholder="price_..."
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Default Stripe Price ID for checkout sessions (optional)</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Checkout Success URL</label>
            <input type="text" name="successUrl" value="${settings.successUrl}"
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Redirect URL after successful checkout</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Checkout Cancel URL</label>
            <input type="text" name="cancelUrl" value="${settings.cancelUrl}"
              class="w-full rounded-lg border-0 bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-cyan-500" />
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Redirect URL if checkout is cancelled</p>
          </div>
        </div>

        <div class="px-6 py-4 flex justify-end">
          <button type="submit"
            class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            Save Settings
          </button>
        </div>
      </form>
    </div>

    <script>
      document.getElementById('stripe-settings-form').addEventListener('submit', async (e) => {
        e.preventDefault()
        const form = e.target
        const data = Object.fromEntries(new FormData(form))
        const msg = document.getElementById('settings-message')
        try {
          const res = await fetch('/admin/plugins/stripe/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          })
          const result = await res.json()
          msg.className = result.success
            ? 'mb-4 rounded-lg p-4 text-sm bg-emerald-400/10 text-emerald-500 dark:text-emerald-400 ring-1 ring-inset ring-emerald-400/20'
            : 'mb-4 rounded-lg p-4 text-sm bg-red-400/10 text-red-500 dark:text-red-400 ring-1 ring-inset ring-red-400/20'
          msg.textContent = result.success ? 'Settings saved successfully.' : (result.error || 'Failed to save settings.')
        } catch {
          msg.className = 'mb-4 rounded-lg p-4 text-sm bg-red-400/10 text-red-500 dark:text-red-400 ring-1 ring-inset ring-red-400/20'
          msg.textContent = 'Network error. Please try again.'
        }
      })
    </script>
  `

  return c.html(renderAdminLayoutCatalyst({
    title: 'Stripe Settings',
    pageTitle: 'Stripe Settings',
    currentPath: '/admin/plugins/stripe',
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    content,
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems')
  }))
})

// Save settings
adminRoutes.post('/settings', async (c) => {
  try {
    const body = await c.req.json()
    const db = c.env.DB

    await db.prepare(`
      UPDATE plugins
      SET settings = ?,
          updated_at = unixepoch()
      WHERE id = 'stripe'
    `).bind(JSON.stringify(body)).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Error saving Stripe settings:', error)
    return c.json({ success: false, error: 'Failed to save settings' }, 500)
  }
})

export { adminRoutes as stripeAdminRoutes }
