import type { D1Database } from '@cloudflare/workers-types'
import type {
  Subscription,
  SubscriptionInsert,
  SubscriptionFilters,
  SubscriptionStats,
  SubscriptionStatus
} from '../types'

/**
 * Manages subscription records in D1
 */
export class SubscriptionService {
  constructor(private db: D1Database) {}

  /**
   * Ensure the subscriptions table exists
   */
  async ensureTable(): Promise<void> {
    await this.db.prepare(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL,
        stripe_customer_id TEXT NOT NULL,
        stripe_subscription_id TEXT NOT NULL UNIQUE,
        stripe_price_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'incomplete',
        current_period_start INTEGER NOT NULL DEFAULT 0,
        current_period_end INTEGER NOT NULL DEFAULT 0,
        cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
      )
    `).run()

    // Indexes for common lookups
    await this.db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)
    `).run()
    await this.db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer_id ON subscriptions(stripe_customer_id)
    `).run()
    await this.db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription_id ON subscriptions(stripe_subscription_id)
    `).run()
    await this.db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)
    `).run()
  }

  /**
   * Create a new subscription record
   */
  async create(data: SubscriptionInsert): Promise<Subscription> {
    const result = await this.db.prepare(`
      INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, stripe_price_id, status, current_period_start, current_period_end, cancel_at_period_end)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      RETURNING *
    `).bind(
      data.userId,
      data.stripeCustomerId,
      data.stripeSubscriptionId,
      data.stripePriceId,
      data.status,
      data.currentPeriodStart,
      data.currentPeriodEnd,
      data.cancelAtPeriodEnd ? 1 : 0
    ).first()

    return this.mapRow(result as any)
  }

  /**
   * Upsert a subscription by stripe_subscription_id (INSERT or UPDATE on conflict)
   */
  async upsert(data: SubscriptionInsert): Promise<Subscription> {
    const result = await this.db.prepare(`
      INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, stripe_price_id, status, current_period_start, current_period_end, cancel_at_period_end)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(stripe_subscription_id) DO UPDATE SET
        status = excluded.status,
        stripe_price_id = excluded.stripe_price_id,
        current_period_start = excluded.current_period_start,
        current_period_end = excluded.current_period_end,
        cancel_at_period_end = excluded.cancel_at_period_end,
        updated_at = unixepoch()
      RETURNING *
    `).bind(
      data.userId,
      data.stripeCustomerId,
      data.stripeSubscriptionId,
      data.stripePriceId,
      data.status,
      data.currentPeriodStart,
      data.currentPeriodEnd,
      data.cancelAtPeriodEnd ? 1 : 0
    ).first()

    return this.mapRow(result as any)
  }

  /**
   * Update a subscription by its Stripe subscription ID
   */
  async updateByStripeId(stripeSubscriptionId: string, data: Partial<SubscriptionInsert>): Promise<Subscription | null> {
    const sets: string[] = []
    const values: any[] = []

    if (data.status !== undefined) {
      sets.push('status = ?')
      values.push(data.status)
    }
    if (data.stripePriceId !== undefined) {
      sets.push('stripe_price_id = ?')
      values.push(data.stripePriceId)
    }
    if (data.currentPeriodStart !== undefined) {
      sets.push('current_period_start = ?')
      values.push(data.currentPeriodStart)
    }
    if (data.currentPeriodEnd !== undefined) {
      sets.push('current_period_end = ?')
      values.push(data.currentPeriodEnd)
    }
    if (data.cancelAtPeriodEnd !== undefined) {
      sets.push('cancel_at_period_end = ?')
      values.push(data.cancelAtPeriodEnd ? 1 : 0)
    }

    if (sets.length === 0) return this.getByStripeSubscriptionId(stripeSubscriptionId)

    sets.push('updated_at = unixepoch()')
    values.push(stripeSubscriptionId)

    const result = await this.db.prepare(`
      UPDATE subscriptions SET ${sets.join(', ')} WHERE stripe_subscription_id = ? RETURNING *
    `).bind(...values).first()

    return result ? this.mapRow(result as any) : null
  }

  /**
   * Get subscription by Stripe subscription ID
   */
  async getByStripeSubscriptionId(stripeSubscriptionId: string): Promise<Subscription | null> {
    const result = await this.db.prepare(
      'SELECT * FROM subscriptions WHERE stripe_subscription_id = ?'
    ).bind(stripeSubscriptionId).first()
    return result ? this.mapRow(result as any) : null
  }

  /**
   * Get the active subscription for a user
   */
  async getByUserId(userId: string): Promise<Subscription | null> {
    const result = await this.db.prepare(
      "SELECT * FROM subscriptions WHERE user_id = ? ORDER BY CASE WHEN status = 'active' THEN 0 WHEN status = 'trialing' THEN 1 ELSE 2 END, updated_at DESC LIMIT 1"
    ).bind(userId).first()
    return result ? this.mapRow(result as any) : null
  }

  /**
   * Get subscription by Stripe customer ID
   */
  async getByStripeCustomerId(stripeCustomerId: string): Promise<Subscription | null> {
    const result = await this.db.prepare(
      'SELECT * FROM subscriptions WHERE stripe_customer_id = ? ORDER BY updated_at DESC LIMIT 1'
    ).bind(stripeCustomerId).first()
    return result ? this.mapRow(result as any) : null
  }

  /**
   * Find the userId linked to a Stripe customer ID
   */
  async getUserIdByStripeCustomer(stripeCustomerId: string): Promise<string | null> {
    const result = await this.db.prepare(
      'SELECT user_id FROM subscriptions WHERE stripe_customer_id = ? LIMIT 1'
    ).bind(stripeCustomerId).first() as { user_id: string } | null
    return result?.user_id ?? null
  }

  /**
   * List subscriptions with filters and pagination
   */
  async list(filters: SubscriptionFilters = {}): Promise<{ subscriptions: Subscription[]; total: number }> {
    const where: string[] = []
    const values: any[] = []

    if (filters.status) {
      where.push('status = ?')
      values.push(filters.status)
    }
    if (filters.userId) {
      where.push('user_id = ?')
      values.push(filters.userId)
    }
    if (filters.stripeCustomerId) {
      where.push('stripe_customer_id = ?')
      values.push(filters.stripeCustomerId)
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''
    const sortBy = filters.sortBy || 'created_at'
    const sortOrder = filters.sortOrder || 'desc'
    const limit = Math.min(filters.limit || 50, 100)
    const page = filters.page || 1
    const offset = (page - 1) * limit

    // Get total count
    const countResult = await this.db.prepare(
      `SELECT COUNT(*) as count FROM subscriptions ${whereClause}`
    ).bind(...values).first() as { count: number }

    // Get paginated results
    const results = await this.db.prepare(
      `SELECT s.*, u.email as user_email FROM subscriptions s LEFT JOIN auth_user u ON s.user_id = u.id ${whereClause} ORDER BY ${sortBy} ${sortOrder} LIMIT ? OFFSET ?`
    ).bind(...values, limit, offset).all()

    return {
      subscriptions: (results.results || []).map((r: any) => this.mapRow(r)),
      total: countResult?.count || 0
    }
  }

  /**
   * Get subscription stats
   */
  async getStats(): Promise<SubscriptionStats> {
    const result = await this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN status = 'canceled' THEN 1 ELSE 0 END) as canceled,
        SUM(CASE WHEN status = 'past_due' THEN 1 ELSE 0 END) as past_due,
        SUM(CASE WHEN status = 'trialing' THEN 1 ELSE 0 END) as trialing
      FROM subscriptions
    `).first() as any

    return {
      total: result?.total || 0,
      active: result?.active || 0,
      canceled: result?.canceled || 0,
      pastDue: result?.past_due || 0,
      trialing: result?.trialing || 0
    }
  }

  /**
   * Delete a subscription record by Stripe subscription ID
   */
  async deleteByStripeId(stripeSubscriptionId: string): Promise<boolean> {
    const result = await this.db.prepare(
      'DELETE FROM subscriptions WHERE stripe_subscription_id = ?'
    ).bind(stripeSubscriptionId).run()
    return (result.meta?.changes || 0) > 0
  }

  private mapRow(row: Record<string, any>): Subscription {
    return {
      id: row.id,
      userId: row.user_id,
      stripeCustomerId: row.stripe_customer_id,
      stripeSubscriptionId: row.stripe_subscription_id,
      stripePriceId: row.stripe_price_id,
      status: row.status as SubscriptionStatus,
      currentPeriodStart: row.current_period_start,
      currentPeriodEnd: row.current_period_end,
      cancelAtPeriodEnd: !!row.cancel_at_period_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      // Attach email if joined
      ...(row.user_email ? { userEmail: row.user_email } : {})
    } as Subscription
  }
}
