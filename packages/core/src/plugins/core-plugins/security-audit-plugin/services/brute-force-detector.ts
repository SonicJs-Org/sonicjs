import type { KVNamespace } from '@cloudflare/workers-types'
import type { SecurityAuditSettings } from '../types'
import { DEFAULT_SETTINGS } from '../types'

const KV_PREFIX = 'security:bf:'
const LOCK_PREFIX = 'security:locked:'

export class BruteForceDetector {
  private settings: SecurityAuditSettings['bruteForce']

  constructor(
    private kv: KVNamespace,
    settings?: SecurityAuditSettings['bruteForce']
  ) {
    this.settings = settings || DEFAULT_SETTINGS.bruteForce
  }

  async recordFailedAttempt(ip: string, email: string): Promise<{
    ipCount: number
    emailCount: number
    shouldLockIP: boolean
    shouldLockEmail: boolean
    isSuspicious: boolean
  }> {
    if (!this.settings.enabled || !this.kv) {
      return { ipCount: 0, emailCount: 0, shouldLockIP: false, shouldLockEmail: false, isSuspicious: false }
    }

    const now = Date.now()
    const windowMs = this.settings.windowMinutes * 60 * 1000

    // Increment IP counter
    const ipKey = `${KV_PREFIX}ip:${ip}`
    const ipCount = await this.incrementCounter(ipKey, windowMs)

    // Increment email counter
    const emailKey = `${KV_PREFIX}email:${email}`
    const emailCount = await this.incrementCounter(emailKey, windowMs)

    // Check for multi-email from single IP (suspicious)
    const ipEmailsKey = `${KV_PREFIX}ip-emails:${ip}`
    await this.addToSet(ipEmailsKey, email, windowMs)
    const emailsFromIP = await this.getSetSize(ipEmailsKey)
    const isSuspicious = emailsFromIP >= 5

    const shouldLockIP = ipCount >= this.settings.maxFailedAttemptsPerIP
    const shouldLockEmail = emailCount >= this.settings.maxFailedAttemptsPerEmail

    return { ipCount, emailCount, shouldLockIP, shouldLockEmail, isSuspicious }
  }

  async isLocked(ip: string, email: string): Promise<{ locked: boolean, reason?: string }> {
    if (!this.settings.enabled || !this.kv) {
      return { locked: false }
    }

    const ipLocked = await this.kv.get(`${LOCK_PREFIX}ip:${ip}`)
    if (ipLocked) {
      return { locked: true, reason: 'IP address temporarily locked due to excessive failed login attempts' }
    }

    const emailLocked = await this.kv.get(`${LOCK_PREFIX}email:${email}`)
    if (emailLocked) {
      return { locked: true, reason: 'Account temporarily locked due to excessive failed login attempts' }
    }

    return { locked: false }
  }

  async lockIP(ip: string): Promise<void> {
    if (!this.kv) return
    const ttl = this.settings.lockoutDurationMinutes * 60
    await this.kv.put(`${LOCK_PREFIX}ip:${ip}`, JSON.stringify({
      lockedAt: Date.now(),
      reason: 'brute_force_ip'
    }), { expirationTtl: ttl })
  }

  async lockEmail(email: string): Promise<void> {
    if (!this.kv) return
    const ttl = this.settings.lockoutDurationMinutes * 60
    await this.kv.put(`${LOCK_PREFIX}email:${email}`, JSON.stringify({
      lockedAt: Date.now(),
      reason: 'brute_force_email'
    }), { expirationTtl: ttl })
  }

  async unlockIP(ip: string): Promise<void> {
    if (!this.kv) return
    await this.kv.delete(`${LOCK_PREFIX}ip:${ip}`)
  }

  async unlockEmail(email: string): Promise<void> {
    if (!this.kv) return
    await this.kv.delete(`${LOCK_PREFIX}email:${email}`)
  }

  async getActiveLockouts(): Promise<Array<{ key: string, type: 'ip' | 'email', value: string, lockedAt: number }>> {
    if (!this.kv) return []
    // KV list with prefix to find all active lockouts
    const ipLocks = await this.kv.list({ prefix: `${LOCK_PREFIX}ip:` })
    const emailLocks = await this.kv.list({ prefix: `${LOCK_PREFIX}email:` })

    const lockouts: Array<{ key: string, type: 'ip' | 'email', value: string, lockedAt: number }> = []

    for (const key of ipLocks.keys) {
      const data = await this.kv.get(key.name)
      if (data) {
        const parsed = JSON.parse(data)
        lockouts.push({
          key: key.name,
          type: 'ip',
          value: key.name.replace(`${LOCK_PREFIX}ip:`, ''),
          lockedAt: parsed.lockedAt
        })
      }
    }

    for (const key of emailLocks.keys) {
      const data = await this.kv.get(key.name)
      if (data) {
        const parsed = JSON.parse(data)
        lockouts.push({
          key: key.name,
          type: 'email',
          value: key.name.replace(`${LOCK_PREFIX}email:`, ''),
          lockedAt: parsed.lockedAt
        })
      }
    }

    return lockouts
  }

  async releaseLockout(key: string): Promise<void> {
    if (!this.kv) return
    await this.kv.delete(key)
  }

  isAboveAlertThreshold(count: number): boolean {
    return count >= this.settings.alertThreshold
  }

  private async incrementCounter(key: string, windowMs: number): Promise<number> {
    const existing = await this.kv.get(key)
    const now = Date.now()

    let entries: number[] = []
    if (existing) {
      try {
        entries = JSON.parse(existing)
      } catch {
        entries = []
      }
    }

    // Remove expired entries
    const cutoff = now - windowMs
    entries = entries.filter(ts => ts > cutoff)

    // Add new entry
    entries.push(now)

    // Store with TTL equal to window
    const ttlSeconds = Math.ceil(windowMs / 1000)
    await this.kv.put(key, JSON.stringify(entries), { expirationTtl: ttlSeconds })

    return entries.length
  }

  private async addToSet(key: string, value: string, windowMs: number): Promise<void> {
    const existing = await this.kv.get(key)
    let set: Record<string, number> = {}
    const now = Date.now()
    const cutoff = now - windowMs

    if (existing) {
      try {
        set = JSON.parse(existing)
      } catch {
        set = {}
      }
    }

    // Remove expired entries
    for (const [k, ts] of Object.entries(set)) {
      if (ts < cutoff) delete set[k]
    }

    set[value] = now

    const ttlSeconds = Math.ceil(windowMs / 1000)
    await this.kv.put(key, JSON.stringify(set), { expirationTtl: ttlSeconds })
  }

  private async getSetSize(key: string): Promise<number> {
    const existing = await this.kv.get(key)
    if (!existing) return 0

    try {
      const set = JSON.parse(existing)
      return Object.keys(set).length
    } catch {
      return 0
    }
  }
}
