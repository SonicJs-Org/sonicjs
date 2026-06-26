/**
 * BruteForceDetector unit tests.
 *
 * The detector is wired into the login path via the security-audit-plugin
 * audit middleware, but had zero direct coverage. These tests mirror the
 * account-lockout scenarios that Payload's auth suite covers:
 *   - lock after N failed attempts (per-IP and per-email, independently)
 *   - isLocked reflects an active lock and clears on unlock
 *   - the sliding window expires stale attempts
 *   - multi-email-from-one-IP is flagged suspicious
 *   - alert threshold + active-lockout enumeration
 *
 * KV is the in-memory mock from test utils, so TTL expiry is real (it keys
 * off Date.now()), letting us assert window/lockout expiration deterministically.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { BruteForceDetector } from './brute-force-detector'
import type { SecurityAuditSettings } from '../types'
import { makeMockKVNamespace } from '../../../../__tests__/utils/mock-factories'

const SETTINGS: SecurityAuditSettings['bruteForce'] = {
  enabled: true,
  maxFailedAttemptsPerIP: 4,
  maxFailedAttemptsPerEmail: 3,
  windowMinutes: 15,
  lockoutDurationMinutes: 30,
  alertThreshold: 6,
}

function makeDetector(overrides?: Partial<SecurityAuditSettings['bruteForce']>) {
  const kv = makeMockKVNamespace()
  const detector = new BruteForceDetector(kv as any, { ...SETTINGS, ...overrides })
  return { kv, detector }
}

describe('BruteForceDetector', () => {
  describe('recordFailedAttempt', () => {
    it('locks the email after maxFailedAttemptsPerEmail failures', async () => {
      const { detector } = makeDetector()
      let result
      for (let i = 0; i < SETTINGS.maxFailedAttemptsPerEmail; i++) {
        result = await detector.recordFailedAttempt('1.1.1.1', 'victim@example.com')
      }
      expect(result!.emailCount).toBe(SETTINGS.maxFailedAttemptsPerEmail)
      expect(result!.shouldLockEmail).toBe(true)
      // IP threshold (4) is higher than email threshold (3), so not yet IP-locked.
      expect(result!.shouldLockIP).toBe(false)
    })

    it('locks the IP after maxFailedAttemptsPerIP failures, independent of email', async () => {
      const { detector } = makeDetector()
      let result
      // Different email each time so the per-email counter never trips first.
      for (let i = 0; i < SETTINGS.maxFailedAttemptsPerIP; i++) {
        result = await detector.recordFailedAttempt('2.2.2.2', `u${i}@example.com`)
      }
      expect(result!.ipCount).toBe(SETTINGS.maxFailedAttemptsPerIP)
      expect(result!.shouldLockIP).toBe(true)
    })

    it('does not signal a lock below the threshold', async () => {
      const { detector } = makeDetector()
      const result = await detector.recordFailedAttempt('3.3.3.3', 'someone@example.com')
      expect(result.shouldLockEmail).toBe(false)
      expect(result.shouldLockIP).toBe(false)
      expect(result.emailCount).toBe(1)
    })

    it('flags suspicious when >=5 distinct emails come from one IP', async () => {
      const { detector } = makeDetector({ maxFailedAttemptsPerIP: 100 })
      let result
      for (let i = 0; i < 5; i++) {
        result = await detector.recordFailedAttempt('4.4.4.4', `spray${i}@example.com`)
      }
      expect(result!.isSuspicious).toBe(true)
    })

    it('returns all-false / zero when the detector is disabled', async () => {
      const { detector } = makeDetector({ enabled: false })
      const result = await detector.recordFailedAttempt('5.5.5.5', 'x@example.com')
      expect(result).toEqual({
        ipCount: 0,
        emailCount: 0,
        shouldLockIP: false,
        shouldLockEmail: false,
        isSuspicious: false,
      })
    })
  })

  describe('sliding window', () => {
    beforeEach(() => vi.useFakeTimers())
    afterEach(() => vi.useRealTimers())

    it('drops attempts older than windowMinutes so the count never trips', async () => {
      vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
      const { detector } = makeDetector({ maxFailedAttemptsPerEmail: 3, windowMinutes: 15 })

      // Two failures now.
      await detector.recordFailedAttempt('6.6.6.6', 'slow@example.com')
      await detector.recordFailedAttempt('6.6.6.6', 'slow@example.com')

      // Advance past the window; the earlier two attempts expire.
      vi.setSystemTime(new Date('2026-01-01T00:20:00Z'))
      const result = await detector.recordFailedAttempt('6.6.6.6', 'slow@example.com')

      // Only the most recent attempt survives the window filter.
      expect(result.emailCount).toBe(1)
      expect(result.shouldLockEmail).toBe(false)
    })
  })

  describe('isLocked / lock / unlock', () => {
    it('reports not locked when nothing is set', async () => {
      const { detector } = makeDetector()
      expect(await detector.isLocked('7.7.7.7', 'free@example.com')).toEqual({ locked: false })
    })

    it('reports locked with an email reason after lockEmail', async () => {
      const { detector } = makeDetector()
      await detector.lockEmail('locked@example.com')
      const status = await detector.isLocked('7.7.7.7', 'locked@example.com')
      expect(status.locked).toBe(true)
      expect(status.reason).toMatch(/Account temporarily locked/)
    })

    it('reports locked with an IP reason after lockIP', async () => {
      const { detector } = makeDetector()
      await detector.lockIP('8.8.8.8')
      const status = await detector.isLocked('8.8.8.8', 'whoever@example.com')
      expect(status.locked).toBe(true)
      expect(status.reason).toMatch(/IP address temporarily locked/)
    })

    it('clears the lock after unlockEmail / unlockIP', async () => {
      const { detector } = makeDetector()
      await detector.lockEmail('temp@example.com')
      await detector.lockIP('9.9.9.9')
      await detector.unlockEmail('temp@example.com')
      await detector.unlockIP('9.9.9.9')
      expect(await detector.isLocked('9.9.9.9', 'temp@example.com')).toEqual({ locked: false })
    })

    it('auto-expires the lock once lockoutDurationMinutes elapses (KV TTL)', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
      const { detector } = makeDetector({ lockoutDurationMinutes: 30 })
      await detector.lockEmail('expire@example.com')
      expect((await detector.isLocked('1.1.1.1', 'expire@example.com')).locked).toBe(true)

      // Past the 30-minute lockout TTL.
      vi.setSystemTime(new Date('2026-01-01T00:31:00Z'))
      expect((await detector.isLocked('1.1.1.1', 'expire@example.com')).locked).toBe(false)
      vi.useRealTimers()
    })
  })

  describe('getActiveLockouts', () => {
    it('enumerates active IP and email lockouts with type + value', async () => {
      const { detector } = makeDetector()
      await detector.lockIP('10.0.0.1')
      await detector.lockEmail('a@example.com')

      const lockouts = await detector.getActiveLockouts()
      const byType = Object.fromEntries(lockouts.map((l) => [l.type, l.value]))
      expect(lockouts).toHaveLength(2)
      expect(byType.ip).toBe('10.0.0.1')
      expect(byType.email).toBe('a@example.com')
      for (const l of lockouts) expect(typeof l.lockedAt).toBe('number')
    })

    it('releaseLockout removes a specific lockout by key', async () => {
      const { detector } = makeDetector()
      await detector.lockIP('10.0.0.2')
      const [lock] = await detector.getActiveLockouts()
      await detector.releaseLockout(lock.key)
      expect(await detector.getActiveLockouts()).toHaveLength(0)
    })
  })

  describe('isAboveAlertThreshold', () => {
    it('is true only at or above alertThreshold', () => {
      const { detector } = makeDetector({ alertThreshold: 6 })
      expect(detector.isAboveAlertThreshold(5)).toBe(false)
      expect(detector.isAboveAlertThreshold(6)).toBe(true)
      expect(detector.isAboveAlertThreshold(7)).toBe(true)
    })
  })
})
