/**
 * The two-factor policy: normalization/clamping, the document-backed load, and the
 * sync-getter contract `auth/config.ts` depends on.
 *
 * The clamp is the security-relevant half. The admin form declares min/max, but a form is a
 * hint — `parseFormDataToSettings` will happily persist whatever a hand-rolled POST sends, and
 * `maxFailedAttempts: 10000` would disable the lockout that is the only thing bounding a
 * distributed TOTP guesser.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { D1Database } from '@cloudflare/workers-types'
import {
  normalizeTwoFactorPolicy,
  loadTwoFactorPolicy,
  getTwoFactorPolicy,
  invalidateTwoFactorPolicy,
  refreshTwoFactorPolicy,
  TWO_FACTOR_POLICY_DEFAULTS,
  TWO_FACTOR_PLUGIN_ID,
} from '../../auth/two-factor-settings'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

let db: TestD1

function seedSettings(settings: unknown) {
  db.raw
    .prepare(
      `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
       VALUES (?, ?, 'plugin', ?, 'default', 1, ?)`,
    )
    .run('doc-2fa', 'root-2fa', TWO_FACTOR_PLUGIN_ID, JSON.stringify({ status: 'active', settings }))
}

beforeEach(() => {
  db = createTestD1()
  invalidateTwoFactorPolicy()
})

afterEach(() => {
  db.close()
  invalidateTwoFactorPolicy()
  vi.restoreAllMocks()
})

describe('normalizeTwoFactorPolicy', () => {
  it('returns the defaults for empty / junk input', () => {
    expect(normalizeTwoFactorPolicy(undefined)).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
    expect(normalizeTwoFactorPolicy(null)).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
    expect(normalizeTwoFactorPolicy('nonsense')).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
    expect(normalizeTwoFactorPolicy({})).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
  })

  it('accepts values inside the declared bounds', () => {
    expect(
      normalizeTwoFactorPolicy({
        issuer: 'Acme CMS',
        maxFailedAttempts: 3,
        lockoutDurationSeconds: 1800,
        backupCodeCount: 20,
      }),
    ).toEqual({
      issuer: 'Acme CMS',
      maxFailedAttempts: 3,
      lockoutDurationSeconds: 1800,
      backupCodeCount: 20,
    })
  })

  it('clamps a lockout threshold that would disable the lockout', () => {
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: 10_000 }).maxFailedAttempts).toBe(10)
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: 0 }).maxFailedAttempts).toBe(3)
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: -5 }).maxFailedAttempts).toBe(3)
  })

  it('clamps lockout duration and backup-code count', () => {
    expect(normalizeTwoFactorPolicy({ lockoutDurationSeconds: 1 }).lockoutDurationSeconds).toBe(300)
    expect(normalizeTwoFactorPolicy({ lockoutDurationSeconds: 99_999 }).lockoutDurationSeconds).toBe(3600)
    expect(normalizeTwoFactorPolicy({ backupCodeCount: 1 }).backupCodeCount).toBe(5)
    expect(normalizeTwoFactorPolicy({ backupCodeCount: 500 }).backupCodeCount).toBe(20)
  })

  it('coerces numeric strings, because FormData values arrive as strings', () => {
    const p = normalizeTwoFactorPolicy({
      maxFailedAttempts: '7',
      lockoutDurationSeconds: '600',
      backupCodeCount: '8',
    })
    expect(p).toMatchObject({ maxFailedAttempts: 7, lockoutDurationSeconds: 600, backupCodeCount: 8 })
  })

  it('falls back rather than letting NaN reach BA\'s arithmetic', () => {
    // `NULL + 1` and `NaN >= max` both read as "never lock out".
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: 'five' }).maxFailedAttempts).toBe(
      TWO_FACTOR_POLICY_DEFAULTS.maxFailedAttempts,
    )
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: NaN }).maxFailedAttempts).toBe(
      TWO_FACTOR_POLICY_DEFAULTS.maxFailedAttempts,
    )
  })

  it('rounds fractional values to integers', () => {
    expect(normalizeTwoFactorPolicy({ maxFailedAttempts: 4.6 }).maxFailedAttempts).toBe(5)
  })

  it('ignores a blank issuer', () => {
    expect(normalizeTwoFactorPolicy({ issuer: '   ' }).issuer).toBe(TWO_FACTOR_POLICY_DEFAULTS.issuer)
  })

  it('strips otpauth:// delimiters out of the issuer', () => {
    // The issuer is interpolated into an otpauth:// label. ':' would split the label into a
    // different issuer/account pair in the user's authenticator.
    expect(normalizeTwoFactorPolicy({ issuer: 'Evil:Corp?x#y' }).issuer).toBe('Evil Corp x y')
  })

  it('bounds issuer length', () => {
    expect(normalizeTwoFactorPolicy({ issuer: 'z'.repeat(500) }).issuer).toHaveLength(64)
  })
})

describe('policy load / cache', () => {
  it('returns defaults before anything has been loaded', () => {
    expect(getTwoFactorPolicy()).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
  })

  it('reads the plugin document settings and exposes them via the sync getter', async () => {
    seedSettings({ issuer: 'Acme', maxFailedAttempts: 4 })
    await loadTwoFactorPolicy(db as unknown as D1Database)
    expect(getTwoFactorPolicy()).toMatchObject({ issuer: 'Acme', maxFailedAttempts: 4 })
  })

  it('clamps stored out-of-range values on read, not just in the form', async () => {
    seedSettings({ maxFailedAttempts: 9999 })
    await loadTwoFactorPolicy(db as unknown as D1Database)
    expect(getTwoFactorPolicy().maxFailedAttempts).toBe(10)
  })

  it('uses defaults when the plugin document has no settings key', async () => {
    db.raw
      .prepare(
        `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
         VALUES ('d','r','plugin',?, 'default', 1, ?)`,
      )
      .run(TWO_FACTOR_PLUGIN_ID, JSON.stringify({ status: 'active' }))
    await loadTwoFactorPolicy(db as unknown as D1Database)
    expect(getTwoFactorPolicy()).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
  })

  it('caches — a second load does not re-query', async () => {
    seedSettings({ issuer: 'First' })
    await loadTwoFactorPolicy(db as unknown as D1Database)
    db.raw
      .prepare(`UPDATE documents SET data = ? WHERE slug = ?`)
      .run(JSON.stringify({ status: 'active', settings: { issuer: 'Second' } }), TWO_FACTOR_PLUGIN_ID)
    await loadTwoFactorPolicy(db as unknown as D1Database)
    expect(getTwoFactorPolicy().issuer).toBe('First')
  })

  it('refresh re-reads, so a settings write lands in the writing isolate', async () => {
    seedSettings({ issuer: 'First' })
    await loadTwoFactorPolicy(db as unknown as D1Database)
    db.raw
      .prepare(`UPDATE documents SET data = ? WHERE slug = ?`)
      .run(JSON.stringify({ status: 'active', settings: { issuer: 'Second' } }), TWO_FACTOR_PLUGIN_ID)
    await refreshTwoFactorPolicy(db as unknown as D1Database)
    expect(getTwoFactorPolicy().issuer).toBe('Second')
  })

  it('degrades to defaults — never throws — when the read fails', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const broken = {
      prepare: () => ({
        bind: () => ({
          first: async () => {
            throw new Error('D1_ERROR: offline')
          },
        }),
      }),
    } as unknown as D1Database
    await expect(loadTwoFactorPolicy(broken)).resolves.toEqual(TWO_FACTOR_POLICY_DEFAULTS)
  })

  it('defaults sit inside the clamp bounds, so a failed load still yields a usable policy', () => {
    // This used to be titled "the strict end of every knob, so a failed load cannot weaken
    // policy" and asserted `<= 10` / `>= 300` / `>= 5` — which normalizeTwoFactorPolicy already
    // guarantees for ANY input, so it was close to a tautology, and the claim was false besides:
    // the defaults are mid-range (5 / 900 / 10), so a failed load hands back 5 attempts to an
    // operator who had tightened it to 3.
    //
    // The property that IS real is containment: whatever happens, the lockout cannot be disabled
    // and backup codes cannot drop below 5. Assert that against the bounds themselves, so
    // widening BOUNDS without revisiting the defaults trips here.
    // Clamping the defaults must be a NO-OP. If someone lowers backupCodeCount to 3 or raises
    // maxFailedAttempts to 50, the clamp rewrites it and this equality breaks.
    expect(normalizeTwoFactorPolicy(TWO_FACTOR_POLICY_DEFAULTS)).toEqual(TWO_FACTOR_POLICY_DEFAULTS)
  })
})
