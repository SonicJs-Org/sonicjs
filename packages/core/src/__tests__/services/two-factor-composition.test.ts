/**
 * How `twoFactor()` is composed into the Better Auth options.
 *
 * Every assertion here corresponds to a way this can silently do nothing:
 *
 *   - not registering `auth_two_factor` in the drizzle schema map → BA cannot resolve the model
 *   - declaring `schema.twoFactor.fields` → double-maps a property key onto a column name
 *   - gating composition on plugin status → deactivation silently downgrades enrolled accounts
 *   - policy read lazily → BA snapshots options at construction, so the values never arrive
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { getDefaultAuthOptions } from '../../auth/config'
import { authTwoFactor, authUser } from '../../db/schema'
import {
  invalidateTwoFactorPolicy,
  loadTwoFactorPolicy,
  TWO_FACTOR_POLICY_DEFAULTS,
  TWO_FACTOR_PLUGIN_ID,
} from '../../auth/two-factor-settings'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'
import type { Bindings } from '../../app'

let db: TestD1

function optionsFor() {
  return getDefaultAuthOptions(
    { DB: db, BETTER_AUTH_SECRET: 'x'.repeat(32) } as unknown as Bindings,
    'https://example.test',
  )
}

/** Pull the twoFactor plugin entry out of the composed options. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- BA plugin objects are loosely typed
function twoFactorPlugin(): any {
  const opts = optionsFor() as unknown as { plugins: Array<{ id?: string }> }
  return opts.plugins.find((p) => p.id === 'two-factor')
}

beforeEach(() => {
  db = createTestD1()
  invalidateTwoFactorPolicy()
})

afterEach(() => {
  db.close()
  invalidateTwoFactorPolicy()
})

describe('twoFactor composition', () => {
  it('is always composed — no plugin-status gate', () => {
    // Gating on `active` would let a deactivation stop challenging every enrolled account while
    // the profile page still read "Enabled". Plugin status gates the SURFACE only.
    expect(twoFactorPlugin()).toBeDefined()
  })

  it('stays composed when the plugin row says INACTIVE — the ADR the whole design rests on', async () => {
    // The test above only proves composition when no status document exists at all, which is the
    // default state, so it would stay green under a gate that treats "unknown" as active. Seed a
    // genuinely DEACTIVATED plugin row and load the policy from it (the one place plugin state
    // reaches this module), then assert the second factor is still composed.
    //
    // If this ever fails, deactivating the plugin has silently downgraded every enrolled account
    // to password-only while `/admin/profile` still reads "Enabled" — the exact failure the
    // unconditional composition exists to prevent.
    const now = Math.floor(Date.now() / 1000)
    db.raw
      .prepare(
        `INSERT INTO documents (id, root_id, type_id, tenant_id, slug, locale, data,
           version_number, is_current_draft, is_published, created_at, updated_at)
         VALUES (?, ?, 'plugin', 'default', ?, 'en', ?, 1, 1, 0, ?, ?)`,
      )
      .run(
        'doc-2fa-inactive',
        'doc-2fa-inactive',
        TWO_FACTOR_PLUGIN_ID,
        JSON.stringify({ status: 'inactive', is_active: false, settings: { maxFailedAttempts: 3 } }),
        now,
        now,
      )
    await loadTwoFactorPolicy(db)

    const plugin = twoFactorPlugin()
    expect(plugin, 'twoFactor() vanished for a deactivated plugin row').toBeDefined()
    // …and the deactivated row's SETTINGS are still honoured, so the surface being off does not
    // quietly revert the policy either.
    expect(plugin.options.accountLockout.maxFailedAttempts).toBe(3)
  })

  it('points at the auth_two_factor table', () => {
    expect(twoFactorPlugin().options.twoFactorTable).toBe('auth_two_factor')
  })

  it('resolves the twoFactor model through the real schema map and writes a real row', async () => {
    // The strong version of "is auth_two_factor registered?". BA resolves models by modelName
    // against the drizzle schema map, so this drives the COMPOSED adapter — the same call
    // `POST /two-factor/enable` makes.
    //
    // Remove the `auth_two_factor: authTwoFactor` entry from auth/config.ts and this fails with
    // `Model "twoFactor" not found in schema`. Rename either side and it fails too.
    //
    // This used to assert on the *error message* of a query that could not execute, because the
    // test D1 shim lacked `Statement.raw()` (which drizzle's D1 driver needs for RETURNING). With
    // that added, the write actually lands and we can assert on storage instead — strictly better,
    // and the reason the round-trip suite exists at all.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- BA adapter factory is untyped
    const options = optionsFor() as any
    const adapter = options.database(options)

    db.raw
      .prepare(
        `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
         VALUES ('u1', 'a@test.local', 'A', 'B', 0, 0)`,
      )
      .run()

    const created = await adapter.create({
      model: 'twoFactor',
      data: {
        secret: 'enc-secret',
        backupCodes: 'enc-codes',
        userId: 'u1',
        verified: true,
        failedVerificationCount: 0,
        lockedUntil: null,
      },
    })

    // BA generated the id and got its own field names back.
    expect(created).toMatchObject({ userId: 'u1', secret: 'enc-secret', verified: true })
    expect(typeof created.id).toBe('string')

    // And the row is in the table BA was told to use, with the two columns BA never sends
    // populated by the drizzle defaults (see two-factor-adapter-create.test.ts).
    const row = db.raw
      .prepare(
        `SELECT user_id, secret, backup_codes, verified, failed_verification_count,
                locked_until, created_at, updated_at
         FROM auth_two_factor WHERE id = ?`,
      )
      .get(created.id) as Record<string, unknown>
    expect(row).toMatchObject({
      user_id: 'u1',
      secret: 'enc-secret',
      backup_codes: 'enc-codes',
      verified: 1,
      failed_verification_count: 0,
      locked_until: null,
    })
    expect(row.created_at).toBeGreaterThan(0)
    expect(row.updated_at).toBeGreaterThan(0)
  })

  it('enables per-account lockout from the policy defaults', () => {
    const lockout = twoFactorPlugin().options.accountLockout
    expect(lockout).toEqual({
      enabled: true,
      maxFailedAttempts: TWO_FACTOR_POLICY_DEFAULTS.maxFailedAttempts,
      durationSeconds: TWO_FACTOR_POLICY_DEFAULTS.lockoutDurationSeconds,
    })
  })

  it('reads the loaded policy, not just the defaults', async () => {
    db.raw
      .prepare(
        `INSERT INTO documents (id, root_id, type_id, slug, tenant_id, is_current_draft, data)
         VALUES ('d','r','plugin', ?, 'default', 1, ?)`,
      )
      .run(
        TWO_FACTOR_PLUGIN_ID,
        JSON.stringify({
          status: 'active',
          settings: { issuer: 'Acme', maxFailedAttempts: 3, lockoutDurationSeconds: 600, backupCodeCount: 7 },
        }),
      )
    await loadTwoFactorPolicy(db as unknown as never)

    const plugin = twoFactorPlugin()
    expect(plugin.options.issuer).toBe('Acme')
    expect(plugin.options.accountLockout).toMatchObject({ maxFailedAttempts: 3, durationSeconds: 600 })
    expect(plugin.options.backupCodeOptions).toEqual({ amount: 7 })
  })

  it('sets trustDeviceMaxAge to 0 — leaving it UNSET would enable a 30-day bypass', () => {
    // BA reads `options?.trustDeviceMaxAge ?? 2592e3`, so omitting the key opts IN to a 30-day
    // trusted-device cookie that any client can request with `{trustDevice:true}` on verify.
    // `0` is not nullish, so it wins the `??` and every trust record expires immediately.
    expect(twoFactorPlugin().options.trustDeviceMaxAge).toBe(0)
  })

  it('does not enable skipVerificationOnEnable — an unproven secret must not count', () => {
    // With it on, /two-factor/enable would flip two_factor_enabled before the user has proven a
    // live code, and a mistyped secret would lock them out of their own account.
    const options = twoFactorPlugin().options
    expect(Object.prototype.hasOwnProperty.call(options, 'skipVerificationOnEnable')).toBe(false)
  })
})
