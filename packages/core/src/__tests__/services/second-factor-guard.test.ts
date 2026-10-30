/**
 * `hasVerifiedSecondFactor` / `getEnrolmentState` against a real (SQLite) D1.
 *
 * The three properties worth pinning are the ones a refactor would silently invert:
 *   1. it keys off `auth_two_factor.verified`, NOT `auth_user.two_factor_enabled`
 *   2. a query ERROR blocks (fail closed) — but a MISSING TABLE does not
 *   3. `getEnrolmentState` fails the other way (open), because it feeds a page, not a gate
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { D1Database } from '@cloudflare/workers-types'
import { hasVerifiedSecondFactor, getEnrolmentState } from '../../auth/second-factor-guard'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

let db: TestD1

function seedUser(id: string, email: string, twoFactorEnabled: 0 | 1 = 0) {
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at, two_factor_enabled)
       VALUES (?, ?, 'A', 'B', 0, 0, ?)`,
    )
    .run(id, email, twoFactorEnabled)
}

function seedEnrolment(userId: string, verified: 0 | 1) {
  db.raw
    .prepare(
      `INSERT INTO auth_two_factor (id, secret, backup_codes, user_id, verified, created_at, updated_at)
       VALUES (?, 'enc', 'enc', ?, ?, 0, 0)`,
    )
    .run(`tf-${userId}`, userId, verified)
}

/** A DB whose every query rejects — stands in for a D1 outage, not a schema problem. */
function brokenDb(message: string): D1Database {
  return {
    prepare: () => ({
      bind: () => ({
        first: async () => {
          throw new Error(message)
        },
      }),
    }),
  } as unknown as D1Database
}

beforeEach(() => {
  db = createTestD1()
})

afterEach(() => {
  db.close()
  vi.restoreAllMocks()
})

describe('hasVerifiedSecondFactor', () => {
  it('is false for a user with no enrolment row', async () => {
    seedUser('u1', 'a@test.local')
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, 'u1')).toBe(false)
  })

  it('is false while an enrolment is started but unconfirmed (verified = 0)', async () => {
    // Blocking here would lock the user out MID-ENROLMENT: they would hold a secret they had
    // not yet proven, and no way back in.
    seedUser('u1', 'a@test.local')
    seedEnrolment('u1', 0)
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, 'u1')).toBe(false)
  })

  it('is true once the enrolment is confirmed (verified = 1)', async () => {
    seedUser('u1', 'a@test.local')
    seedEnrolment('u1', 1)
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, 'u1')).toBe(true)
  })

  it('ignores auth_user.two_factor_enabled — the flag BA sets before proof', async () => {
    seedUser('u1', 'a@test.local', 1)
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, 'u1')).toBe(false)
  })

  it('does not match another user\'s enrolment', async () => {
    seedUser('u1', 'a@test.local')
    seedUser('u2', 'b@test.local')
    seedEnrolment('u2', 1)
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, 'u1')).toBe(false)
  })

  it('is false for an empty user id (nothing to protect)', async () => {
    expect(await hasVerifiedSecondFactor(db as unknown as D1Database, '')).toBe(false)
  })

  it('BLOCKS on a query error — fail closed', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await hasVerifiedSecondFactor(brokenDb('D1_ERROR: network'), 'u1')).toBe(true)
  })

  it('does NOT block when the table is absent — nobody can be enrolled', async () => {
    // A deployment whose schema predates auth_two_factor has no enrolments to protect;
    // blocking would lock every user out of every passwordless path at once.
    expect(await hasVerifiedSecondFactor(brokenDb('no such table: auth_two_factor'), 'u1')).toBe(false)
  })
})

describe('getEnrolmentState', () => {
  it('reports not-enrolled with no row', async () => {
    expect(await getEnrolmentState(db as unknown as D1Database, 'u1')).toEqual({
      enrolled: false,
      verified: false,
    })
  })

  it('distinguishes started-but-unconfirmed from confirmed', async () => {
    seedUser('u1', 'a@test.local')
    seedEnrolment('u1', 0)
    expect(await getEnrolmentState(db as unknown as D1Database, 'u1')).toEqual({
      enrolled: true,
      verified: false,
    })

    db.raw.prepare(`UPDATE auth_two_factor SET verified = 1 WHERE user_id = 'u1'`).run()
    expect(await getEnrolmentState(db as unknown as D1Database, 'u1')).toEqual({
      enrolled: true,
      verified: true,
    })
  })

  it('fails OPEN on error — it feeds a page, not a gate', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await getEnrolmentState(brokenDb('D1_ERROR: network'), 'u1')).toEqual({
      enrolled: false,
      verified: false,
    })
  })
})
