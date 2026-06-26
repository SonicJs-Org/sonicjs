// @ts-nocheck
// Real-SQLite coverage for the programmatic API key feature (services/api-keys.ts).
// Mock tests can't prove the q_apikey_* generated columns, the hash-only storage,
// or the resolve predicates (revoked/expiry/active) — so this runs actual SQL via
// the better-sqlite3 D1 shim (R10).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { ApiKeyService, API_KEY_QUERYABLE, hashApiKey, generateApiKeySecret } from './api-key-service'

async function seedUser(db, { id = 'user-1', email = 'owner@example.com', role = 'editor', active = 1 } = {}) {
  db.raw
    .prepare(
      `INSERT INTO auth_user (id, name, email, email_verified, first_name, last_name, role, is_active, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
    )
    .run(id, 'Owner', email, 1, 'Owner', 'User', role, active, 1, 1)
  return { id, email, role }
}

describe('ApiKeyService — real SQLite', () => {
  let db
  beforeEach(async () => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,created_at,updated_at)
         VALUES ('api_key','api_key','API Key','{}','[]','{}','system',1,1,1,1,1)`,
      )
      .run()
    await db.applyScalarSchema('api_key', API_KEY_QUERYABLE)
  })
  afterEach(() => db.close())

  describe('create', () => {
    it('returns a one-time sk_ secret and stores only its hash', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      const created = await svc.create({ userId: user.id, name: 'CI token' })

      expect(created.key).toMatch(/^sk_[0-9a-f]{48}$/)
      expect(created.prefix).toBe(created.key.slice(0, 11))
      expect(created.name).toBe('CI token')

      const row = db.raw
        .prepare('SELECT data, q_apikey_hash h, q_apikey_user_id u, q_apikey_revoked r FROM documents WHERE root_id=?')
        .get(created.id)
      // Plaintext secret never lands in the row; only its SHA-256 hash.
      expect(row.data).not.toContain(created.key)
      expect(row.h).toBe(await hashApiKey(created.key))
      expect(row.u).toBe(user.id)
      expect(row.r).toBe(0)
    })

    it('persists an explicit expiry', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      const expiresAt = Date.now() + 60_000
      const created = await svc.create({ userId: user.id, name: 'temp', expiresAt })
      expect(created.expiresAt).toBe(expiresAt)
    })
  })

  describe('resolve', () => {
    it('resolves a valid secret to its owning user with role', async () => {
      const user = await seedUser(db, { role: 'author' })
      const svc = new ApiKeyService(db, 'default')
      const { key } = await svc.create({ userId: user.id, name: 'k' })

      const resolved = await svc.resolve(key)
      expect(resolved).toEqual({
        userId: user.id,
        email: user.email,
        role: 'author',
        isSuperAdmin: false,
      })
    })

    it('returns null for an unknown / malformed secret', async () => {
      await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      expect(await svc.resolve('sk_deadbeef')).toBeNull()
      expect(await svc.resolve('not-a-key')).toBeNull()
      expect(await svc.resolve('')).toBeNull()
    })

    it('returns null for an expired key', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      const { key } = await svc.create({ userId: user.id, name: 'expired', expiresAt: Date.now() - 1000 })
      expect(await svc.resolve(key)).toBeNull()
    })

    it('returns null when the owning user is inactive', async () => {
      const user = await seedUser(db, { active: 0 })
      const svc = new ApiKeyService(db, 'default')
      const { key } = await svc.create({ userId: user.id, name: 'k' })
      expect(await svc.resolve(key)).toBeNull()
    })

    it('stamps lastUsedAt on a successful resolve', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      const { key, id } = await svc.create({ userId: user.id, name: 'k' })

      const before = db.raw.prepare('SELECT data FROM documents WHERE root_id=?').get(id)
      expect(JSON.parse(before.data).lastUsedAt).toBeNull()

      await svc.resolve(key)
      const after = db.raw.prepare('SELECT data FROM documents WHERE root_id=?').get(id)
      expect(typeof JSON.parse(after.data).lastUsedAt).toBe('number')
    })

    it('does not resolve a key minted for one tenant under another', async () => {
      const user = await seedUser(db)
      const { key } = await new ApiKeyService(db, 'default').create({ userId: user.id, name: 'k' })
      expect(await new ApiKeyService(db, 'other').resolve(key)).toBeNull()
    })
  })

  describe('list', () => {
    it('returns metadata only (no secret, no hash) for the owner', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      await svc.create({ userId: user.id, name: 'first' })
      await svc.create({ userId: user.id, name: 'second' })

      const keys = await svc.list(user.id)
      expect(keys).toHaveLength(2)
      for (const k of keys) {
        expect(k).toHaveProperty('prefix')
        expect(k).not.toHaveProperty('key')
        expect(k).not.toHaveProperty('keyHash')
        expect(JSON.stringify(k)).not.toMatch(/sk_[0-9a-f]{48}/)
      }
      expect(keys.map((k) => k.name).sort()).toEqual(['first', 'second'])
    })

    it('isolates keys by user', async () => {
      const a = await seedUser(db, { id: 'ua', email: 'a@x.com' })
      const b = await seedUser(db, { id: 'ub', email: 'b@x.com' })
      const svc = new ApiKeyService(db, 'default')
      await svc.create({ userId: a.id, name: 'a-key' })
      await svc.create({ userId: b.id, name: 'b-key' })

      expect((await svc.list(a.id)).map((k) => k.name)).toEqual(['a-key'])
      expect((await svc.list(b.id)).map((k) => k.name)).toEqual(['b-key'])
    })
  })

  describe('revoke', () => {
    it('hard-deletes the key so it no longer resolves or lists', async () => {
      const user = await seedUser(db)
      const svc = new ApiKeyService(db, 'default')
      const { key, id } = await svc.create({ userId: user.id, name: 'k' })

      expect(await svc.revoke(id, user.id)).toBe(true)
      expect(await svc.resolve(key)).toBeNull()
      expect(await svc.list(user.id)).toHaveLength(0)
      // Document row is gone (credential hard-erase, not soft-flag).
      const row = db.raw.prepare('SELECT COUNT(*) c FROM documents WHERE root_id=?').get(id)
      expect(row.c).toBe(0)
    })

    it('refuses to revoke a key owned by another user', async () => {
      const a = await seedUser(db, { id: 'ua', email: 'a@x.com' })
      const b = await seedUser(db, { id: 'ub', email: 'b@x.com' })
      const svc = new ApiKeyService(db, 'default')
      const { key, id } = await svc.create({ userId: a.id, name: 'a-key' })

      expect(await svc.revoke(id, b.id)).toBe(false)
      // Still valid for the real owner.
      expect(await svc.resolve(key)).not.toBeNull()
    })
  })

  describe('helpers', () => {
    it('generateApiKeySecret produces unique sk_ secrets', () => {
      const a = generateApiKeySecret()
      const b = generateApiKeySecret()
      expect(a).toMatch(/^sk_[0-9a-f]{48}$/)
      expect(a).not.toBe(b)
    })

    it('hashApiKey is deterministic and not the input', async () => {
      const h1 = await hashApiKey('sk_test')
      const h2 = await hashApiKey('sk_test')
      expect(h1).toBe(h2)
      expect(h1).not.toBe('sk_test')
      expect(h1).toMatch(/^[0-9a-f]{64}$/)
    })
  })
})
