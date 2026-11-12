import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createSonicJSApp, type Bindings } from '../../app'
import type { MigrationServiceOptions } from '../../services/migrations'
import { RbacService } from '../../services/rbac'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

// Leave factory middleware, authorization, route mounting and migration reads real.
// Bootstrap schema/seed work and Better Auth session lookup are independent of
// ledger selection; supply their results without short-circuiting the request.
vi.mock('../../middleware/bootstrap', () => ({
  bootstrapMiddleware: () => async (_c: unknown, next: () => Promise<void>) => next(),
}))

let authenticated = true
vi.mock('../../auth/config', () => ({
  createAuth: () => ({
    api: {
      getSession: async () => authenticated ? {
        user: { id: 'admin', email: 'admin@example.test', role: 'admin' },
        session: {
          id: 'test-session', userId: 'admin', token: 'test-token',
          expiresAt: Date.now() + 60_000, createdAt: Date.now(), updatedAt: Date.now(),
        },
      } : null,
    },
  }),
}))

describe('Factory admin migration status options (real SQLite)', () => {
  let db: TestD1
  beforeEach(async () => {
    authenticated = true
    db = createTestD1()
    db.raw.exec(`
      CREATE TABLE d1_migrations (name TEXT, applied_at TEXT);
      CREATE TABLE custom_migration_history (name TEXT, applied_at TEXT);
      INSERT INTO d1_migrations VALUES ('0001_core.sql', '2026-01-01');
      INSERT INTO custom_migration_history VALUES ('0002_documents.sql', '2026-02-01');
      INSERT INTO custom_migration_history VALUES ('0003_session_org.sql', '2026-02-02');
    `)
    const rbac = new RbacService(db as unknown as Bindings['DB'])
    await rbac.ensureSystemRbacSeed()
    await rbac.addUserRoleByName('admin', 'admin')
  })
  afterEach(() => db.close())

  /**
   * Build the real app with its built-in status routes and ledger configuration.
   *
   * @param options - Ledger options supplied to the public factory.
   * @returns A test application exposing both migration-status endpoints.
   */
  function appFor(options?: MigrationServiceOptions) {
    return createSonicJSApp({
      migrations: options,
      plugins: { disableAll: true },
    })
  }

  for (const endpoint of ['/admin/api/migrations/status', '/admin/settings/api/migrations/status']) {
    it(`${endpoint} uses the selected journal without modifying it`, async () => {
      const before = db.raw.serialize()
      const response = await appFor({ tableName: 'custom_migration_history' }).request(endpoint, {}, { DB: db } as unknown as Bindings)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data).toMatchObject({ totalMigrations: 7, appliedMigrations: 2, pendingMigrations: 5, lastApplied: '2026-02-02' })
      expect(body.data.migrations.find((m: { id: string }) => m.id === '0001').applied).toBe(false)
      expect(body.data.migrations.filter((m: { applied: boolean }) => m.applied)).toMatchObject([
        { id: '0002', appliedAt: '2026-02-01' },
        { id: '0003', appliedAt: '2026-02-02' },
      ])
      expect(db.raw.serialize()).toEqual(before)
    })

    it(`${endpoint} retains the default ledger and authentication requirement`, async () => {
      const env = { DB: db } as unknown as Bindings
      const before = db.raw.serialize()
      const response = await appFor().request(endpoint, {}, env)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.data).toMatchObject({ totalMigrations: 7, appliedMigrations: 1, pendingMigrations: 6, lastApplied: '2026-01-01' })
      expect(body.data.migrations.filter((m: { applied: boolean }) => m.applied)).toMatchObject([
        { id: '0001', appliedAt: '2026-01-01' },
      ])
      authenticated = false
      const unauthorized = await appFor().request(endpoint, {}, env)
      expect(unauthorized.status).toBe(401)
      expect(db.raw.serialize()).toEqual(before)
    })
  }
})
