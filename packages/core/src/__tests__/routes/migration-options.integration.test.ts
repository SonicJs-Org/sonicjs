import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Hono } from 'hono'
import type { Bindings, Variables } from '../../app'
import type { MigrationServiceOptions } from '../../services/migrations'
import { adminApiRoutes } from '../../routes/admin-api'
import { adminSettingsRoutes } from '../../routes/admin-settings'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

describe('Admin migration status options (real SQLite)', () => {
  let db: TestD1
  beforeEach(() => {
    db = createTestD1()
    db.raw.exec(`
      CREATE TABLE d1_migrations (name TEXT, applied_at TEXT);
      CREATE TABLE custom_migration_history (name TEXT, applied_at TEXT);
      INSERT INTO d1_migrations VALUES ('0001_core.sql', '2026-01-01');
      INSERT INTO custom_migration_history VALUES ('0002_documents.sql', '2026-02-01');
      INSERT INTO custom_migration_history VALUES ('0003_session_org.sql', '2026-02-02');
    `)
  })
  afterEach(() => db.close())

  function appFor(options?: MigrationServiceOptions, authenticated = true) {
    const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()
    app.use('*', async (c, next) => {
      if (authenticated) c.set('user', { userId: 'admin', email: 'admin@example.test', role: 'admin', exp: 0, iat: 0 })
      if (options) c.set('migrationOptions', options)
      await next()
    })
    app.route('/admin/api', adminApiRoutes)
    app.route('/admin/settings', adminSettingsRoutes)
    return app
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
      expect(db.raw.serialize()).toEqual(before)
    })

    it(`${endpoint} retains the default ledger and authentication requirement`, async () => {
      const env = { DB: db } as unknown as Bindings
      const response = await appFor().request(endpoint, {}, env)
      expect(response.status).toBe(200)
      expect((await response.json()).data).toMatchObject({ appliedMigrations: 1, pendingMigrations: 6 })
      const unauthorized = await appFor(undefined, false).request(endpoint, {}, env)
      expect(unauthorized.status).toBe(401)
    })
  }
})
