// @ts-nocheck
// Regression: the bootstrap FK-ordering guarantee (first-boot race).
//
// bootstrap.ts seeds system data on a fresh DB. Two kinds of step run there:
//   PRODUCERS — bootstrapDocumentTypes / autoRegisterCollectionDocumentTypes — create
//               `document_types` rows.
//   CONSUMERS — RBAC seed / core-plugin bootstrap — `INSERT INTO documents`, whose
//               `type_id` FK-references those `document_types` rows (0002_documents.sql:30).
// The pre-fix code ran all of them in one Promise.all, so on a cold DB a consumer insert
// could win the race against its producer and hit `FOREIGN KEY constraint failed` (each
// step's error was caught+swallowed, leaving RBAC roles / plugins unseeded — then a KV
// marker latched the partial state for 24h).
//
// The shared d1-sqlite harness disables FK enforcement (D1 doesn't reliably enforce it and
// services delete derived rows explicitly). Here the FK IS the subject, so we turn it back
// ON for the DB under test — it is exactly what production D1 enforced when it threw.
import { Hono } from 'hono'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { bootstrapMiddleware, resetBootstrap } from '../../middleware/bootstrap'

function fkOnDb() {
  const db = createTestD1()
  db.raw.pragma('foreign_keys = ON') // re-enable for this test (harness default is OFF)
  return db
}

describe('bootstrap FK ordering (first-boot race regression)', () => {
  let db
  beforeEach(() => { db = fkOnDb() })
  afterEach(() => db.close())

  it('reproduces the race failure: inserting a document before its type exists throws FK', async () => {
    // CONSUMER before PRODUCER — what the pre-fix parallel batch allowed on a cold DB.
    const svc = new DocumentsService(db, { tenantId: 'default' })
    await expect(
      svc.create({ typeId: 'rbac_role', data: { name: 'admin' }, publishOnCreate: true }),
    ).rejects.toThrow(/FOREIGN KEY constraint failed/i)

    // Nothing was written — this is the "roles missing after boot" symptom.
    const n = db.raw.prepare("SELECT COUNT(*) AS n FROM documents WHERE type_id = 'rbac_role'").get().n
    expect(n).toBe(0)
  })

  it('the fixed ordering succeeds: register document types FIRST, then insert documents', async () => {
    // PRODUCER first (bootstrap Phase A) …
    await bootstrapDocumentTypes(db)
    const typeCount = db.raw
      .prepare("SELECT COUNT(*) AS n FROM document_types WHERE id IN ('rbac_role','plugin')").get().n
    expect(typeCount).toBe(2)

    // … then the CONSUMER insert (bootstrap Phase B) no longer violates the FK.
    const svc = new DocumentsService(db, { tenantId: 'default' })
    const doc = await svc.create({ typeId: 'rbac_role', data: { name: 'admin' }, publishOnCreate: true })
    expect(doc.typeId).toBe('rbac_role')

    const n = db.raw.prepare("SELECT COUNT(*) AS n FROM documents WHERE type_id = 'rbac_role'").get().n
    expect(n).toBe(1)
  })

  it('registering all producer types up front lets many document inserts land under FK enforcement', async () => {
    await bootstrapDocumentTypes(db)
    const svc = new DocumentsService(db, { tenantId: 'default' })
    // A spread of system types real consumers (RBAC seed, plugin bootstrap) write.
    for (const [typeId, data] of [
      ['rbac_role', { name: 'editor' }],
      ['rbac_verb', { name: 'read' }],
      ['plugin', { name: 'core-auth' }],
    ]) {
      const d = await svc.create({ typeId, data, publishOnCreate: true })
      expect(d.typeId).toBe(typeId)
    }
    const total = db.raw
      .prepare("SELECT COUNT(*) AS n FROM documents WHERE type_id IN ('rbac_role','rbac_verb','plugin')").get().n
    expect(total).toBe(3)
  })
})

// The three tests above prove the general DB premise (a consumer insert before its type
// exists throws under FK enforcement, and registering types first fixes it) — they never
// touch bootstrap.ts itself. This block calls the REAL bootstrapMiddleware end to end, so
// it actually regresses if bootstrap.ts's Phase A/B split is ever collapsed back into one
// Promise.all. Plugin bootstrap is disabled (config.plugins.disableAll) to keep the FK
// dynamic isolated to RBAC seeding — the same Phase A→B wiring covers both, so this is
// sufficient to prove the ordering without pulling in real plugin definitions.
describe('bootstrapMiddleware (first-boot race regression, end to end)', () => {
  let db
  beforeEach(() => {
    db = fkOnDb()
    resetBootstrap()
  })
  afterEach(() => {
    db.close()
    resetBootstrap()
  })

  it('a single cold-start request seeds document types before RBAC documents that FK-reference them', async () => {
    const app = new Hono()
    app.use('*', bootstrapMiddleware({ plugins: { disableAll: true } }, []))
    app.get('/', (c) => c.text('ok'))

    const res = await app.request('/', {}, { DB: db })
    expect(res.status).toBe(200)

    // If Phase A (producers) didn't fully land before Phase B (RBAC seed, a consumer)
    // ran, this would be 0 — either from a swallowed FK error, or because a partial
    // bootstrap never got the chance to retry. A real fresh boot seeds 4 system roles
    // (admin/editor/author/viewer) — see rbac.ts's SYSTEM_ROLES.
    const roleCount = db.raw.prepare("SELECT COUNT(*) AS n FROM documents WHERE type_id = 'rbac_role'").get().n
    expect(roleCount).toBeGreaterThan(0)

    const verbCount = db.raw.prepare("SELECT COUNT(*) AS n FROM documents WHERE type_id = 'rbac_verb'").get().n
    expect(verbCount).toBeGreaterThan(0)

    // document_types themselves must exist too (Phase A actually ran, not skipped).
    const typeCount = db.raw
      .prepare("SELECT COUNT(*) AS n FROM document_types WHERE id IN ('rbac_role','rbac_verb')").get().n
    expect(typeCount).toBe(2)
  })
})
