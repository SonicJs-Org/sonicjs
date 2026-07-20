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
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { DocumentsService } from '../../services/documents'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

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
