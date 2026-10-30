// @ts-nocheck
// LOGIC-ONLY mock coverage. This file uses a pure vi.fn() store that does NOT execute SQL, so it
// can only assert that services issue the expected calls / pure-function results. Real SQL behavior
// (bind/column balance, partial unique indexes, batch atomicity, generated columns, tenant scoping,
// version_number, erase, golden reindex) is verified in documents.sqlite.test.ts against better-sqlite3.
// Do NOT re-add SQL-simulation tests here — they masked the saveDraft bind bug (D1).
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { DocumentsService } from '../../services/documents'
import { DocumentPermissionsService } from '../../services/document-permissions'
import { DocumentProjection } from '../../services/document-projection'

// Suppress console output in tests
vi.spyOn(console, 'log').mockImplementation(() => {})

// ─── Mock DB factory ──────────────────────────────────────────────────────────
// Each test gets a fresh store so state does not bleed between tests.

function makeMockDb(initialRows: any[] = []) {
  const store: Map<string, any> = new Map()
  initialRows.forEach(r => store.set(r.id, r))

  const batchCalls: any[][] = []

  function makeStmt(sql: string, bindings: any[]) {
    return {
      run: vi.fn().mockResolvedValue({ success: true }),
      first: vi.fn().mockImplementation(async () => {
        // Naive: match by id binding
        if (sql.includes('WHERE id = ?')) {
          return store.get(bindings[0]) ?? null
        }
        if (sql.includes('WHERE root_id = ? AND is_current_draft = 1')) {
          return [...store.values()].find(r => r.root_id === bindings[0] && r.is_current_draft === 1) ?? null
        }
        if (sql.includes('WHERE root_id = ? AND is_published = 1 AND id != ?')) {
          return [...store.values()].find(r => r.root_id === bindings[0] && r.is_published === 1 && r.id !== bindings[1]) ?? null
        }
        if (sql.includes('WHERE root_id = ? AND is_published = 1')) {
          return [...store.values()].find(r => r.root_id === bindings[0] && r.is_published === 1) ?? null
        }
        return null
      }),
      all: vi.fn().mockImplementation(async () => {
        if (sql.includes('root_id = ? AND tenant_id = ?') && sql.includes('SELECT id')) {
          const rows = [...store.values()].filter(r => r.root_id === bindings[0] && r.tenant_id === bindings[1])
          return { results: rows }
        }
        if (sql.includes('type_id = ? AND tenant_id = ?')) {
          const rows = [...store.values()].filter(r => r.type_id === bindings[0] && r.tenant_id === bindings[1])
          return { results: rows }
        }
        return { results: [] }
      }),
      bind: function (...args: any[]) { return makeStmt(sql, args) },
    }
  }

  const db = {
    prepare: (sql: string) => ({
      bind: (...args: any[]) => {
        const stmt = makeStmt(sql, args)
        // Side-effect: apply simple mutations when .run() is called from batch
        stmt._sql = sql
        stmt._bindings = args
        return stmt
      },
    }),
    batch: vi.fn().mockImplementation(async (stmts: any[]) => {
      batchCalls.push(stmts)
      // Apply INSERT/UPDATE/DELETE mutations so subsequent reads are consistent.
      for (const s of stmts) {
        if (!s || !s._sql) continue
        const sql = s._sql as string
        const b = s._bindings as any[]
        if (sql.startsWith('INSERT INTO documents')) {
          // Handles both simple INSERT and INSERT...SELECT (saveDraft) forms.
          const row = buildDocRowFromInsert(sql, b)
          if (row) store.set(row.id, row)
        }
        if (sql.startsWith('UPDATE documents SET is_current_draft = 0')) {
          const id = b[1]
          const row = store.get(id)
          if (row) store.set(id, { ...row, is_current_draft: 0, updated_at: b[0] })
        }
        if (sql.includes("SET is_published = 1, status = 'published'")) {
          const id = b[3]
          const row = store.get(id)
          if (row) store.set(id, { ...row, is_published: 1, status: 'published', published_at: b[0], updated_at: b[1] })
        }
        if (sql.includes('SET is_published = 0')) {
          const id = b[1]
          const row = store.get(id)
          if (row) store.set(id, { ...row, is_published: 0, updated_at: b[0] })
        }
        if (sql.includes("SET is_published = 0, status = 'draft'")) {
          const id = b[1]
          const row = store.get(id)
          if (row) store.set(id, { ...row, is_published: 0, status: 'draft', updated_at: b[0] })
        }
        if (sql.startsWith('DELETE FROM documents WHERE id = ?')) {
          store.delete(b[0])
        }
        if (sql.startsWith('DELETE FROM document_facets') || sql.startsWith('DELETE FROM document_references') || sql.startsWith('DELETE FROM document_permissions')) {
          // No-op in unit tests — facet/reference tables are not tracked in this mock
        }
      }
      return []
    }),
    _store: store,
    _batchCalls: batchCalls,
  }

  return db
}

function buildDocRowFromInsert(sql: string, b: any[]): any {
  if (b.length < 27) return null

  // Two INSERT forms are used:
  // 1. Simple INSERT (create): 30 params, columns positionally aligned.
  // 2. INSERT...SELECT (saveDraft): has a subquery for version_number, 27 params.
  //    Param[5] is the rootId for the COALESCE subquery; the remaining map shifted by 1.
  const isSelectForm = sql.includes('COALESCE(MAX')

  if (!isSelectForm && b.length >= 30) {
    return {
      id: b[0], root_id: b[1], type_id: b[2], type_version: b[3], version_of_id: b[4], version_number: b[5],
      is_current_draft: b[6], is_published: b[7], status: b[8], parent_root_id: b[9], slug: b[10], path: b[11],
      title: b[12], zone: b[13], sort_order: b[14], visible: b[15], published_at: b[16], scheduled_at: b[17],
      expires_at: b[18], deleted_at: b[19], tenant_id: b[20], locale: b[21], translation_group_id: b[22],
      data: b[23], metadata: b[24], owner_id: b[25], created_by: b[26], updated_by: b[27],
      created_at: b[28], updated_at: b[29],
    }
  }

  if (isSelectForm) {
    // b[0]=id, b[1]=root_id, b[2]=type_id, b[3]=type_version, b[4]=version_of_id,
    // b[5]=rootId (subquery param), b[6]=parent_root_id, b[7]=slug, b[8]=path,
    // b[9]=title, b[10]=zone, b[11]=sort_order, b[12]=visible, b[13]=published_at,
    // b[14]=scheduled_at, b[15]=expires_at, b[16]=deleted_at, b[17]=tenant_id,
    // b[18]=locale, b[19]=translation_group_id, b[20]=data, b[21]=metadata,
    // b[22]=owner_id, b[23]=created_by, b[24]=updated_by, b[25]=created_at, b[26]=updated_at
    return {
      id: b[0], root_id: b[1], type_id: b[2], type_version: b[3], version_of_id: b[4],
      version_number: 2, // approximated: mock can't run the subquery
      is_current_draft: 1, is_published: 0, status: 'draft',
      parent_root_id: b[6], slug: b[7], path: b[8], title: b[9], zone: b[10],
      sort_order: b[11], visible: b[12], published_at: b[13], scheduled_at: b[14],
      expires_at: b[15], deleted_at: b[16],
      tenant_id: b[17], locale: b[18], translation_group_id: b[19],
      data: b[20], metadata: b[21],
      owner_id: b[22], created_by: b[23], updated_by: b[24],
      created_at: b[25], updated_at: b[26],
    }
  }

  return null
}

const FAQ_TYPE_ID = 'faq'
const TENANT = 'acme'
const OTHER_TENANT = 'other-tenant'

function makeService(db: any, opts = {}) {
  return new DocumentsService(db as any, {
    queryableFields: [
      { name: 'category', kind: 'scalar', type: 'text', column: 'q_faq_category' },
      { name: 'tags', kind: 'facet', type: 'text' },
    ],
    ...opts,
  })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('DocumentsService.create', () => {
  it('inserts document with root_id = id and version_number = 1', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const doc = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: TENANT, data: { question: 'Q?' } })

    expect(doc.rootId).toBe(doc.id)
    expect(doc.versionNumber).toBe(1)
    expect(doc.isCurrentDraft).toBe(true)
    expect(doc.isPublished).toBe(false)
    expect(doc.status).toBe('draft')
    expect(db._store.has(doc.id)).toBe(true)
  })

  it('sets is_published = 1 when publishOnCreate is true', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const doc = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: TENANT, data: {}, publishOnCreate: true })

    expect(doc.isPublished).toBe(true)
    expect(doc.status).toBe('published')
  })

  it('calls db.batch once (atomic)', async () => {
    const db = makeMockDb()
    const svc = makeService(db)
    await svc.create({ typeId: FAQ_TYPE_ID, tenantId: TENANT, data: {} })
    expect(db.batch).toHaveBeenCalledTimes(1)
  })

  it('validates tenantId is stored on the row', async () => {
    const db = makeMockDb()
    const svc = makeService(db)
    const doc = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: OTHER_TENANT, data: {} })
    expect(doc.tenantId).toBe(OTHER_TENANT)
  })
})

// NOTE: saveDraft behavior (new version row, demote-prev, data merge, batch atomicity, tenant
// scoping) is covered against real SQL in documents.sqlite.test.ts. The former mock-simulation
// tests here were theater (the mock hardcoded version_number=2 and could not catch the bind bug)
// and have been removed deliberately.

describe('DocumentsService.publish', () => {
  it('sets is_published on the target row', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const v1 = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: TENANT, data: {} })
    await svc.publish(v1.id)

    const row = db._store.get(v1.id)
    expect(row.is_published).toBe(1)
    expect(row.status).toBe('published')
  })

  // (Publish-transition that demotes a previously-published row is covered in documents.sqlite.test.ts.)

  it('throws if document not found', async () => {
    const db = makeMockDb()
    const svc = makeService(db)
    await expect(svc.publish('nonexistent')).rejects.toThrow('not found')
  })
})

describe('DocumentsService.unpublish', () => {
  it('clears is_published flag', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const v1 = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: TENANT, data: {} })
    await svc.publish(v1.id)

    // Confirm it's published
    db._store.set(v1.id, { ...db._store.get(v1.id), is_published: 1 })

    await svc.unpublish(v1.id)

    const row = db._store.get(v1.id)
    expect(row.is_published).toBe(0)
    expect(row.status).toBe('draft')
  })
})

describe('DocumentsService.erase (PII)', () => {
  it('deletes all version rows for the root', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const v1 = await svc.create({ typeId: 'contact_message', tenantId: TENANT, data: { email: 'x@example.com' } })

    // erase uses SELECT id first (mocked via .all()), then deletes
    // Plant the id in the results so the mock finds it
    db.prepare = (sql: string) => ({
      bind: (...args: any[]) => {
        if (sql.includes('SELECT id FROM documents WHERE root_id')) {
          return { all: async () => ({ results: [{ id: v1.id }] }) }
        }
        return {
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] }),
          bind: (...a: any[]) => ({ run: vi.fn(), first: vi.fn(), all: vi.fn() }),
          _sql: sql, _bindings: args,
        }
      },
    })

    await svc.erase(v1.rootId, TENANT)

    // batch should have been called (erase uses db.batch)
    expect(db.batch).toHaveBeenCalled()
  })
})

describe('DocumentsService - tenant isolation', () => {
  it('stores tenant_id correctly on create', async () => {
    const db = makeMockDb()
    const svc = makeService(db)

    const docA = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: 'tenant-a', data: {} })
    const docB = await svc.create({ typeId: FAQ_TYPE_ID, tenantId: 'tenant-b', data: {} })

    expect(docA.tenantId).toBe('tenant-a')
    expect(docB.tenantId).toBe('tenant-b')
    expect(docA.id).not.toBe(docB.id)
  })
})

describe('DocumentPermissionsService.isAllowedSync', () => {
  const svc = new DocumentPermissionsService({ prepare: vi.fn(), batch: vi.fn() } as any)

  it('deny overrides allow (deny wins)', () => {
    const overrides = [{ effect: 'deny' as const }, { effect: 'allow' as const }]
    expect(svc.isAllowedSync([{ type: 'role', id: 'editor' }], overrides, 'read', {})).toBe(false)
  })

  it('explicit allow returns true', () => {
    const overrides = [{ effect: 'allow' as const }]
    expect(svc.isAllowedSync([{ type: 'role', id: 'editor' }], overrides, 'read', {})).toBe(true)
  })

  it('falls back to base grants when no overrides', () => {
    const settings = { baseGrants: { editor: ['read' as const, 'update' as const] } }
    expect(svc.isAllowedSync([{ type: 'role', id: 'editor' }], [], 'read', settings)).toBe(true)
    expect(svc.isAllowedSync([{ type: 'role', id: 'editor' }], [], 'delete', settings)).toBe(false)
  })

  it('public principal uses base grants', () => {
    const settings = { baseGrants: { public: ['read' as const] } }
    expect(svc.isAllowedSync([{ type: 'public', id: '*' }], [], 'read', settings)).toBe(true)
    expect(svc.isAllowedSync([{ type: 'public', id: '*' }], [], 'update', settings)).toBe(false)
  })

  it('unknown role with no overrides returns false', () => {
    expect(svc.isAllowedSync([{ type: 'role', id: 'stranger' }], [], 'read', {})).toBe(false)
  })
})

describe('DocumentProjection - chunking (D1 param limit)', () => {
  it('chunks facet inserts within the 100-param limit', () => {
    const statements: any[] = []
    const db = {
      prepare: (sql: string) => ({
        bind: (...args: any[]) => {
          statements.push({ sql, paramCount: args.length })
          return { _sql: sql, _bindings: args }
        },
      }),
    }

    const proj = new DocumentProjection(db as any)

    const doc = {
      id: 'doc1', rootId: 'root1', typeId: 'faq', tenantId: 'acme',
      data: { tags: Array.from({ length: 20 }, (_, i) => `tag-${i}`) },
      isCurrentDraft: true, isPublished: false,
    }

    proj.buildDerivedInsertStatements(
      doc as any,
      [{ name: 'tags', kind: 'facet', type: 'text' }],
      1000,
    )

    // Each facet row is 10 params; 20 tags = 200 params total.
    // Should be split so no single statement exceeds 90 params.
    for (const s of statements) {
      expect(s.paramCount).toBeLessThanOrEqual(90)
    }
  })
})
