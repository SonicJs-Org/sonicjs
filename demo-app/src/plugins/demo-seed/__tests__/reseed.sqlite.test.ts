// @ts-nocheck
/**
 * Real-SQLite integration coverage for runReseed (R10).
 *
 * Unlike a pure-mock test, this executes the ACTUAL wipe + reseed SQL through
 * DocumentsService / MediaDocumentService against a better-sqlite3 D1 shim and
 * an in-memory R2 stub. It is the only thing that can verify:
 *   - the batch derived-row + documents wipe actually removes everything,
 *   - ensureTypes' partial-column INSERT is valid against the real schema,
 *   - the media insert computes q_media_* generated columns,
 *   - content + media are published-on-create,
 *   - a second run is a true reset (no accumulation), and
 *   - the ENVIRONMENT=demo path writes the exact plugin row routes/auth.ts gates on.
 *
 * Reuses core's real-DB harness (applies migrations 0001 + 0002, FK OFF to
 * mirror D1). Run with: npm run build:core && npm test --workspace=demo-app.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../../../../packages/core/src/__tests__/utils/d1-sqlite'
import { runReseed } from '../reseed'
import { SEED_COLLECTIONS } from '../../../seed/content'
import { DEMO_IMAGES, MEDIA_FOLDER } from '../../../seed/assets/images'
import { DEMO_LOGIN_PLUGIN_ID } from '../../demo-login'

// Mirrors MediaDocumentService.MEDIA_QUERYABLE (the q_media_* columns createFromUpload
// projects). Bootstrap adds these at runtime via ensureDocumentGeneratedColumns; the
// harness ships only the base `documents` schema, so add them for media_asset here.
const MEDIA_QUERYABLE = [
  { name: 'mimeType', kind: 'scalar', type: 'text', column: 'q_media_mime' },
  { name: 'folder', kind: 'scalar', type: 'text', column: 'q_media_folder' },
  { name: 'size', kind: 'scalar', type: 'integer', column: 'q_media_size' },
  { name: 'tags', kind: 'facet', type: 'text' },
]

// Minimal in-memory R2 bucket — just the surface runReseed touches (put/list/delete).
function createR2Stub() {
  const store = new Map()
  return {
    async put(key, body, opts) {
      store.set(key, { body, httpMetadata: opts?.httpMetadata })
      return { key }
    },
    async list(opts = {}) {
      const prefix = opts.prefix ?? ''
      const objects = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .map((key) => ({ key, size: store.get(key).body.byteLength }))
      return { objects, truncated: false, cursor: undefined, delimitedPrefixes: [] }
    },
    async delete(keys) {
      for (const k of Array.isArray(keys) ? keys : [keys]) store.delete(k)
    },
    _store: store,
  }
}

const EXPECTED_CONTENT = SEED_COLLECTIONS.reduce((n, c) => n + c.items.length, 0)
const EXPECTED_MEDIA = DEMO_IMAGES.length
const CONTENT_TYPES = SEED_COLLECTIONS.map((c) => c.typeId)

const makeEnv = (db, bucket, environment) => ({ DB: db, MEDIA_BUCKET: bucket, ENVIRONMENT: environment })

const countCurrent = (db, typeId) =>
  db.raw
    .prepare(`SELECT COUNT(*) n FROM documents WHERE type_id = ? AND tenant_id = 'default' AND is_current_draft = 1`)
    .get(typeId).n

describe('runReseed — real SQLite', () => {
  let db
  let bucket

  beforeEach(async () => {
    db = createTestD1()
    await db.applyScalarSchema('media_asset', MEDIA_QUERYABLE)
    bucket = createR2Stub()
  })
  afterEach(() => db.close())

  it('seeds content + media into an empty DB and returns an accurate summary', async () => {
    const summary = await runReseed(makeEnv(db, bucket))

    expect(summary.wiped).toBe(0)
    expect(summary.created).toBe(EXPECTED_CONTENT)
    expect(summary.media).toBe(EXPECTED_MEDIA)
    expect(summary.ms).toBeGreaterThanOrEqual(0)

    // Each collection's items exist and are published-on-create.
    for (const c of SEED_COLLECTIONS) {
      expect(countCurrent(db, c.typeId)).toBe(c.items.length)
      const published = db.raw
        .prepare(`SELECT COUNT(*) n FROM documents WHERE type_id = ? AND is_published = 1`)
        .get(c.typeId).n
      expect(published).toBe(c.items.length)
    }

    // Media documents registered + bytes uploaded under the demo-seed/ prefix.
    expect(countCurrent(db, 'media_asset')).toBe(EXPECTED_MEDIA)
    expect(bucket._store.size).toBe(EXPECTED_MEDIA)
    for (const key of bucket._store.keys()) {
      expect(key.startsWith(`${MEDIA_FOLDER}/`)).toBe(true)
    }

    // q_media_* generated columns computed from the JSON payload.
    const m = db.raw
      .prepare(`SELECT q_media_mime mime, q_media_folder folder FROM documents WHERE type_id = 'media_asset' LIMIT 1`)
      .get()
    expect(m.mime).toBe('image/svg+xml')
    expect(m.folder).toBe(MEDIA_FOLDER)
  })

  it('ensureTypes upserts every seed document type (partial-column INSERT is schema-valid)', async () => {
    await runReseed(makeEnv(db, bucket))
    const ids = db.raw
      .prepare(`SELECT id FROM document_types ORDER BY id`)
      .all()
      .map((r) => r.id)
    expect(ids).toEqual(expect.arrayContaining([...CONTENT_TYPES, 'media_asset']))
  })

  it('is a full reset: a second run wipes the prior dataset (incl. visitor edits) and rebuilds 1:1', async () => {
    await runReseed(makeEnv(db, bucket))

    // Simulate visitor edits: a stray document + a stray R2 object under the seed prefix.
    db.raw
      .prepare(
        `INSERT INTO documents (
           id, root_id, type_id, version_number, is_current_draft, is_published, status,
           parent_root_id, slug, title, tenant_id, locale, translation_group_id,
           data, metadata, created_at, updated_at
         ) VALUES ('stray','stray','blog_post',1,1,1,'published','','stray','Stray',
           'default','default','','{}','{}',1,1)`,
      )
      .run()
    await bucket.put(`${MEDIA_FOLDER}/stray.svg`, new Uint8Array([1]))

    const before = db.raw.prepare(`SELECT COUNT(*) n FROM documents WHERE tenant_id = 'default'`).get().n
    const summary = await runReseed(makeEnv(db, bucket))

    expect(summary.wiped).toBe(before) // wiped everything that was present, stray included
    expect(summary.created).toBe(EXPECTED_CONTENT)

    // Final content equals a single seed — no duplication, stray gone.
    const content = CONTENT_TYPES.reduce((n, t) => n + countCurrent(db, t), 0)
    expect(content).toBe(EXPECTED_CONTENT)
    expect(countCurrent(db, 'media_asset')).toBe(EXPECTED_MEDIA)

    // Stray R2 object purged; only the seed media remains.
    expect(bucket._store.size).toBe(EXPECTED_MEDIA)
  })

  it('activates the demo-login prefill only when ENVIRONMENT=demo (matches the auth.ts gate query)', async () => {
    // Exactly the query routes/auth.ts runs to decide demoLoginActive.
    const gate = () =>
      db.raw
        .prepare(
          `SELECT 1 FROM documents
           WHERE type_id = 'plugin' AND slug = ? AND tenant_id = 'default'
             AND is_current_draft = 1 AND deleted_at IS NULL
             AND json_extract(data, '$.status') = 'active'
           LIMIT 1`,
        )
        .get(DEMO_LOGIN_PLUGIN_ID)

    // Non-demo environment: prefill stays off (no plugin row written).
    await runReseed(makeEnv(db, bucket, 'staging'))
    expect(gate()).toBeUndefined()

    // Demo environment: the plugin row exists and is active — gate flips on.
    await runReseed(makeEnv(db, bucket, 'demo'))
    expect(gate()).toBeDefined()
  })
})
