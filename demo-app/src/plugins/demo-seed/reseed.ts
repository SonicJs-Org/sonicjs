/**
 * Demo reseed — the single source of truth for "reset the demo to a known state".
 *
 * Called by BOTH triggers in the demo-seed plugin:
 *   - POST /__demo/reseed  (deploy workflow, after each promotion to main)
 *   - the 2-hour cron      (so visitor edits never persist longer than ~2h)
 *
 * Full wipe semantics: every document for tenant `default` (content, media,
 * plugin rows, email logs) plus its derived facet/reference/permission rows is
 * deleted, then the demo content + media + demo-login activation are rebuilt.
 * document_types and Better-Auth users are NOT documents, so they survive
 * (admin@sonicjs.com is seeded once by the deploy workflow via /auth/seed-admin).
 *
 * All writes go through DocumentsService / MediaDocumentService (R1/R4) — no
 * hand-written document SQL except the explicit derived-row wipe and the
 * defensive document_types upsert.
 */

import type { D1Database, R2Bucket } from '@cloudflare/workers-types'
import { DocumentsService, MediaDocumentService } from '@sonicjs-cms/core'

import { DEMO_IMAGES, MEDIA_FOLDER } from '../../seed/assets/images'
import { SEED_COLLECTIONS } from '../../seed/content'
import { ensureDemoLoginActive } from '../demo-login'

const TENANT = 'default'

/** Worker bindings the reseed needs. */
export interface DemoEnv {
  DB: D1Database
  MEDIA_BUCKET: R2Bucket
  ENVIRONMENT?: string
  DEMO_SEED_TOKEN?: string
}

export interface ReseedSummary {
  wiped: number
  created: number
  media: number
  ms: number
}

/** document_types the seed writes into. Upserted defensively so the reseed works
 *  even on the cron path or a fresh DB where bootstrap hasn't registered them.
 *  `source` must satisfy the document_types CHECK ('code'|'plugin'|'system'); the
 *  real bootstrap registers both collection types and media_asset as 'system'
 *  (autoRegisterCollectionDocumentTypes / bootstrapDocumentTypes), so match that —
 *  'user' is not a legal source and INSERT OR IGNORE would silently drop the row. */
const SEED_TYPES: Array<{ id: string; displayName: string; source: 'code' | 'plugin' | 'system' }> = [
  { id: 'blog_post', displayName: 'Blog Posts', source: 'system' },
  { id: 'page', displayName: 'Pages', source: 'system' },
  { id: 'testimonial', displayName: 'Testimonials', source: 'system' },
  { id: 'faq', displayName: 'FAQs', source: 'system' },
  { id: 'media_asset', displayName: 'Media Asset', source: 'system' },
]

const TYPE_SETTINGS = JSON.stringify({
  baseGrants: {
    public: ['read'],
    admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
  },
})

/** Delete every R2 object under a prefix (paginated). */
async function purgePrefix(bucket: R2Bucket, prefix: string): Promise<void> {
  let cursor: string | undefined
  do {
    const listed = await bucket.list(cursor ? { prefix, cursor } : { prefix })
    if (listed.objects.length > 0) {
      await bucket.delete(listed.objects.map((o) => o.key))
    }
    cursor = listed.truncated ? listed.cursor : undefined
  } while (cursor)
}

/** INSERT OR IGNORE each seed document_type so the FK on documents.type_id holds. */
async function ensureTypes(db: D1Database): Promise<void> {
  const stmts = SEED_TYPES.map((t) =>
    db
      .prepare(
        `INSERT OR IGNORE INTO document_types (id, name, display_name, source, settings, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))`,
      )
      .bind(t.id, t.id, t.displayName, t.source, TYPE_SETTINGS),
  )
  await db.batch(stmts)
}

/** Full wipe + rebuild of the demo dataset. Idempotent. */
export async function runReseed(env: DemoEnv): Promise<ReseedSummary> {
  const start = Date.now()
  const db = env.DB

  // 1. Count then wipe all tenant documents + derived rows (R7: delete derived
  //    explicitly; don't rely on FK cascade).
  const countRow = await db
    .prepare(`SELECT COUNT(*) AS n FROM documents WHERE tenant_id = ?`)
    .bind(TENANT)
    .first<{ n: number }>()
  const wiped = countRow?.n ?? 0

  await db.batch([
    db
      .prepare(`DELETE FROM document_facets WHERE document_id IN (SELECT id FROM documents WHERE tenant_id = ?)`)
      .bind(TENANT),
    db
      .prepare(`DELETE FROM document_references WHERE from_document_id IN (SELECT id FROM documents WHERE tenant_id = ?)`)
      .bind(TENANT),
    db.prepare(`DELETE FROM document_permissions WHERE tenant_id = ?`).bind(TENANT),
    db.prepare(`DELETE FROM documents WHERE tenant_id = ?`).bind(TENANT),
  ])

  // 2. Purge previously-seeded media from R2 so objects don't accumulate.
  await purgePrefix(env.MEDIA_BUCKET, `${MEDIA_FOLDER}/`)

  // 3. Ensure document types exist before any insert.
  await ensureTypes(db)

  // 4. Seed media: upload SVG bytes to R2 + register media_asset documents.
  const mediaSvc = new MediaDocumentService(db, TENANT)
  let media = 0
  for (const image of DEMO_IMAGES) {
    const bytes = new TextEncoder().encode(image.svg)
    await env.MEDIA_BUCKET.put(image.r2Key, bytes, {
      httpMetadata: { contentType: image.mime },
    })
    await mediaSvc.createFromUpload(
      {
        filename: image.filename,
        originalName: image.filename,
        mimeType: image.mime,
        size: bytes.byteLength,
        width: image.width,
        height: image.height,
        folder: MEDIA_FOLDER,
        r2Key: image.r2Key,
        alt: image.alt,
      },
      'system',
    )
    media++
  }

  // 5. Seed collection content (published-on-create).
  const docs = new DocumentsService(db, { tenantId: TENANT })
  let created = 0
  for (const collection of SEED_COLLECTIONS) {
    for (const item of collection.items) {
      await docs.create(
        {
          typeId: collection.typeId,
          tenantId: TENANT,
          locale: 'default',
          parentRootId: '',
          slug: item.slug,
          title: item.title,
          sortOrder: 0,
          visible: true,
          data: item.data,
          metadata: {},
          publishOnCreate: true,
        },
        'system',
      )
      created++
    }
  }

  // 6. Re-assert the demo-login prefill (its plugin document was wiped in step 1).
  if (env.ENVIRONMENT === 'demo') {
    try {
      await ensureDemoLoginActive(db)
    } catch (e) {
      console.warn('[demo-seed] Could not re-activate demo login:', e)
    }
  }

  return { wiped, created, media, ms: Date.now() - start }
}
