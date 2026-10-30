/**
 * Backfill: migrate ALL existing legacy `content` rows into the document model (any collection that is
 * document-backed — which, after autoRegisterCollectionDocumentTypes, is every user collection).
 * Non-destructive — legacy content rows are left in place. Idempotent: a row whose (collection, slug)
 * already exists as a document is skipped, so re-running is safe.
 *
 * Use this to move content created before its collection became document-backed (e.g. a news item
 * added while only blog_post was converted).
 *
 * Run from my-sonicjs-app/:
 *   npx tsx scripts/backfill-content.ts
 */
import { getPlatformProxy } from 'wrangler'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../packages/core/src/services/document-types-seed'
import { DocumentTypeRegistry } from '../../packages/core/src/services/document-type-registry'
import { DocumentsService } from '../../packages/core/src/services/documents'
import { createDocumentSchema } from '../../packages/core/src/schemas/document'

async function backfill() {
  const { env, dispose } = await getPlatformProxy()
  const db = (env as any).DB as D1Database
  if (!db) {
    console.error('❌ DB binding not found. Check wrangler.toml.')
    process.exit(1)
  }

  try {
    await bootstrapDocumentTypes(db)
    const auto = await autoRegisterCollectionDocumentTypes(db)
    if (auto.length) console.log(`Registered document types for collections: ${auto.join(', ')}`)

    const registry = new DocumentTypeRegistry(db)
    const { results: rows } = await db
      .prepare(
        `SELECT c.*, col.name AS collection_name FROM content c
         JOIN collections col ON c.collection_id = col.id
         WHERE c.status != 'deleted'`,
      )
      .all<any>()
    console.log(`Found ${rows?.length ?? 0} content rows to consider.`)

    let created = 0
    let skipped = 0
    let notBacked = 0

    for (const row of rows ?? []) {
      const docType = await registry.findById(row.collection_name)
      if (!docType) {
        notBacked++
        continue // collection not document-backed (e.g. form-sourced) — leave it on the content table
      }

      const slug = row.slug || null
      if (slug) {
        const existing = await db
          .prepare("SELECT id FROM documents WHERE type_id = ? AND tenant_id = 'default' AND is_current_draft = 1 AND slug = ?")
          .bind(row.collection_name, slug)
          .first()
        if (existing) {
          skipped++
          continue
        }
      }

      const data = row.data ? JSON.parse(row.data) : {}
      const svc = new DocumentsService(db, {
        queryableFields: docType.queryableFields ?? [],
        typeSchemaVersion: docType.schemaVersion ?? 1,
        maxVersionsPerRoot: docType.settings?.maxVersionsPerRoot ?? 50,
        tenantId: 'default',
      })
      // Preserve the legacy row's original timestamps (D34). Legacy `content` stores MILLISECONDS;
      // documents store SECONDS — convert. Fall back to undefined (→ now) when a timestamp is absent.
      const toSec = (ms: any) => (typeof ms === 'number' && ms > 0 ? Math.floor(ms / 1000) : undefined)
      const doc = await svc.create(
        createDocumentSchema.parse({
          typeId: row.collection_name,
          tenantId: 'default',
          locale: 'default',
          title: row.title || data.title || slug || 'Untitled',
          slug: slug || undefined,
          data,
          publishOnCreate: row.status === 'published',
          createdAt: toSec(row.created_at),
          updatedAt: toSec(row.updated_at),
        }),
        row.author_id || undefined,
      )
      created++
      console.log(`  ✓ [${row.collection_name}] ${doc.rootId}  ${doc.title}`)
    }

    console.log(`\nDone. Created ${created} document(s); skipped ${skipped} already-migrated; ${notBacked} on non-doc-backed collections.`)
    console.log('Legacy content rows were left in place.')
  } finally {
    await dispose()
  }
}

backfill()
