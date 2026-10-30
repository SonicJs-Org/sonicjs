/**
 * Backfill: migrate existing `blog_post` collection content (the `content` table) into the
 * document model (Option B). Non-destructive — the legacy content rows are LEFT IN PLACE for
 * rollback (per the plan's "keep the table-backed path" rule). Idempotent: a post whose slug already
 * exists as a blog_post document is skipped, so re-running is safe.
 *
 * Run from my-sonicjs-app/:
 *   npx tsx scripts/backfill-blog-posts.ts
 */
import { getPlatformProxy } from 'wrangler'
import { DocumentsService } from '../../packages/core/src/services/documents'
import { DocumentTypeRegistry } from '../../packages/core/src/services/document-type-registry'
import { bootstrapDocumentTypes } from '../../packages/core/src/services/document-types-seed'
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
    const registry = new DocumentTypeRegistry(db)
    const docType = await registry.findById('blog_post')
    if (!docType) {
      console.error('❌ blog_post document type not registered.')
      process.exit(1)
    }

    const svc = new DocumentsService(db, {
      queryableFields: docType.queryableFields ?? [],
      typeSchemaVersion: docType.schemaVersion ?? 1,
      maxVersionsPerRoot: docType.settings?.maxVersionsPerRoot ?? 50,
      tenantId: 'default',
    })

    const { results: rows } = await db
      .prepare(
        `SELECT c.* FROM content c JOIN collections col ON c.collection_id = col.id
         WHERE col.name = 'blog_post' AND c.status != 'deleted'`,
      )
      .all<any>()

    console.log(`Found ${rows?.length ?? 0} blog_post content rows to consider.`)
    let created = 0
    let skipped = 0

    for (const row of rows ?? []) {
      const data = row.data ? JSON.parse(row.data) : {}
      const slug = row.slug || data.slug || null

      // Idempotency: skip if a blog_post document with this slug already exists.
      if (slug) {
        const existing = await db
          .prepare("SELECT id FROM documents WHERE type_id = 'blog_post' AND tenant_id = 'default' AND slug = ? AND is_current_draft = 1")
          .bind(slug)
          .first()
        if (existing) {
          skipped++
          continue
        }
      }

      const doc = await svc.create(
        createDocumentSchema.parse({
          typeId: 'blog_post',
          tenantId: 'default',
          locale: 'default',
          title: row.title || data.title || slug || 'Untitled',
          slug: slug || undefined,
          data,
          publishOnCreate: row.status === 'published',
        }),
        row.author_id || undefined,
      )
      created++
      console.log(`  ✓ ${doc.rootId}  ${doc.title}${row.status === 'published' ? ' (published)' : ''}`)
    }

    console.log(`\nDone. Created ${created} blog post document(s); skipped ${skipped} already-migrated.`)
    console.log('Legacy content rows were left in place for rollback.')
  } finally {
    await dispose()
  }
}

backfill()
