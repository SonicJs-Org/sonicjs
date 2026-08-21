/**
 * Backfill: populate `documents_fts` for documents written before the FTS projection seam existed,
 * or after an FTS schema rebuild (FTS5 has no ALTER TABLE — a column change drops + recreates the
 * table, see migration 0003). Idempotent: `reindexType` upserts (delete + insert) per row, so
 * re-running is safe. New installs don't need this — the projection indexes from the first write.
 *
 * Run from my-sonicjs-app/:
 *   npx tsx scripts/backfill-fts.ts
 */
import { getPlatformProxy } from 'wrangler'
import { DocumentProjection } from '../../packages/core/src/services/document-projection'

async function backfill() {
  const { env, dispose } = await getPlatformProxy()
  const db = (env as any).DB as D1Database
  if (!db) {
    console.error('❌ DB binding not found. Check wrangler.toml.')
    process.exit(1)
  }

  try {
    const { results: types } = await db
      .prepare('SELECT id, queryable_fields FROM document_types WHERE is_active = 1')
      .all<{ id: string; queryable_fields: string }>()

    const projection = new DocumentProjection(db)
    let total = 0

    for (const t of types ?? []) {
      const queryableFields = JSON.parse(t.queryable_fields || '[]')
      // reindexType is per (type, tenant); walk every tenant that has indexable rows of this type.
      const { results: tenants } = await db
        .prepare(
          `SELECT DISTINCT tenant_id FROM documents
           WHERE type_id = ? AND (is_current_draft = 1 OR is_published = 1) AND deleted_at IS NULL`,
        )
        .bind(t.id)
        .all<{ tenant_id: string }>()

      for (const { tenant_id } of tenants ?? []) {
        const n = await projection.reindexType(t.id, tenant_id, queryableFields)
        if (n > 0) console.log(`  ${t.id} @ ${tenant_id}: ${n} rows`)
        total += n
      }
    }

    console.log(`✅ Backfilled ${total} documents into documents_fts.`)
  } finally {
    await dispose()
  }
}

backfill().catch((e) => {
  console.error(e)
  process.exit(1)
})
