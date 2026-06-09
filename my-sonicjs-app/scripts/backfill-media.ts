/**
 * Backfill: mirror existing `media` rows into media_asset documents (Phase 6).
 * Non-destructive — legacy media rows are left in place. Idempotent: a file whose r2Key already has a
 * media_asset document is skipped, so re-running is safe (and it complements the upload dual-write,
 * which only mirrors NEW uploads).
 *
 * Run from my-sonicjs-app/:
 *   npx tsx scripts/backfill-media.ts
 */
import { getPlatformProxy } from 'wrangler'
import { bootstrapDocumentTypes } from '../../packages/core/src/services/document-types-seed'
import { MediaDocumentService } from '../../packages/core/src/services/media-documents'

async function backfill() {
  const { env, dispose } = await getPlatformProxy()
  const db = (env as any).DB as D1Database
  if (!db) {
    console.error('❌ DB binding not found. Check wrangler.toml.')
    process.exit(1)
  }

  try {
    await bootstrapDocumentTypes(db)
    const svc = new MediaDocumentService(db, 'default')

    const { results: rows } = await db
      .prepare('SELECT * FROM media WHERE deleted_at IS NULL')
      .all<any>()
    console.log(`Found ${rows?.length ?? 0} media rows to consider.`)

    let created = 0
    let skipped = 0
    for (const row of rows ?? []) {
      const existing = await db
        .prepare("SELECT id FROM documents WHERE type_id = 'media_asset' AND tenant_id = 'default' AND is_current_draft = 1 AND json_extract(data, '$.r2Key') = ?")
        .bind(row.r2_key)
        .first()
      if (existing) {
        skipped++
        continue
      }

      const doc = await svc.createFromUpload(
        {
          filename: row.filename,
          originalName: row.original_name ?? row.filename,
          mimeType: row.mime_type ?? 'application/octet-stream',
          size: row.size ?? 0,
          width: row.width ?? null,
          height: row.height ?? null,
          folder: row.folder ?? 'uploads',
          r2Key: row.r2_key,
          alt: row.alt ?? '',
          caption: row.caption ?? '',
          tags: row.tags ? (typeof row.tags === 'string' ? JSON.parse(row.tags) : row.tags) : [],
        },
        row.uploaded_by ?? undefined,
      )
      created++
      console.log(`  ✓ ${doc.rootId}  ${row.filename}`)
    }

    console.log(`\nDone. Created ${created} media_asset document(s); skipped ${skipped} already-mirrored.`)
    console.log('Legacy media rows were left in place.')
  } finally {
    await dispose()
  }
}

backfill()
