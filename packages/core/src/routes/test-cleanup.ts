/**
 * Test Cleanup Routes
 *
 * Endpoints that wipe disposable test data between e2e runs.
 *
 * Data model: the document model is authoritative. Test artifacts are `documents`
 * rows (matched by title pattern or by a `test_*` type_id) plus test `auth_user`
 * rows. Legacy tables (`content`, `collections`, `media`, …) were decommissioned in
 * the v3 migration; every reference to them here is guarded so a greenfield schema
 * (which never creates them) does not throw.
 *
 * SECURITY: these endpoints delete data and require no auth. They are gated
 * fail-closed — only reachable when `ENVIRONMENT` is an explicit non-production
 * value (development/test/e2e/preview/local). An unset or production ENVIRONMENT
 * is denied, so a default `wrangler deploy` cannot expose them.
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'

const app = new Hono()

// Environments where destructive cleanup is permitted. Anything else (including
// 'production' and an unset value) is denied.
const ALLOWED_ENVIRONMENTS = new Set(['development', 'test', 'e2e', 'preview', 'local'])

function cleanupAllowed(c: Context): boolean {
  const env = (c.env.ENVIRONMENT ?? '').toString().toLowerCase()
  return ALLOWED_ENVIRONMENTS.has(env)
}

function denyResponse(c: Context) {
  return c.json({ error: 'Cleanup endpoint not available in this environment' }, 403)
}

async function tableExists(db: D1Database, tableName: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(tableName)
    .first()
  return !!row
}

// Run a delete and return the row count. Swallows "no such table" so statements that
// touch decommissioned legacy tables are safe on a greenfield (document-model) schema.
async function tryDelete(db: D1Database, sql: string, ...binds: unknown[]): Promise<number> {
  try {
    const stmt = binds.length ? db.prepare(sql).bind(...(binds as never[])) : db.prepare(sql)
    const res = await stmt.run()
    return res.meta?.changes || 0
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error)
    if (/no such table|no such column/i.test(msg)) return 0
    throw error
  }
}

const TEST_TITLE_PATTERN =
  "title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'"

/**
 * Clean up all disposable test data.
 * POST /test-cleanup
 */
app.post('/test-cleanup', async (c: Context) => {
  if (!cleanupAllowed(c)) return denyResponse(c)
  const db = c.env.DB as D1Database

  try {
    let deletedCount = 0

    // ── Document model (authoritative) ──────────────────────────────────────
    // Test content/media by title pattern.
    deletedCount += await tryDelete(
      db,
      `DELETE FROM documents WHERE tenant_id = 'default' AND (${TEST_TITLE_PATTERN})`,
    )
    // Documents belonging to disposable test types (collections are code-only now,
    // so a "test collection" is just a type_id).
    deletedCount += await tryDelete(
      db,
      `DELETE FROM documents
       WHERE tenant_id = 'default'
         AND (type_id LIKE 'test_%' OR type_id IN ('test_collection', 'products', 'articles'))`,
    )

    // ── Test users + their child rows ───────────────────────────────────────
    const TEST_USER =
      "email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')"
    await tryDelete(db, `DELETE FROM auth_api_tokens WHERE user_id IN (SELECT id FROM auth_user WHERE ${TEST_USER})`)
    deletedCount += await tryDelete(db, `DELETE FROM auth_user WHERE ${TEST_USER}`)

    // ── Legacy tables (guarded — absent on greenfield) ──────────────────────
    if (await tableExists(db, 'content')) {
      const childByPattern = (table: string) =>
        tryDelete(
          db,
          `DELETE FROM ${table} WHERE content_id IN (SELECT id FROM content WHERE ${TEST_TITLE_PATTERN})`,
        )
      await childByPattern('content_versions')
      await childByPattern('workflow_history')
      await childByPattern('content_data')
      deletedCount += await tryDelete(db, `DELETE FROM content WHERE ${TEST_TITLE_PATTERN}`)
      // Orphan sweep.
      await tryDelete(db, 'DELETE FROM content_data WHERE content_id NOT IN (SELECT id FROM content)')
      await tryDelete(db, 'DELETE FROM content_versions WHERE content_id NOT IN (SELECT id FROM content)')
      await tryDelete(db, 'DELETE FROM workflow_history WHERE content_id NOT IN (SELECT id FROM content)')
    }
    // Trim activity log (guarded).
    await tryDelete(
      db,
      'DELETE FROM activity_logs WHERE id NOT IN (SELECT id FROM activity_logs ORDER BY created_at DESC LIMIT 100)',
    )

    return c.json({ success: true, deletedCount, message: 'Test data cleaned up successfully' })
  } catch (error) {
    console.error('Test cleanup error:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500)
  }
})

/**
 * Clean up test users only.
 * POST /test-cleanup/users
 */
app.post('/test-cleanup/users', async (c: Context) => {
  if (!cleanupAllowed(c)) return denyResponse(c)
  const db = c.env.DB as D1Database

  try {
    const deletedCount = await tryDelete(
      db,
      `DELETE FROM auth_user
       WHERE email != 'admin@sonicjs.com'
         AND (email LIKE '%test%' OR email LIKE '%example.com%' OR first_name = 'Test')`,
    )
    return c.json({ success: true, deletedCount, message: 'Test users cleaned up successfully' })
  } catch (error) {
    console.error('User cleanup error:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500)
  }
})

/**
 * Clean up disposable test "collections" — now just documents of a test type_id.
 * POST /test-cleanup/collections
 */
app.post('/test-cleanup/collections', async (c: Context) => {
  if (!cleanupAllowed(c)) return denyResponse(c)
  const db = c.env.DB as D1Database

  try {
    let deletedCount = await tryDelete(
      db,
      `DELETE FROM documents
       WHERE tenant_id = 'default'
         AND (type_id LIKE 'test_%' OR type_id IN ('test_collection', 'products', 'articles'))`,
    )
    // Legacy collection rows, if the table still exists.
    deletedCount += await tryDelete(
      db,
      "DELETE FROM collections WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')",
    )
    await tryDelete(db, 'DELETE FROM collection_fields WHERE collection_id NOT IN (SELECT id FROM collections)')

    return c.json({ success: true, deletedCount, message: 'Test collections cleaned up successfully' })
  } catch (error) {
    console.error('Collection cleanup error:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500)
  }
})

/**
 * Clean up test content only.
 * POST /test-cleanup/content
 */
app.post('/test-cleanup/content', async (c: Context) => {
  if (!cleanupAllowed(c)) return denyResponse(c)
  const db = c.env.DB as D1Database

  try {
    let deletedCount = await tryDelete(
      db,
      `DELETE FROM documents WHERE tenant_id = 'default' AND (${TEST_TITLE_PATTERN})`,
    )
    if (await tableExists(db, 'content')) {
      deletedCount += await tryDelete(db, `DELETE FROM content WHERE ${TEST_TITLE_PATTERN}`)
      await tryDelete(db, 'DELETE FROM content_data WHERE content_id NOT IN (SELECT id FROM content)')
    }
    return c.json({ success: true, deletedCount, message: 'Test content cleaned up successfully' })
  } catch (error) {
    console.error('Content cleanup error:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500)
  }
})

/**
 * Re-seed default content required by E2E specs.
 * POST /test-seed-defaults
 *
 * Idempotent: creates the welcome blog post if absent or soft-deleted,
 * skips if already present. Should be called from global-setup after cleanup.
 */
app.post('/test-seed-defaults', async (c: Context) => {
  if (!cleanupAllowed(c)) return denyResponse(c)
  const db = c.env.DB as D1Database

  try {
    const BLOG_POST_TYPE = 'blog_post'
    const WELCOME_SLUG = 'welcome-to-sonicjs'

    const existing = await db
      .prepare(
        `SELECT id, deleted_at FROM documents
         WHERE type_id = ? AND tenant_id = 'default' AND slug = ? AND is_current_draft = 1`,
      )
      .bind(BLOG_POST_TYPE, WELCOME_SLUG)
      .first() as any

    if (existing && !existing.deleted_at) {
      return c.json({ success: true, action: 'skipped', message: 'Welcome post already exists' })
    }

    const nowSec = Math.floor(Date.now() / 1000)

    if (existing && existing.deleted_at) {
      // Restore soft-deleted post
      await db
        .prepare(
          `UPDATE documents SET deleted_at = NULL, updated_at = ?, is_published = 1, is_current_draft = 1
           WHERE id = ?`,
        )
        .bind(nowSec, existing.id)
        .run()
      return c.json({ success: true, action: 'restored', message: 'Welcome post restored' })
    }

    // Ensure blog_post document type exists
    const typeExists = await db
      .prepare(`SELECT id FROM document_types WHERE id = ? AND tenant_id = 'default'`)
      .bind(BLOG_POST_TYPE)
      .first()
    if (!typeExists) {
      return c.json({ success: false, error: 'blog_post document type not seeded yet' }, 500)
    }

    const id = `blog-post-welcome-seed`
    const dataJson = JSON.stringify({
      title: 'Welcome to SonicJS',
      slug: WELCOME_SLUG,
      excerpt: 'Start building with the Cloudflare-native SonicJS CMS.',
      content: '<p>Welcome to SonicJS. This first post confirms your default blog content is ready.</p>',
      author: 'SonicJS',
      status: 'published',
      difficulty: 'beginner',
      tags: 'welcome,sonicjs',
    })

    await db
      .prepare(
        `INSERT INTO documents
           (id, root_id, version_number, type_id, tenant_id, locale, slug, title,
            data, sort_order, visible, is_current_draft, is_published, status,
            created_at, updated_at, deleted_at)
         VALUES (?, ?, 1, ?, 'default', 'default', ?, ?, ?, 0, 1, 1, 1, 'published', ?, ?, NULL)`,
      )
      .bind(id, id, BLOG_POST_TYPE, WELCOME_SLUG, 'Welcome to SonicJS', dataJson, nowSec, nowSec)
      .run()

    return c.json({ success: true, action: 'created', message: 'Welcome post created' })
  } catch (error) {
    console.error('Seed defaults error:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }, 500)
  }
})

export default app
