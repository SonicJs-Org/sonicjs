/**
 * Test Cleanup Routes
 *
 * Provides endpoints to clean up test data after e2e tests
 * WARNING: These endpoints should only be available in development/test environments
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'

const app = new Hono()

async function tableExists(db: D1Database, tableName: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(tableName)
    .first()
  return !!row
}

/**
 * Clean up all test data (collections, content, users except admin)
 * POST /test-cleanup
 */
app.post('/test-cleanup', async (c: Context) => {
  const db = c.env.DB as D1Database

  // Only allow in development/test environments
  if (c.env.ENVIRONMENT === 'production') {
    return c.json({ error: 'Cleanup endpoint not available in production' }, 403)
  }

  try {
    let deletedCount = 0
    const hasContentTable = await tableExists(db, 'content')

    // Use pattern-based deletes to avoid SQL variable limits
    // This approach uses subqueries instead of building large IN lists

    const documentsResult = await db.prepare(`
      DELETE FROM documents
      WHERE tenant_id = 'default'
        AND (title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%')
    `).run()
    deletedCount += documentsResult.meta?.changes || 0

    // Step 1: Delete child data for test content (by pattern)
    if (hasContentTable) {
      await db.prepare(`
        DELETE FROM content_versions
        WHERE content_id IN (
          SELECT id FROM content
          WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
        )
      `).run()

      await db.prepare(`
        DELETE FROM workflow_history
        WHERE content_id IN (
          SELECT id FROM content
          WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
        )
      `).run()

      // Note: content_data table may not exist in all schemas
      try {
        await db.prepare(`
          DELETE FROM content_data
          WHERE content_id IN (
            SELECT id FROM content
            WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
          )
        `).run()
      } catch (e) {
        // Table doesn't exist, skip
      }

      // Step 2: Delete test content by pattern
      const contentResult = await db.prepare(`
        DELETE FROM content
        WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
      `).run()
      deletedCount += contentResult.meta?.changes || 0
    }

    // Step 3: Delete child data for test users
    await db.prepare(`
      DELETE FROM api_tokens
      WHERE user_id IN (
        SELECT id FROM users
        WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')
      )
    `).run()

    await db.prepare(`
      DELETE FROM media
      WHERE uploaded_by IN (
        SELECT id FROM users
        WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')
      )
    `).run()

    // Step 4: Delete test users
    const usersResult = await db.prepare(`
      DELETE FROM users
      WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')
    `).run()
    deletedCount += usersResult.meta?.changes || 0

    // Step 5: Delete child data for test collections.
    // NOTE: `blog_post` is intentionally NOT in this list — it is a SEEDED collection (migration 001)
    // that backs the document-model blog feature, not disposable test data. Deleting it here broke the
    // doc-backed blog e2e (the new-content form had no collection to resolve). Only genuine test
    // artifacts are removed.
    try {
      await db.prepare(`
        DELETE FROM collection_fields
        WHERE collection_id IN (
          SELECT id FROM collections
          WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
        )
      `).run()
    } catch (e) {
      // Table doesn't exist
    }

    await db.prepare(`
      DELETE FROM documents
      WHERE tenant_id = 'default'
        AND type_id IN (
          SELECT name FROM collections
          WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
        )
    `).run()

    // Delete remaining legacy content from test collections
    if (hasContentTable) {
      await db.prepare(`
        DELETE FROM content
        WHERE collection_id IN (
          SELECT id FROM collections
          WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
        )
      `).run()
    }

    // Step 6: Delete test collections
    const collectionsResult = await db.prepare(`
      DELETE FROM collections
      WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
    `).run()
    deletedCount += collectionsResult.meta?.changes || 0

    // Step 7: Clean up orphaned data (skip if tables don't exist)
    if (hasContentTable) {
      try {
        await db.prepare(`
          DELETE FROM content_data WHERE content_id NOT IN (SELECT id FROM content)
        `).run()
      } catch (e) {
        // Table doesn't exist
      }
    }

    try {
      await db.prepare(`
        DELETE FROM collection_fields WHERE collection_id NOT IN (SELECT id FROM collections)
      `).run()
    } catch (e) {
      // Table doesn't exist
    }

    if (hasContentTable) {
      try {
        await db.prepare(`
          DELETE FROM content_versions WHERE content_id NOT IN (SELECT id FROM content)
        `).run()
      } catch (e) {
        // Table doesn't exist
      }

      try {
        await db.prepare(`
          DELETE FROM workflow_history WHERE content_id NOT IN (SELECT id FROM content)
        `).run()
      } catch (e) {
        // Table doesn't exist
      }
    }

    // Step 8: Delete old activity logs (keep only last 100)
    await db.prepare(`
      DELETE FROM activity_logs
      WHERE id NOT IN (
        SELECT id FROM activity_logs
        ORDER BY created_at DESC
        LIMIT 100
      )
    `).run()

    return c.json({
      success: true,
      deletedCount,
      message: 'Test data cleaned up successfully'
    })
  } catch (error) {
    console.error('Test cleanup error:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

/**
 * Clean up test users only
 * POST /test-cleanup/users
 */
app.post('/test-cleanup/users', async (c: Context) => {
  const db = c.env.DB as D1Database

  // Only allow in development/test environments
  if (c.env.ENVIRONMENT === 'production') {
    return c.json({ error: 'Cleanup endpoint not available in production' }, 403)
  }

  try {
    // Delete test users (preserve admin)
    const result = await db.prepare(`
      DELETE FROM users
      WHERE email != 'admin@sonicjs.com'
      AND (
        email LIKE '%test%'
        OR email LIKE '%example.com%'
        OR first_name = 'Test'
      )
    `).run()

    return c.json({
      success: true,
      deletedCount: result.meta?.changes || 0,
      message: 'Test users cleaned up successfully'
    })
  } catch (error) {
    console.error('User cleanup error:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

/**
 * Clean up test collections only
 * POST /test-cleanup/collections
 */
app.post('/test-cleanup/collections', async (c: Context) => {
  const db = c.env.DB as D1Database

  // Only allow in development/test environments
  if (c.env.ENVIRONMENT === 'production') {
    return c.json({ error: 'Cleanup endpoint not available in production' }, 403)
  }

  try {
    let deletedCount = 0
    const hasContentTable = await tableExists(db, 'content')

    // Get test collection IDs first
    const collections = await db.prepare(`
      SELECT id, name FROM collections
      WHERE name LIKE 'test_%'
      OR name IN ('test_collection', 'products', 'articles')
    `).all()

    if (collections.results && collections.results.length > 0) {
      const collectionIds = collections.results.map((c: any) => c.id)

      // Delete associated fields
      for (const id of collectionIds) {
        await db.prepare('DELETE FROM collection_fields WHERE collection_id = ?').bind(id).run()
      }

      for (const collection of collections.results as any[]) {
        await db.prepare("DELETE FROM documents WHERE tenant_id = 'default' AND type_id = ?").bind(collection.name).run()
      }

      // Delete associated legacy content
      if (hasContentTable) {
        for (const id of collectionIds) {
          await db.prepare('DELETE FROM content WHERE collection_id = ?').bind(id).run()
        }
      }

      // Delete the collections
      const result = await db.prepare(`
        DELETE FROM collections
        WHERE id IN (${collectionIds.map(() => '?').join(',')})
      `).bind(...collectionIds).run()

      deletedCount = result.meta?.changes || 0
    }

    return c.json({
      success: true,
      deletedCount,
      message: 'Test collections cleaned up successfully'
    })
  } catch (error) {
    console.error('Collection cleanup error:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

/**
 * Clean up test content only
 * POST /test-cleanup/content
 */
app.post('/test-cleanup/content', async (c: Context) => {
  const db = c.env.DB as D1Database

  // Only allow in development/test environments
  if (c.env.ENVIRONMENT === 'production') {
    return c.json({ error: 'Cleanup endpoint not available in production' }, 403)
  }

  try {
    const documentsResult = await db.prepare(`
      DELETE FROM documents
      WHERE tenant_id = 'default'
      AND (
        title LIKE 'Test %'
        OR title LIKE '%E2E%'
        OR title LIKE '%Playwright%'
        OR title LIKE '%Sample%'
      )
    `).run()

    let deletedCount = documentsResult.meta?.changes || 0
    const hasContentTable = await tableExists(db, 'content')
    if (hasContentTable) {
      const result = await db.prepare(`
        DELETE FROM content
        WHERE title LIKE 'Test %'
        OR title LIKE '%E2E%'
        OR title LIKE '%Playwright%'
        OR title LIKE '%Sample%'
      `).run()
      deletedCount += result.meta?.changes || 0
    }

    if (hasContentTable) {
      // Clean up orphaned content_data
      await db.prepare(`
        DELETE FROM content_data
        WHERE content_id NOT IN (SELECT id FROM content)
      `).run()
    }

    return c.json({
      success: true,
      deletedCount,
      message: 'Test content cleaned up successfully'
    })
  } catch (error) {
    console.error('Content cleanup error:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

export default app
