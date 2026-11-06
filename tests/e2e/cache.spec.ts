import { test } from "./fixtures"
import { expect } from "./fixtures"
import { ensurePluginActive } from "./fixtures/plugin-fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { waitForHTMX } from "./utils/test-helpers"
import { isFeatureAvailable } from "./utils/test-helpers"
import { ADMIN_CREDENTIALS } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import type { APIRequestContext } from "@playwright/test"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 43-cache-plugin.spec.ts", () => {
  /**
   * Cache Plugin E2E Tests
   *
   * Tests for the cache management admin UI and API endpoints
   * Issue #461: https://github.com/SonicJs-Org/sonicjs/issues/461
   */




  test.describe('Cache Plugin Dashboard @plugins', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/cache')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
      // The sidebar entry only exists while `core-cache` is active, and it is not one of the
      // plugins bootstrapped on a greenfield install.
      await ensurePluginActive(page, 'core-cache');
    });

    test('should navigate to cache dashboard from admin menu', async ({ page }) => {
      // Navigate to admin dashboard first
      await page.goto('/admin');
      await waitForHTMX(page);

      // Look for Cache menu item in navigation (use first() since there may be desktop + mobile sidebars)
      const cacheLink = page.locator('a[href="/admin/cache"]').first();

      // Click on Cache menu item
      await cacheLink.click();
      await waitForHTMX(page);

      // Verify we're on the cache page
      await expect(page).toHaveURL(/\/admin\/cache/);

      // Verify cache dashboard content is visible - look for the page heading
      await expect(page.getByRole('heading', { name: 'Cache System' })).toBeVisible();
    });

    test('should display cache dashboard with statistics', async ({ page }) => {
      // Navigate directly to cache dashboard
      await page.goto('/admin/cache');
      await waitForHTMX(page);

      // Verify we get 200 OK (not 404)
      const response = await page.request.get('/admin/cache');
      expect(response.status()).toBe(200);

      // Verify page contains cache-related content
      const html = await page.content();
      expect(html.toLowerCase()).toContain('cache');
    });

    test('should display cache statistics cards', async ({ page }) => {
      await page.goto('/admin/cache');
      await waitForHTMX(page);

      // Should show statistics (may have various formats)
      // Just verify the page loaded successfully and has cache-related content
      const content = await page.content();
      expect(content.toLowerCase()).toContain('cache');
    });

    test('should have clear all caches button', async ({ page }) => {
      await page.goto('/admin/cache');
      await waitForHTMX(page);

      // The dashboard renders "Clear All" unconditionally (admin-cache.template.ts), so this is a
      // hard requirement. `toBeGreaterThanOrEqual(0)` was true of every possible count, including
      // the one where the page failed to render any buttons at all.
      const clearButton = page.locator('button').filter({ hasText: /clear/i }).first();
      await expect(clearButton).toBeVisible();
    });

    test('should have refresh functionality', async ({ page }) => {
      await page.goto('/admin/cache');
      await waitForHTMX(page);

      // Look for refresh button
      // Also rendered unconditionally; the old `if (count > 0)` turned a missing Refresh button
      // into a pass for the test whose whole subject is the Refresh button.
      const refreshButton = page.locator('button').filter({ hasText: /refresh/i }).first();
      await expect(refreshButton).toBeVisible();

      await refreshButton.click();
      await waitForHTMX(page);

      // Page should still be on cache dashboard
      await expect(page).toHaveURL(/\/admin\/cache/);
      await expect(refreshButton).toBeVisible();
    });
  });

  test.describe('Cache API Endpoints @plugins @api', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should return 200 for GET /admin/cache', async ({ page }) => {
      const response = await page.request.get('/admin/cache');

      expect(response.status()).toBe(200);

      // Should return HTML (dashboard page)
      const contentType = response.headers()['content-type'];
      expect(contentType).toContain('text/html');
    });

    test('should return cache stats from /admin/cache/stats', async ({ page }) => {
      const response = await page.request.get('/admin/cache/stats');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data).toHaveProperty('data');
      expect(data).toHaveProperty('timestamp');
    });

    test('should return stats for specific namespace', async ({ page }) => {
      const response = await page.request.get('/admin/cache/stats/content');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data.data).toHaveProperty('namespace', 'content');
    });

    test('should return 404 for unknown namespace stats', async ({ page }) => {
      const response = await page.request.get('/admin/cache/stats/nonexistent-namespace');

      expect(response.status()).toBe(404);

      const data = await response.json();
      expect(data.success).toBe(false);
    });

    test('should clear all caches via POST /admin/cache/clear', async ({ page }) => {
      const response = await page.request.post('/admin/cache/clear');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data).toHaveProperty('message');
      expect(data.message).toContain('cleared');
    });

    test('should clear specific namespace cache', async ({ page }) => {
      const response = await page.request.post('/admin/cache/clear/content');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data).toHaveProperty('namespace', 'content');
    });

    test('should return 404 when clearing unknown namespace', async ({ page }) => {
      const response = await page.request.post('/admin/cache/clear/nonexistent-namespace');

      expect(response.status()).toBe(404);
    });

    test('should invalidate cache entries matching pattern', async ({ page }) => {
      const response = await page.request.post('/admin/cache/invalidate', {
        headers: { 'Content-Type': 'application/json' },
        data: { pattern: 'content:*' }
      });

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data).toHaveProperty('pattern', 'content:*');
      expect(data).toHaveProperty('invalidated');
      expect(typeof data.invalidated).toBe('number');
    });

    test('should return 400 when pattern is missing for invalidation', async ({ page }) => {
      const response = await page.request.post('/admin/cache/invalidate', {
        headers: { 'Content-Type': 'application/json' },
        data: {}
      });

      expect(response.status()).toBe(400);

      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error).toBe('Pattern is required');
    });

    test('should return cache health status', async ({ page }) => {
      const response = await page.request.get('/admin/cache/health');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data.data).toHaveProperty('status');
      expect(['healthy', 'warning', 'unhealthy']).toContain(data.data.status);
      expect(Array.isArray(data.data.namespaces)).toBe(true);
    });

    test('should return cache browser data', async ({ page }) => {
      const response = await page.request.get('/admin/cache/browser');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(Array.isArray(data.data.entries)).toBe(true);
      expect(typeof data.data.total).toBe('number');
      expect(typeof data.data.showing).toBe('number');
    });

    test('should support cache browser filtering', async ({ page }) => {
      const response = await page.request.get('/admin/cache/browser?namespace=content&search=test&sort=size&limit=10');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data.data.namespace).toBe('content');
      expect(data.data.search).toBe('test');
      expect(data.data.sortBy).toBe('size');
      expect(data.data.showing).toBeLessThanOrEqual(10);
    });

    test('should return cache analytics data', async ({ page }) => {
      const response = await page.request.get('/admin/cache/analytics');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data.data).toHaveProperty('overview');
      expect(data.data).toHaveProperty('performance');
      expect(data.data).toHaveProperty('namespaces');
      expect(data.data).toHaveProperty('invalidation');

      // Check performance metrics
      expect(typeof data.data.performance.dbQueriesAvoided).toBe('number');
      expect(typeof data.data.performance.timeSavedMs).toBe('number');
    });

    test('should return cache trends data', async ({ page }) => {
      const response = await page.request.get('/admin/cache/analytics/trends');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(Array.isArray(data.data.trends)).toBe(true);
    });

    test('should return top keys data (placeholder)', async ({ page }) => {
      const response = await page.request.get('/admin/cache/analytics/top-keys');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('success', true);
      expect(data.data).toHaveProperty('topKeys');
    });
  });

  test.describe('Cache Management Workflow @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should complete full cache management workflow', async ({ page }) => {
      // 1. Navigate to cache dashboard
      await page.goto('/admin/cache');
      await waitForHTMX(page);

      // Verify page loaded
      expect(page.url()).toContain('/admin/cache');

      // 2. Check health status via API
      const healthRes = await page.request.get('/admin/cache/health');
      expect(healthRes.status()).toBe(200);
      const healthData = await healthRes.json();
      expect(healthData.success).toBe(true);

      // 3. Get current stats
      const statsRes = await page.request.get('/admin/cache/stats');
      expect(statsRes.status()).toBe(200);

      // 4. Clear all caches
      const clearRes = await page.request.post('/admin/cache/clear');
      expect(clearRes.status()).toBe(200);
      const clearData = await clearRes.json();
      expect(clearData.success).toBe(true);

      // 5. Verify stats after clear
      const statsAfterRes = await page.request.get('/admin/cache/stats');
      expect(statsAfterRes.status()).toBe(200);

      // 6. Check analytics
      const analyticsRes = await page.request.get('/admin/cache/analytics');
      expect(analyticsRes.status()).toBe(200);
    });

    test('should handle namespace-specific operations', async ({ page }) => {
      // Clear content namespace
      const clearContentRes = await page.request.post('/admin/cache/clear/content');
      expect(clearContentRes.status()).toBe(200);

      const clearData = await clearContentRes.json();
      expect(clearData.namespace).toBe('content');

      // Get content namespace stats
      const statsRes = await page.request.get('/admin/cache/stats/content');
      expect(statsRes.status()).toBe(200);

      const statsData = await statsRes.json();
      expect(statsData.data.namespace).toBe('content');
    });

    test('should handle pattern-based invalidation', async ({ page }) => {
      // Invalidate all content entries
      const invalidateRes = await page.request.post('/admin/cache/invalidate', {
        headers: { 'Content-Type': 'application/json' },
        data: { pattern: 'post:*', namespace: 'content' }
      });

      expect(invalidateRes.status()).toBe(200);

      const data = await invalidateRes.json();
      expect(data.success).toBe(true);
      expect(data.namespace).toBe('content');
    });
  });

  test.describe('Cache Dashboard Navigation @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
      // Both tests below assert on the sidebar link, which `reconcileMenuFromPlugins` hides
      // unless `core-cache` is installed and active.
      await ensurePluginActive(page, 'core-cache');
    });

    test('should have Cache link in admin navigation', async ({ page }) => {
      await page.goto('/admin');
      await waitForHTMX(page);

      // Find cache link in navigation
      const cacheLink = page.locator('nav a[href="/admin/cache"], aside a[href="/admin/cache"], a[href="/admin/cache"]');

      // At least one cache link should exist
      await expect(cacheLink.first()).toBeVisible();
    });

    test('should navigate to cache dashboard when clicking Cache link', async ({ page }) => {
      await page.goto('/admin');
      await waitForHTMX(page);

      // Click on Cache link (use first() since there may be desktop + mobile sidebars)
      await page.locator('a[href="/admin/cache"]').first().click();
      await waitForHTMX(page);

      // Should be on cache page
      await expect(page).toHaveURL(/\/admin\/cache/);
    });
  });

  test.describe('Cache API Error Handling @plugins @api', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should handle invalid namespace gracefully', async ({ page }) => {
      // Try to get stats for invalid namespace
      const response = await page.request.get('/admin/cache/stats/invalid-namespace-12345');

      expect(response.status()).toBe(404);

      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error).toContain('Unknown namespace');
    });

    test('should handle missing pattern in invalidation request', async ({ page }) => {
      const response = await page.request.post('/admin/cache/invalidate', {
        headers: { 'Content-Type': 'application/json' },
        data: { namespace: 'content' } // Missing pattern
      });

      expect(response.status()).toBe(400);

      const data = await response.json();
      expect(data.success).toBe(false);
    });

    test('should handle invalid namespace in targeted invalidation', async ({ page }) => {
      const response = await page.request.post('/admin/cache/invalidate', {
        headers: { 'Content-Type': 'application/json' },
        data: { pattern: '*', namespace: 'invalid-namespace-xyz' }
      });

      expect(response.status()).toBe(404);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 80-cache-warming-documents.spec.ts", () => {
  /**
   * Cache Warming — Document Model
   *
   * Verifies the cache plugin's warm endpoint reads from the `documents` table
   * (not the legacy `content` / `media` tables) per the document-model migration.
   */




  test.describe('Cache Warming — document model @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('POST /admin/cache/warm succeeds and reports content + media namespaces', async ({ page }) => {
      const response = await page.request.post('/admin/cache/warm')

      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(Array.isArray(body.details)).toBe(true)

      const namespaces = body.details.map((d: { namespace: string }) => d.namespace)
      expect(namespaces).toContain('content')
      expect(namespaces).toContain('media')
      expect(namespaces).toContain('collection')
    })

    test('warming does not error against the documents table', async ({ page }) => {
      // Warm twice — if warming hit the dropped `media` table or a missing column,
      // the second call would surface the same error and `warmed` would stay 0 for that namespace.
      const first = await page.request.post('/admin/cache/warm')
      const second = await page.request.post('/admin/cache/warm')

      expect(first.status()).toBe(200)
      expect(second.status()).toBe(200)

      const body = await second.json()
      expect(body.success).toBe(true)
      const namespaces = new Set(
        (body.details as Array<{ namespace: string }>).map((d) => d.namespace)
      )
      expect(namespaces.has('content')).toBe(true)
      expect(namespaces.has('media')).toBe(true)
    })

    test('cache stats endpoint reflects content + media namespaces after warming', async ({ page }) => {
      await page.request.post('/admin/cache/warm')

      const stats = await page.request.get('/admin/cache/stats')
      expect(stats.status()).toBe(200)
      const body = await stats.json()
      expect(body.success).toBe(true)
      expect(body.data).toBeDefined()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 81-cache-collection-settings.spec.ts", () => {
  /**
   * Cache Plugin — Collection Settings Tab
   *
   * Verifies the Collection Settings tab on /admin/cache renders per-collection
   * cache config rows with clickable API path links that open in a new tab.
   */




  test.describe('Cache — Collection Settings tab @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/cache')
    })

    test('Collection Settings tab is present and activatable', async ({ page }) => {
      const tab = page.getByRole('button', { name: /collection settings/i })
      await expect(tab).toBeVisible()
      await tab.click()

      // Tab panel becomes visible
      const panel = page.locator('#tab-panel-collection-settings')
      await expect(panel).toBeVisible()
    })

    test('collection rows render with API path links', async ({ page }) => {
      await page.getByRole('button', { name: /collection settings/i }).click()

      // At least one API path link should exist
      const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
      await expect(links.first()).toBeVisible()
    })

    test('API path links open in new tab', async ({ page }) => {
      await page.getByRole('button', { name: /collection settings/i }).click()

      const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
      const count = await links.count()
      expect(count).toBeGreaterThan(0)

      // Every link must have target="_blank" and rel containing "noopener"
      for (let i = 0; i < count; i++) {
        const link = links.nth(i)
        await expect(link).toHaveAttribute('target', '_blank')
        const rel = await link.getAttribute('rel')
        expect(rel).toContain('noopener')
      }
    })

    test('blog-posts collection has correct /api/blog-posts link', async ({ page }) => {
      await page.getByRole('button', { name: /collection settings/i }).click()

      const link = page.locator('#tab-panel-collection-settings a[href="/api/blog-posts"]')
      await expect(link).toBeVisible()
      await expect(link).toHaveAttribute('target', '_blank')
    })

    test('API path link navigates to correct endpoint', async ({ page, context }) => {
      await page.getByRole('button', { name: /collection settings/i }).click()

      const links = page.locator('#tab-panel-collection-settings a[href^="/api/"]')
      const href = await links.first().getAttribute('href')
      expect(href).toBeTruthy()

      // Open in new page to verify endpoint responds
      const newPage = await context.newPage()
      const response = await newPage.goto(href!)
      expect(response?.status()).toBeLessThan(500)
      await newPage.close()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 97-cache-invalidation.spec.ts", () => {
  /**
   * Cache Invalidation E2E Tests
   *
   * Validates that updating a content item actually invalidates the in-memory
   * and KV API list cache so subsequent GET requests return fresh data.
   *
   * Regression for: invalidation patterns missing `api:` namespace prefix
   * (patterns like `content-filtered:*` never matched stored keys `api:content-filtered:...:v1`)
   */





  const API = TEST_ORIGIN
  // Collection slugs use underscores; `blog` is not a registered collection.
  const COLLECTION = 'blog_post'

  async function pollListForItem(
    request: APIRequestContext,
    itemId: string,
    { retries = 5, delayMs = 1000 } = {}
  ): Promise<any[]> {
    for (let i = 0; i < retries; i++) {
      const res = await request.get(`${API}/api/${COLLECTION}`)
      expect(res.status()).toBe(200)
      const items: any[] = (await res.json())?.data ?? []
      if (items.some((item) => item.id === itemId)) return items
      if (i < retries - 1) await new Promise((r) => setTimeout(r, delayMs))
    }
    const final = await request.get(`${API}/api/${COLLECTION}`)
    return (await final.json())?.data ?? []
  }

  test.describe('Cache invalidation — list freshness after item update @api', () => {
    test.beforeAll(async ({ request }) => {
      // Earlier sections of this consolidated spec file (43-cache-plugin,
      // 80-cache-warming-documents) warm the KV cache for blog_post with a
      // long TTL.  Without clearing first, the list endpoint keeps serving
      // the warmed snapshot and newly-created items never appear — causing
      // the cache-invalidation assertions below to fail on every retry.
      const loginRes = await request.post(`${API}/auth/sign-in/email`, {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      if (loginRes.ok()) {
        await request.post(`${API}/admin/cache/clear`)
      }
    })

    test('creating item via public API invalidates list cache', async ({ request }) => {
      const loginRes = await request.post(`${API}/auth/sign-in/email`, {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(loginRes.ok()).toBeTruthy()

      // Fetch list — populate cache
      const list1 = await request.get(`${API}/api/${COLLECTION}`)
      expect(list1.status()).toBe(200)
      const data1 = await list1.json()
      const idsBefore: string[] = (data1?.data ?? []).map((i: any) => i.id)

      // Create new item
      const stamp = Date.now()
      const createRes = await request.post(`${API}/api/${COLLECTION}`, {
        data: {
          title: `Cache test item ${stamp}`,
          slug: `cache-test-${stamp}`,
          data: {},
        },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(createRes.ok()).toBeTruthy()
      const createdId = (await createRes.json())?.data?.id
      expect(createdId).toBeTruthy()
      expect(idsBefore).not.toContain(createdId)

      // Fetch list again — must contain the new item, not a stale cached page.
      // Poll because Cloudflare Workers may route to a different isolate whose
      // in-memory cache has not yet been invalidated.
      const freshItems = await pollListForItem(request, createdId)
      expect(freshItems.map((i: any) => i.id)).toContain(createdId)
    })

    test('updating item via public API invalidates list cache', async ({ request }) => {
      const loginRes = await request.post(`${API}/auth/sign-in/email`, {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(loginRes.ok()).toBeTruthy()

      // Create the item this test will edit, so it never depends on seeded content.
      const stamp = Date.now()
      const createRes = await request.post(`${API}/api/${COLLECTION}`, {
        data: { title: `Cache update target ${stamp}`, slug: `cache-update-${stamp}`, data: {} },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(createRes.ok()).toBeTruthy()
      const created = (await createRes.json())?.data
      expect(created?.id).toBeTruthy()

      // Prime the list cache — poll until the created item appears (cross-isolate delay).
      const primedItems = await pollListForItem(request, created.id)
      expect(primedItems.map((item: any) => item.id)).toContain(created.id)

      const newTitle = `Cache update target ${stamp} (updated)`
      const updateRes = await request.put(`${API}/api/${COLLECTION}/${created.id}`, {
        data: { title: newTitle },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(updateRes.ok()).toBeTruthy()

      // Poll until the updated title propagates across isolates.
      let updatedItem: any
      for (let i = 0; i < 5; i++) {
        const res = await request.get(`${API}/api/${COLLECTION}`)
        expect(res.status()).toBe(200)
        updatedItem = ((await res.json())?.data ?? []).find((it: any) => it.id === created.id)
        if (updatedItem?.title === newTitle) break
        if (i < 4) await new Promise((r) => setTimeout(r, 1000))
      }
      expect(updatedItem).toBeDefined()
      expect(updatedItem?.title).toBe(newTitle)
    })

    test('admin clear cache endpoint restores fresh list', async ({ page }) => {
      await loginAsAdmin(page)

      // Prime the list cache
      await page.request.get(`${API}/api/${COLLECTION}`)

      // Clear all caches via admin endpoint
      const clearRes = await page.request.post(`${API}/admin/cache/clear`)
      expect(clearRes.status()).toBe(200)
      const clearData = await clearRes.json()
      expect(clearData.success).toBe(true)

      // List should still be fetchable after clear
      const listRes = await page.request.get(`${API}/api/${COLLECTION}`)
      expect(listRes.status()).toBe(200)
    })
  })
})
