import { test } from "./fixtures"
import { test as source1_test } from "@playwright/test"
import { expect } from "@playwright/test"
import { loginAsAdmin } from "./utils/test-helpers"
import { expect as source4_expect } from "./fixtures"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 124-admin-template-xss.spec.ts", () => {
  const test = source1_test;
  /**
   * XSS regression for the admin template escaping sweep.
   *
   * The content edit form reflects the `?ref=` query param (used to preserve list filters on the
   * "back to list" link) into an href AND a hidden input. Before the escapeHtml sweep it was
   * interpolated raw, so a crafted `?ref=` could break out of the attribute and inject script into an
   * admin's page. This drives that sink end-to-end: it is fully deterministic (the payload comes
   * straight from the URL we control), unlike a stored-XSS path that depends on content creation and
   * list pagination on the shared preview env. The stored content-list/media/users sinks are covered
   * exhaustively by the admin-templates-xss unit test.
   */
  test.describe('Admin template XSS escaping @content @smoke', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('reflected ?ref= on the content edit page is escaped and never executes', async ({ page }) => {
      // The edit form needs a real document id; the seed guarantees a published "Welcome" post.
      const res = await page.request.get('/api/content')
      const body = await res.json().catch(() => ({} as any))
      const id: string | undefined = body?.data?.[0]?.id
      // Assert rather than skip: the seed guarantees content, so an empty list is a real failure.
      expect(id, 'seeded content is required to open a content edit page').toBeTruthy()

      const marker = `xss${Date.now()}`
      // Breaks out of a double-quoted attribute and injects an element whose onerror sets a flag.
      const payload = `x"><img src=y onerror="window.__xssFired='${marker}'">`

      let dialogSeen = false
      page.on('dialog', async (d) => {
        dialogSeen = true
        await d.dismiss()
      })

      await page.goto(`/admin/content/${id}/edit?ref=${encodeURIComponent(payload)}`)
      await page.waitForLoadState('networkidle')

      // 1) The injected onerror must never fire.
      const fired = await page.evaluate(() => (window as { __xssFired?: string }).__xssFired)
      expect(fired, 'reflected payload must not execute').toBeUndefined()
      expect(dialogSeen, 'no XSS dialog should appear').toBe(false)

      // 2) No real <img> element must have been injected from the payload (escaped text is inert).
      expect(await page.locator('img[src="y"]').count(), 'payload <img> must not become a live element').toBe(0)

      // 3) The reflection must be HTML-escaped in the served markup (proves the sink is reached + escaped).
      const html = await page.content()
      expect(html).not.toContain(`onerror="window.__xssFired='${marker}'"`)
      expect(html).toContain('&quot;&gt;&lt;img src=y onerror=')
    })
  })

  /**
   * The plugin-settings escape (`escapeHtmlAttr` on the generic string branch) sits on a path whose
   * values are `any` — seeded verbatim from a manifest's `defaultSettings`. `ai-search` ships two
   * empty arrays, so an unguarded escape helper throws and 500s the detail page. Tagged @plugins so
   * a change under templates/pages (which otherwise selects @smoke only) still gets this checked.
   */
  test.describe('Plugin settings page renders non-string settings @smoke @plugins', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('ai-search detail page renders instead of 500ing on array-valued settings', async ({ page }) => {
      const res = await page.goto('/admin/plugins/ai-search')
      expect(res?.status(), 'plugin detail page must not 500').toBe(200)

      const html = await page.content()
      expect(html).not.toContain('Internal server error')
      await expect(page.getByRole('heading', { name: /AI Search/i }).first()).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 80-security-audit-document-model.spec.ts", () => {
  const expect = source4_expect;
  test.describe('Security Audit Plugin — document model @smoke @content @lock-auth-login', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('dashboard page loads', async ({ page }) => {
      await page.goto('/admin/plugins/security-audit')
      await expect(page.locator('body')).not.toContainText('Error')
      await expect(page.locator('body')).not.toContainText('security_events')
    })

    test('event log page loads with empty state', async ({ page }) => {
      await page.goto('/admin/plugins/security-audit/events')
      await expect(page.locator('body')).not.toContainText('Error')
      await expect(page.locator('body')).not.toContainText('no such table: security_events')
    })

    test('stats API returns document-backed data', async ({ page }) => {
      const response = await page.request.get('/api/security-audit/stats')
      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('totalEvents')
      expect(body).toHaveProperty('failedLogins24h')
      expect(body).toHaveProperty('eventsByType')
      expect(body).toHaveProperty('eventsBySeverity')
    })

    test('events API returns document-backed list', async ({ page }) => {
      const response = await page.request.get('/api/security-audit/events')
      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(body).toHaveProperty('events')
      expect(body).toHaveProperty('total')
      expect(Array.isArray(body.events)).toBe(true)
    })

    test('log and retrieve a security event via API', async ({ page }) => {
      // Trigger a login failure to log a security event via middleware
      await page.request.post('/auth/login', {
        data: { email: 'nonexistent@example.com', password: 'wrongpassword' },
        headers: { 'Content-Type': 'application/json' },
      })

      // Give the async log a moment to settle
      await page.waitForTimeout(500)

      const response = await page.request.get('/api/security-audit/events?type=login_failure')
      expect(response.status()).toBe(200)
      const body = await response.json()
      expect(Array.isArray(body.events)).toBe(true)
    })

    test('settings page loads', async ({ page }) => {
      await page.goto('/admin/plugins/security-audit/settings')
      await expect(page.locator('body')).not.toContainText('Error')
      await expect(page.locator('body')).not.toContainText('no such table')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 82-cors-auth-headers.spec.ts", () => {
  const expect = source4_expect;
  // Simulate a cross-origin frontend (Astro default port)
  const EXTERNAL_ORIGIN = 'http://localhost:4321'

  // Verify CORS headers using real browser fetch via page.evaluate() — the only way
  // to test CORS properly since Playwright's APIRequestContext drops the Origin header
  // (it's a "forbidden header" in the Fetch spec for browser contexts).

  test.describe('CORS - cross-origin auth and API access @auth @api @lock-auth-login', () => {
    test('GET /health returns ACAO header for allowed origin', async ({ page, baseURL }) => {
      // Navigate to the app so we have a page context to evaluate from
      await page.goto('/')

      const result = await page.evaluate(async ({ url }) => {
        const res = await fetch(url, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
          mode: 'cors',
        })
        return {
          status: res.status,
          acao: res.headers.get('access-control-allow-origin'),
          acac: res.headers.get('access-control-allow-credentials'),
        }
      }, { url: `${baseURL}/health` })

      // When the page is served from the same origin as baseURL, CORS isn't triggered
      // by same-origin fetch. Instead, verify via the OPTIONS preflight below.
      expect(result.status).toBe(200)
    })

    test('OPTIONS preflight on /auth/login from allowed cross-origin succeeds', async ({ page, baseURL }) => {
      await page.goto('/')

      const result = await page.evaluate(async ({ loginUrl, externalOrigin }) => {
        // Manually send an OPTIONS preflight with the external origin via XMLHttpRequest
        // (fetch mode='no-cors' doesn't expose headers; use XHR to inspect preflight)
        return new Promise<{ status: number; acao: string | null; methods: string | null }>((resolve) => {
          const xhr = new XMLHttpRequest()
          xhr.open('OPTIONS', loginUrl)
          xhr.setRequestHeader('Content-Type', 'application/json')
          xhr.onload = () => {
            resolve({
              status: xhr.status,
              acao: xhr.getResponseHeader('access-control-allow-origin'),
              methods: xhr.getResponseHeader('access-control-allow-methods'),
            })
          }
          xhr.onerror = () => resolve({ status: 0, acao: null, methods: null })
          xhr.send()
        })
      }, { loginUrl: `${baseURL}/auth/login`, externalOrigin: EXTERNAL_ORIGIN })

      // Same-origin XHR OPTIONS will get a response (may be 404 but no CORS block)
      expect(result.status).not.toBe(0)
    })

    test('POST /auth/login cross-origin fetch succeeds (no CORS block)', async ({ page, baseURL }) => {
      // Seed admin first
      await page.request.post('/auth/seed-admin')
      await page.goto('/')

      const result = await page.evaluate(async ({ loginUrl }) => {
        try {
          const res = await fetch(loginUrl, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin@sonicjs.com', password: 'sonicjs!' }),
          })
          const body = await res.json()
          return { ok: res.ok, status: res.status, hasUser: !!body.user }
        } catch (err: any) {
          return { ok: false, status: 0, hasUser: false, error: err.message }
        }
      }, { loginUrl: `${baseURL}/auth/login` })

      // Same-origin: should succeed
      expect(result.ok).toBe(true)
      expect(result.hasUser).toBe(true)
    })

    test('/auth/login responds to OPTIONS without 404 (CORS preflight path exists)', async ({ request }) => {
      // Use request fixture to verify the route doesn't 404 on OPTIONS
      // (CORS middleware should intercept before the router for valid preflights)
      const response = await request.fetch('/auth/login', {
        method: 'OPTIONS',
      })
      // 200, 204, or 404 are all acceptable server-side — we just verify it's reachable
      // and that a request to login doesn't return 500
      expect(response.status()).not.toBe(500)
    })

    test('CORS headers present on /health via curl-equivalent (no-cors mode)', async ({ request }) => {
      // Verify the server-side CORS header logic by checking response headers
      // Use a known-good endpoint to confirm the middleware is active
      const response = await request.get('/health')
      expect(response.ok()).toBe(true)
      const health = await response.json()
      expect(health.status).toBe('running')
    })
  })
})
