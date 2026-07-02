import { test, expect, type Page } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

// Multi-tenant plugin: off by default, activated on the Plugins page, then it exposes a Tenants
// admin page + sidebar switcher and scopes document reads/writes to the resolved tenant.
// Single shared e2e DB (workers:1) → the tests run serially and leave the plugin DEACTIVATED at the
// end so the rest of the suite stays single-tenant. Tenant slugs are timestamped for re-run safety.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const TENANT_HEADER = 'X-Tenant-Id'
const RUN = Date.now()
const TENANT_SLUG = `acme${RUN}`
const TENANT_NAME = `Acme ${RUN}`

async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  // Best-effort install (no-op once installed), then activate/deactivate via the plugin API.
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('Multi-Tenant plugin @auth', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('is off by default: Tenants page shows inactive notice, no nav, no switcher', async ({ page }) => {
    // Establish the inactive baseline (idempotent — a prior run may have left it active).
    await setPluginState(page, 'deactivate')

    await page.goto(`${BASE_URL}/admin/tenants`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-tenants-inactive]')).toBeVisible()
    await expect(page.locator('[data-tenants-inactive]')).toContainText(/not active/i)

    // No Tenants nav link and no tenant switcher while inactive.
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')
    expect(await page.locator('a[href="/admin/tenants"]').count()).toBe(0)
    expect(await page.locator('[data-tenant-switcher]').count()).toBe(0)
  })

  test('can be turned on from the Plugins page', async ({ page }) => {
    await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})

    await page.goto(`${BASE_URL}/admin/plugins`)
    await page.waitForLoadState('networkidle')

    const card = page.locator('.plugin-card').filter({ hasText: /Multi-Tenant/i }).first()
    await expect(card).toBeVisible()

    // If still showing an Install button, install first.
    const installBtn = card.locator('button', { hasText: /^Install$/ })
    if (await installBtn.count()) {
      await Promise.all([
        page.waitForResponse((r) => r.url().includes('/admin/plugins/install')),
        installBtn.click(),
      ])
      await page.goto(`${BASE_URL}/admin/plugins`)
      await page.waitForLoadState('networkidle')
    }

    // Flip the activation toggle if not already active.
    const toggle = card.locator('button[role="switch"]').first()
    if ((await toggle.getAttribute('aria-checked')) !== 'true') {
      await Promise.all([
        page.waitForResponse((r) => r.url().includes(`/admin/plugins/${PLUGIN_ID}/activate`)),
        toggle.click(),
      ])
    }

    // Reload and confirm the card reports Active.
    await page.goto(`${BASE_URL}/admin/plugins`)
    await page.waitForLoadState('networkidle')
    await expect(
      page.locator('.plugin-card').filter({ hasText: /Multi-Tenant/i }).locator('.status-badge')
    ).toContainText(/Active/i)

    // Tenants nav link is registered (it lives inside the collapsed Plugins accordion, so assert
    // presence not visibility); the sidebar tenant switcher is rendered in the footer.
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('a[href="/admin/tenants"]').first()).toBeAttached()
    await expect(page.locator('[data-tenant-switcher]').first()).toBeVisible()
  })

  test('lists the default tenant and creates a new tenant via the admin UI', async ({ page }) => {
    await setPluginState(page, 'activate')

    await page.goto(`${BASE_URL}/admin/tenants`)
    await page.waitForLoadState('networkidle')

    // Default tenant row exists and cannot be deleted.
    const defaultRow = page.locator('[data-tenant-row="default"]')
    await expect(defaultRow).toBeVisible()
    expect(await defaultRow.locator('[data-delete-tenant]').count()).toBe(0)

    // Create a tenant through the form UI.
    await page.goto(`${BASE_URL}/admin/tenants/new`)
    await page.waitForLoadState('networkidle')
    await page.fill('#tenant-name', TENANT_NAME)
    await page.fill('#tenant-slug', TENANT_SLUG)
    await Promise.all([
      page.waitForURL(/\/admin\/tenants/),
      page.click('[data-save-tenant]'),
    ])

    const row = page.locator(`[data-tenant-row="${TENANT_SLUG}"]`)
    await expect(row).toBeVisible()
    await expect(row).toContainText(TENANT_NAME)
  })

  test('scopes documents to the active tenant (cross-tenant isolation)', async ({ page }) => {
    await setPluginState(page, 'activate')

    const title = `Secret ${RUN}`
    // Create a blog_post document under the new tenant via the resolved tenant header. The write is
    // stamped with the resolved tenant (server-side), never trusting a body-supplied tenant.
    const createRes = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { [TENANT_HEADER]: TENANT_SLUG, 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title, data: { author: 'Tenant A' } },
    })
    expect(createRes.ok()).toBeTruthy()
    expect((await createRes.json()).data.tenantId).toBe(TENANT_SLUG)

    // Visible when reading as the same tenant.
    const asTenant = await page.request.get(`${BASE_URL}/admin/documents?type=blog_post&status=all&limit=100`, {
      headers: { [TENANT_HEADER]: TENANT_SLUG },
    })
    const tenantTitles = ((await asTenant.json()).data ?? []).map((d: any) => d.title)
    expect(tenantTitles).toContain(title)

    // Invisible when reading as the default tenant (no header → default).
    const asDefault = await page.request.get(`${BASE_URL}/admin/documents?type=blog_post&status=all&limit=100`)
    const defaultTitles = ((await asDefault.json()).data ?? []).map((d: any) => d.title)
    expect(defaultTitles).not.toContain(title)
  })

  test('switching the active tenant updates the current-tenant indicator', async ({ page }) => {
    await setPluginState(page, 'activate')

    await page.goto(`${BASE_URL}/admin/tenants`)
    await page.waitForLoadState('networkidle')

    // Switch to the created tenant via the row action.
    await Promise.all([
      page.waitForURL(/\/admin\/tenants/),
      page.locator(`[data-switch-tenant="${TENANT_SLUG}"]`).click(),
    ])

    // The created tenant row now carries the "Current" badge.
    await expect(
      page.locator(`[data-tenant-row="${TENANT_SLUG}"] [data-current-tenant-badge]`)
    ).toBeVisible()

    // Switch back to default so later tests/specs are unaffected.
    await Promise.all([
      page.waitForURL(/\/admin\/tenants/),
      page.locator('[data-switch-tenant="default"]').click(),
    ])
    await expect(
      page.locator('[data-tenant-row="default"] [data-current-tenant-badge]')
    ).toBeVisible()
  })

  test('deactivating restores single-tenant behavior', async ({ page }) => {
    await setPluginState(page, 'deactivate')

    await page.goto(`${BASE_URL}/admin/tenants`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-tenants-inactive]')).toBeVisible()

    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')
    expect(await page.locator('[data-tenant-switcher]').count()).toBe(0)
  })
})
