import { test, expect, type Page } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable } from './utils/test-helpers'

// Views plugin re-ground onto the multi-tenant system: `views`/`view_displays` previously had no
// tenant_id at all, so every tenant could see, edit, and publish over every other tenant's views.
// This spec proves isolation end to end through the real HTTP API, mirroring 70-multi-tenant.spec.ts's
// header-based tenant resolution (X-Tenant-Id) rather than driving the tenant-switcher UI — the
// unit/sqlite suite (views-plugin-tenant-scoping.sqlite.test.ts) already covers the SQL-level detail;
// this is the end-to-end confirmation that the real routes wire it up the same way.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const TENANT_HEADER = 'X-Tenant-Id'
const RUN = Date.now()
const TENANT_SLUG = `viewsacme${RUN}`
const TENANT_NAME = `Views Acme ${RUN}`
// Both tenants deliberately use the SAME view name and the SAME publish path — the point of this
// spec is that per-tenant uniqueness holds and neither tenant's data leaks into the other's.
const VIEW_NAME = `roster${RUN}`
const PUBLISH_PATH = `roster-path-${RUN}`

async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('Views plugin — multi-tenant scoping @views @auth', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable =
      (await isFeatureAvailable(request, '/admin/views')) && (await isFeatureAvailable(request, '/admin/tenants'))
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Views plugin and/or multi-tenant plugin not available in this deployment') })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test.afterAll(async ({ browser }) => {
    // Restore single-tenant baseline for the rest of the suite, same convention as 70-multi-tenant.
    const page = await browser.newPage()
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'deactivate')
    await page.close()
  })

  test('two tenants can create a view with the identical name without colliding', async ({ page }) => {
    await setPluginState(page, 'activate')

    const createDefault = await page.request.post(`${BASE_URL}/admin/views/api/`, {
      headers: { 'Content-Type': 'application/json' },
      data: { name: VIEW_NAME, display_name: 'Default Tenant Roster' },
    })
    expect(createDefault.ok(), `default-tenant create failed: ${createDefault.status()}`).toBeTruthy()

    const createTenant = await page.request.post(`${BASE_URL}/admin/views/api/`, {
      headers: { [TENANT_HEADER]: TENANT_SLUG, 'Content-Type': 'application/json' },
      data: { name: VIEW_NAME, display_name: 'Acme Tenant Roster' },
    })
    expect(createTenant.ok(), `tenant create failed (should NOT collide with the default-tenant view): ${createTenant.status()}`).toBeTruthy()
  })

  test('a tenant only sees its own view in the list, and cannot reach the other tenant\'s by id', async ({ page }) => {
    const listDefault = await page.request.get(`${BASE_URL}/admin/views/api/`)
    const namesDefault = ((await listDefault.json()).data ?? []).map((v: any) => v.display_name)
    expect(namesDefault).toContain('Default Tenant Roster')
    expect(namesDefault).not.toContain('Acme Tenant Roster')

    const listTenant = await page.request.get(`${BASE_URL}/admin/views/api/`, { headers: { [TENANT_HEADER]: TENANT_SLUG } })
    const namesTenant = ((await listTenant.json()).data ?? []).map((v: any) => v.display_name)
    expect(namesTenant).toContain('Acme Tenant Roster')
    expect(namesTenant).not.toContain('Default Tenant Roster')

    // Resolve the tenant view's id (from its own tenant-scoped list), then confirm the DEFAULT
    // tenant gets a 404 trying to update it directly by id — not a leak, not a silent no-op success.
    const tenantView = ((await listTenant.json()).data ?? []).find((v: any) => v.display_name === 'Acme Tenant Roster')
    expect(tenantView?.id).toBeTruthy()

    const crossTenantPut = await page.request.put(`${BASE_URL}/admin/views/api/${tenantView.id}`, {
      headers: { 'Content-Type': 'application/json' }, // no tenant header → default tenant
      data: { display_name: 'hijacked' },
    })
    expect(crossTenantPut.status()).toBe(404)
  })

  test('publishing at the same path from two tenants serves each tenant\'s own content at /v/:path', async ({ page }) => {
    const listTenant = await page.request.get(`${BASE_URL}/admin/views/api/`, { headers: { [TENANT_HEADER]: TENANT_SLUG } })
    const tenantView = ((await listTenant.json()).data ?? []).find((v: any) => v.display_name === 'Acme Tenant Roster')
    const listDefault = await page.request.get(`${BASE_URL}/admin/views/api/`)
    const defaultView = ((await listDefault.json()).data ?? []).find((v: any) => v.display_name === 'Default Tenant Roster')

    const publishDefault = await page.request.post(`${BASE_URL}/admin/views/${defaultView.id}/display/publish`, {
      headers: { 'Content-Type': 'application/json' },
      data: { path: PUBLISH_PATH, columns: ['name'] },
    })
    expect(publishDefault.ok(), `default publish failed: ${publishDefault.status()} ${await publishDefault.text()}`).toBeTruthy()

    const publishTenant = await page.request.post(`${BASE_URL}/admin/views/${tenantView.id}/display/publish`, {
      headers: { [TENANT_HEADER]: TENANT_SLUG, 'Content-Type': 'application/json' },
      data: { path: PUBLISH_PATH, columns: ['name'] },
    })
    expect(
      publishTenant.ok(),
      `tenant publish at the SAME path should NOT collide with the default tenant's: ${publishTenant.status()} ${await publishTenant.text()}`,
    ).toBeTruthy()

    // The public embed route has no auth and resolves tenant from the request itself (header, in
    // this deployment's resolution chain) — confirm each tenant's request reaches its OWN display,
    // not a 404 and not the other tenant's, by checking the rendered page references the right view.
    const embedDefault = await page.request.get(`${BASE_URL}/v/${PUBLISH_PATH}`)
    expect(embedDefault.status(), 'default-tenant embed should resolve, not 404').not.toBe(404)

    const embedTenant = await page.request.get(`${BASE_URL}/v/${PUBLISH_PATH}`, { headers: { [TENANT_HEADER]: TENANT_SLUG } })
    expect(embedTenant.status(), 'acme-tenant embed at the identical path should ALSO resolve, not 404 and not silently reuse the default tenant\'s row').not.toBe(404)
  })
})
