import { test, expect, type Page } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable, IS_REMOTE_DEPLOYMENT, d1Exec, flashedTo } from './utils/test-helpers'

// User-centric tenant membership management: from a user's edit page, open their memberships,
// add the user to a tenant with a role, change the role, and remove them. Roles are per-tenant.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const RUN = Date.now()
const T_A = `umta${RUN}`
const T_B = `umtb${RUN}`
const UID = `umbr${RUN}`
const UEMAIL = `member${RUN}@example.com`

async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('User-centric tenant memberships @auth @lock-plugin-multi-tenant', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeAll(() => {
    if (!featureAvailable) return
    d1Exec(`INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at) VALUES ('${UID}', '${UEMAIL}', 'Mem', 'Ber', 1, 1)`)
    for (const t of [T_A, T_B]) {
      d1Exec(`INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at) VALUES ('${t}', '${t}', '${t}', 'active', '', '{}', 1, 1)`)
    }
  })

  test.afterAll(() => {
    if (!featureAvailable) return
    d1Exec(`DELETE FROM auth_tenant_member WHERE user_id = '${UID}'`)
    d1Exec(`DELETE FROM auth_tenant WHERE slug IN ('${T_A}','${T_B}')`)
    d1Exec(`DELETE FROM auth_user WHERE id = '${UID}'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('user edit page links to membership management when the plugin is active', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/users/${UID}/edit`)
    await page.waitForLoadState('domcontentloaded')
    // The standalone "manage memberships" link was replaced by an inline memberships matrix
    // (commit 39a9f61eb); the section only renders while the multi-tenant plugin is active.
    const section = page.locator('[data-tenant-memberships]')
    await expect(section).toBeVisible()
    await expect(section.getByRole('heading', { name: 'Tenant memberships' })).toBeVisible()
    // Management affordance: the add-to-tenant form targeting this user's memberships endpoint.
    await expect(section.locator(`form[action="/admin/tenants/users/${UID}/memberships"]`)).toBeVisible()
  })

  test('add user to a tenant, change role, remove', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/users/${UID}`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#membership-tenant')).toBeVisible()

    // Add to tenant A as viewer.
    await page.selectOption('#membership-tenant', T_A)
    await page.selectOption('#membership-role', 'viewer')
    await Promise.all([
      page.waitForURL(flashedTo(`/admin/tenants/users/${UID}`, `Added to ${T_A}`)),
      page.click('[data-add-membership]'),
    ])
    const row = page.locator(`[data-membership-row="${T_A}"]`)
    await expect(row).toBeVisible()
    await expect(row.locator('[data-membership-role]')).toHaveValue('viewer')

    // Change role to editor (select auto-submits).
    await Promise.all([
      page.waitForURL(flashedTo(`/admin/tenants/users/${UID}`, 'Role updated')),
      row.locator('[data-membership-role]').selectOption('editor'),
    ])
    await expect(page.locator(`[data-membership-row="${T_A}"] [data-membership-role]`)).toHaveValue('editor')

    // Remove.
    page.on('dialog', (d) => d.accept())
    await Promise.all([
      page.waitForURL(flashedTo(`/admin/tenants/users/${UID}`, `Removed from ${T_A}`)),
      page.locator(`[data-remove-membership="${T_A}"]`).click(),
    ])
    await expect(page.locator(`[data-membership-row="${T_A}"]`)).toHaveCount(0)
  })

  test('the per-tenant role-usage page renders and lists assignments', async ({ page }) => {
    // Seed an assignment so the usage page has a row to show.
    d1Exec(`INSERT INTO auth_tenant_member (id, tenant_id, user_id, role, created_at, updated_at) SELECT 'ru-${RUN}', '${T_B}', id, 'viewer', 1, 1 FROM auth_user WHERE id = '${UID}'`)
    await page.goto(`${BASE_URL}/admin/tenants/roles/viewer`)
    await page.waitForLoadState('networkidle')
    await expect(page.getByText(/Role usage/i)).toBeVisible()
    await expect(page.locator(`[data-role-assignment="${UEMAIL}@${T_B}"]`)).toBeVisible()
  })

  test('teardown: deactivate plugin', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
