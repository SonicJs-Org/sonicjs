import { test, expect, type Page } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable, IS_REMOTE_DEPLOYMENT, d1Exec, flashedTo } from './utils/test-helpers'

// Member management UI (G4): add a user to a tenant by email with a role, change their role, remove
// them — all from /admin/tenants/<slug>/members. Lockout guards (last admin) covered by unit tests.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const RUN = Date.now()
const TENANT_SLUG = `members${RUN}`
const TENANT_NAME = `Members Co ${RUN}`
const MEMBER_EMAIL = `member${RUN}@example.com`


async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

/**
 * Wait for the members page to come back from a form POST carrying `message=<expected>`.
 *
 * Not `waitForURL(/\/members/)`: every one of these POSTs is submitted *from* the members page,
 * so that pattern already matches the current URL and resolves before the click has even been
 * dispatched — the `Promise.all` collapses to a bare click and the assertions that follow race
 * the redirect. 74's revoke test lost that race and reported the status banner as "element(s)
 * not found". Every members route redirects with a `message` query param (routes/admin.ts), and
 * each step's message is distinct, so matching on it waits for *this* POST rather than the
 * previous one's URL. A predicate rather than a regex because the handlers are inconsistent
 * about percent-encoding the message.
 */
const membersSettled = (expected: string | RegExp) => flashedTo(/\/members$/, expected)

test.describe.serial('Tenant member management @auth @lock-plugin-multi-tenant', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeAll(() => {
    if (!featureAvailable) return
    // A target user to add as a member (no login needed for them in this test).
    d1Exec(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES ('u-${RUN}', '${MEMBER_EMAIL}', 'Mem', 'Ber', 1, 1)`
    )
  })

  test.afterAll(() => {
    if (!featureAvailable) return
    d1Exec(`DELETE FROM auth_user WHERE id = 'u-${RUN}'`)
    d1Exec(`DELETE FROM auth_tenant WHERE slug = '${TENANT_SLUG}'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('full member lifecycle: add by email, change role, remove', async ({ page }) => {
    // Create the tenant (admin auto-enrolls as its admin).
    await page.goto(`${BASE_URL}/admin/tenants/new`)
    await page.waitForLoadState('networkidle')
    await page.fill('#tenant-name', TENANT_NAME)
    await page.fill('#tenant-slug', TENANT_SLUG)
    await Promise.all([
      page.waitForURL(flashedTo('/admin/tenants', 'Tenant created')),
      page.click('[data-save-tenant]'),
    ])

    // Members page: the creator is listed as admin.
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT_SLUG}/members`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-member-row="admin@sonicjs.com"]')).toBeVisible()

    // Add the seeded user as a viewer.
    await page.fill('#member-email', MEMBER_EMAIL)
    await page.selectOption('#member-role', 'viewer')
    await Promise.all([
      page.waitForURL(membersSettled('Member added')),
      page.click('[data-add-member]'),
    ])
    const row = page.locator(`[data-member-row="${MEMBER_EMAIL}"]`)
    await expect(row).toBeVisible()
    await expect(row.locator('[data-member-role]')).toHaveValue('viewer')

    // Change their role to editor (select auto-submits).
    await Promise.all([
      page.waitForURL(membersSettled('Role updated')),
      row.locator('[data-member-role]').selectOption('editor'),
    ])
    await expect(
      page.locator(`[data-member-row="${MEMBER_EMAIL}"] [data-member-role]`)
    ).toHaveValue('editor')

    // Remove them.
    page.on('dialog', (d) => d.accept())
    await Promise.all([
      page.waitForURL(membersSettled('Member removed')),
      page.locator(`[data-remove-member="${MEMBER_EMAIL}"]`).click(),
    ])
    await expect(page.locator(`[data-member-row="${MEMBER_EMAIL}"]`)).toHaveCount(0)
  })

  test('adding a non-existent email shows an error', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT_SLUG}/members`)
    await page.waitForLoadState('networkidle')
    await page.fill('#member-email', `ghost${RUN}@example.com`)
    await Promise.all([
      page.waitForURL(membersSettled(/No user found/i)),
      page.click('[data-add-member]'),
    ])
    await expect(page.locator('[data-members-alert]')).toContainText(/No user found/i)
  })

  test('teardown: deactivate plugin to restore single-tenant baseline', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
