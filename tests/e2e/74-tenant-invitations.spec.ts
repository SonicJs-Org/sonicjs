import { test, expect, type Page } from './fixtures'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable, IS_REMOTE_DEPLOYMENT, d1Exec, flashedTo } from './utils/test-helpers'

// Invitation flow (G3): invite an email to a tenant with a per-tenant role, accept via the link
// (gated on the signed-in user's email matching the invite), and revoke pending invites. The admin
// is invited to a tenant they are NOT yet a member of, then accepts to join.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const RUN = Date.now()
const TENANT = `invtest${RUN}`
const ADMIN_EMAIL = 'admin@sonicjs.com'


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

test.describe.serial('Tenant invitations @auth @lock-plugin-multi-tenant', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeAll(() => {
    if (!featureAvailable) return
    // A tenant the admin is NOT a member of (seeded directly, so no auto-enroll).
    d1Exec(
      `INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at)
       VALUES ('${TENANT}', 'Inv Test', '${TENANT}', 'active', '', '{}', 1, 1)`
    )
  })

  test.afterAll(() => {
    if (!featureAvailable) return
    d1Exec(`DELETE FROM auth_tenant_member WHERE tenant_id = '${TENANT}'`)
    d1Exec(`DELETE FROM auth_tenant_invitation WHERE tenant_id = '${TENANT}'`)
    d1Exec(`DELETE FROM auth_tenant WHERE slug = '${TENANT}'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('invite → accept makes the invitee a member with the invited role', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT}/members`)
    await page.waitForLoadState('networkidle')
    // Assert we are on the members page (form present) BEFORE the absence check — a count-0 assertion
    // passes spuriously on a wrong/loading page.
    await expect(page.locator('#invite-email')).toBeVisible()
    // Admin is not a member yet.
    await expect(page.locator(`[data-member-row="${ADMIN_EMAIL}"]`)).toHaveCount(0)

    // Invite the admin's own email as 'editor'.
    await page.fill('#invite-email', ADMIN_EMAIL)
    await page.selectOption('#invite-role', 'editor')
    await Promise.all([
      page.waitForURL(membersSettled('Invitation created')),
      page.click('[data-send-invite]'),
    ])
    const inviteRow = page.locator(`[data-invite-row="${ADMIN_EMAIL}"]`)
    await expect(inviteRow).toBeVisible()

    // Follow the accept link (signed in as the invited email → accepted).
    await Promise.all([
      page.waitForURL(membersSettled('Invitation accepted')),
      page.locator(`[data-invite-link="${ADMIN_EMAIL}"]`).click(),
    ])

    // Now a member with role editor; the pending invitation is gone.
    const memberRow = page.locator(`[data-member-row="${ADMIN_EMAIL}"]`)
    await expect(memberRow).toBeVisible()
    await expect(memberRow.locator('[data-member-role]')).toHaveValue('editor')
    await expect(page.locator(`[data-invite-row="${ADMIN_EMAIL}"]`)).toHaveCount(0)
  })

  test('a pending invitation can be revoked', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT}/members`)
    await page.waitForLoadState('networkidle')

    const email = `revoke${RUN}@example.com`
    await page.fill('#invite-email', email)
    await Promise.all([
      page.waitForURL(membersSettled('Invitation created')),
      page.click('[data-send-invite]'),
    ])
    // The POST always redirects back with a status banner; wait for it so a rejected invite
    // (e.g. plugin deactivated by a concurrent spec) fails on the banner text, not on a bare
    // missing row.
    await expect(page.locator('[data-members-alert]')).toBeVisible()
    await expect(page.locator(`[data-invite-row="${email}"]`)).toBeVisible()

    await Promise.all([
      page.waitForURL(membersSettled('Invitation revoked')),
      page.locator(`[data-revoke-invite="${email}"]`).click(),
    ])
    await expect(page.locator(`[data-invite-row="${email}"]`)).toHaveCount(0)
  })

  test('teardown: deactivate plugin to restore single-tenant baseline', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
