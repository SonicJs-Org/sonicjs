import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

// Member management UI (G4): add a user to a tenant by email with a role, change their role, remove
// them — all from /admin/tenants/<slug>/members. Lockout guards (last admin) covered by unit tests.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const RUN = Date.now()
const TENANT_SLUG = `members${RUN}`
const TENANT_NAME = `Members Co ${RUN}`
const MEMBER_EMAIL = `member${RUN}@example.com`

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../my-sonicjs-app')

function d1Exec(sql: string) {
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'DB', '--local', '--command', sql], {
    cwd: APP_DIR,
    stdio: 'pipe',
  })
}

async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('Tenant member management @auth', () => {
  test.beforeAll(() => {
    // A target user to add as a member (no login needed for them in this test).
    d1Exec(
      `INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at)
       VALUES ('u-${RUN}', '${MEMBER_EMAIL}', 'Mem', 'Ber', 1, 1)`
    )
  })

  test.afterAll(() => {
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
    await Promise.all([page.waitForURL(/\/admin\/tenants/), page.click('[data-save-tenant]')])

    // Members page: the creator is listed as admin.
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT_SLUG}/members`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-member-row="admin@sonicjs.com"]')).toBeVisible()

    // Add the seeded user as a viewer.
    await page.fill('#member-email', MEMBER_EMAIL)
    await page.selectOption('#member-role', 'viewer')
    await Promise.all([page.waitForURL(/\/members/), page.click('[data-add-member]')])
    const row = page.locator(`[data-member-row="${MEMBER_EMAIL}"]`)
    await expect(row).toBeVisible()
    await expect(row.locator('[data-member-role]')).toHaveValue('viewer')

    // Change their role to editor (select auto-submits).
    await Promise.all([
      page.waitForURL(/\/members/),
      row.locator('[data-member-role]').selectOption('editor'),
    ])
    await expect(
      page.locator(`[data-member-row="${MEMBER_EMAIL}"] [data-member-role]`)
    ).toHaveValue('editor')

    // Remove them.
    page.on('dialog', (d) => d.accept())
    await Promise.all([
      page.waitForURL(/\/members/),
      page.locator(`[data-remove-member="${MEMBER_EMAIL}"]`).click(),
    ])
    await expect(page.locator(`[data-member-row="${MEMBER_EMAIL}"]`)).toHaveCount(0)
  })

  test('adding a non-existent email shows an error', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/${TENANT_SLUG}/members`)
    await page.waitForLoadState('networkidle')
    await page.fill('#member-email', `ghost${RUN}@example.com`)
    await Promise.all([page.waitForURL(/\/members/), page.click('[data-add-member]')])
    await expect(page.locator('[data-members-alert]')).toContainText(/No user found/i)
  })

  test('teardown: deactivate plugin to restore single-tenant baseline', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
