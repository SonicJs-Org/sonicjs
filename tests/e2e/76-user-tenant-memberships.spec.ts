import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

// User-centric tenant membership management: from a user's edit page, open their memberships,
// add the user to a tenant with a role, change the role, and remove them. Roles are per-tenant.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const RUN = Date.now()
const T_A = `umta${RUN}`
const T_B = `umtb${RUN}`
const UID = `umbr${RUN}`
const UEMAIL = `member${RUN}@example.com`

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../my-sonicjs-app')
function d1Exec(sql: string) {
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'DB', '--local', '--command', sql], { cwd: APP_DIR, stdio: 'pipe' })
}
async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('User-centric tenant memberships @auth', () => {
  test.beforeAll(() => {
    d1Exec(`INSERT INTO auth_user (id, email, first_name, last_name, created_at, updated_at) VALUES ('${UID}', '${UEMAIL}', 'Mem', 'Ber', 1, 1)`)
    for (const t of [T_A, T_B]) {
      d1Exec(`INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at) VALUES ('${t}', '${t}', '${t}', 'active', '', '{}', 1, 1)`)
    }
  })

  test.afterAll(() => {
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
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-tenant-memberships-link]')).toBeVisible()
  })

  test('add user to a tenant, change role, remove', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/tenants/users/${UID}`)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#membership-tenant')).toBeVisible()

    // Add to tenant A as viewer.
    await page.selectOption('#membership-tenant', T_A)
    await page.selectOption('#membership-role', 'viewer')
    await Promise.all([page.waitForURL(/\/tenants\/users\//), page.click('[data-add-membership]')])
    const row = page.locator(`[data-membership-row="${T_A}"]`)
    await expect(row).toBeVisible()
    await expect(row.locator('[data-membership-role]')).toHaveValue('viewer')

    // Change role to editor (select auto-submits).
    await Promise.all([
      page.waitForURL(/\/tenants\/users\//),
      row.locator('[data-membership-role]').selectOption('editor'),
    ])
    await expect(page.locator(`[data-membership-row="${T_A}"] [data-membership-role]`)).toHaveValue('editor')

    // Remove.
    page.on('dialog', (d) => d.accept())
    await Promise.all([
      page.waitForURL(/\/tenants\/users\//),
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
