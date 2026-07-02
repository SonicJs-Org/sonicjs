import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { loginAsAdmin, ensureAdminUserExists, ADMIN_CREDENTIALS } from './utils/test-helpers'

// Membership gate: an authed admin may only switch into / resolve tenants they belong to. Creating a
// tenant auto-enrolls the creator (owner), so the happy path works; a tenant the admin is NOT a
// member of is rejected by the switcher (403) and never resolves from a forged header.
// Single shared e2e DB (workers:1) → serial; leaves the plugin DEACTIVATED at the end.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const TENANT_HEADER = 'X-Tenant-Id'
const RUN = Date.now()
const ORPHAN_SLUG = `orphan${RUN}`        // seeded directly; admin is NOT a member
const MEMBER_SLUG = `member${RUN}`         // created via UI; admin auto-enrolled
const MEMBER_NAME = `Member Co ${RUN}`

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../my-sonicjs-app')

function d1Exec(sql: string) {
  // Seed/clean rows in the dev server's *local* D1 (same .wrangler state the worker uses).
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'DB', '--local', '--command', sql], {
    cwd: APP_DIR,
    stdio: 'pipe',
  })
}

async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('Multi-Tenant membership gate @auth', () => {
  test.beforeAll(() => {
    // An active tenant with NO membership rows — the admin is not a member.
    d1Exec(
      `INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at)
       VALUES ('${ORPHAN_SLUG}', 'Orphan', '${ORPHAN_SLUG}', 'active', '', '{}', 1, 1)`
    )
  })

  test.afterAll(() => {
    d1Exec(`DELETE FROM auth_tenant WHERE slug = '${ORPHAN_SLUG}'`)
    // Safety net: never leave the shared admin flagged super-admin for later specs.
    d1Exec(`UPDATE auth_user SET is_super_admin = 0 WHERE email = 'admin@sonicjs.com'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('switcher rejects a tenant the admin is not a member of (403)', async ({ page }) => {
    const res = await page.request.post(`${BASE_URL}/admin/tenants/switch`, {
      form: { tenant: ORPHAN_SLUG, redirect: '/admin' },
      maxRedirects: 0,
    })
    expect(res.status()).toBe(403)
    expect((await res.json()).error).toMatch(/not a member/i)
  })

  test('a forged header for a non-member tenant does not resolve (no cross-tenant leak)', async ({ page }) => {
    // Write a doc with the orphan tenant header. The gate forces resolution back to 'default',
    // so the document is stamped 'default', never the orphan tenant.
    const createRes = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { [TENANT_HEADER]: ORPHAN_SLUG, 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title: `Forged ${RUN}`, data: { author: 'x' } },
    })
    expect(createRes.ok()).toBeTruthy()
    expect((await createRes.json()).data.tenantId).toBe('default')
  })

  test('creating a tenant auto-enrolls the creator → switch succeeds', async ({ page }) => {
    // Create via the admin UI (auto-enrolls the admin as owner).
    await page.goto(`${BASE_URL}/admin/tenants/new`)
    await page.waitForLoadState('networkidle')
    await page.fill('#tenant-name', MEMBER_NAME)
    await page.fill('#tenant-slug', MEMBER_SLUG)
    await Promise.all([
      page.waitForURL(/\/admin\/tenants/),
      page.click('[data-save-tenant]'),
    ])

    // Switch into it — allowed because the creator was enrolled.
    const res = await page.request.post(`${BASE_URL}/admin/tenants/switch`, {
      form: { tenant: MEMBER_SLUG, redirect: '/admin' },
      maxRedirects: 0,
    })
    expect([301, 302, 303]).toContain(res.status())
  })

  test('the sidebar switcher only lists member tenants (orphan hidden)', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/content`)
    await page.waitForLoadState('networkidle')
    const switcher = page.locator('[data-tenant-switcher]').first()
    await expect(switcher).toBeVisible()
    // Member tenant present, orphan absent, default always present.
    await expect(switcher.locator(`option[value="${MEMBER_SLUG}"]`)).toHaveCount(1)
    await expect(switcher.locator(`option[value="${ORPHAN_SLUG}"]`)).toHaveCount(0)
    await expect(switcher.locator('option[value="default"]')).toHaveCount(1)
  })

  test('super-admin bypasses the gate: switches into a non-member tenant', async ({ page }) => {
    // Promote the admin to platform super-admin, then start a FRESH session so session.user carries
    // the new flag (re-signing over an existing session needs an explicit Origin for BA's CSRF check).
    d1Exec(`UPDATE auth_user SET is_super_admin = 1 WHERE email = 'admin@sonicjs.com'`)
    try {
      await page.context().clearCookies()
      const signin = await page.request.post(`${BASE_URL}/auth/sign-in/email`, {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
        headers: { 'Content-Type': 'application/json', Origin: BASE_URL },
      })
      expect(signin.ok()).toBeTruthy()

      const res = await page.request.post(`${BASE_URL}/admin/tenants/switch`, {
        form: { tenant: ORPHAN_SLUG, redirect: '/admin' },
        maxRedirects: 0,
      })
      // Allowed despite no membership row (super-admin bypass).
      expect([301, 302, 303]).toContain(res.status())
    } finally {
      d1Exec(`UPDATE auth_user SET is_super_admin = 0 WHERE email = 'admin@sonicjs.com'`)
    }
  })

  test('teardown: deactivate plugin to restore single-tenant baseline', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
