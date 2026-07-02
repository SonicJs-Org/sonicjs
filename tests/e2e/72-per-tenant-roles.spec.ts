import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

// Per-tenant roles (G1): a user's effective document role is their role IN the active tenant, not
// their global role. The shared admin is GLOBALLY 'admin' but is seeded as a 'viewer' of tenant
// `vt<run>`. In that tenant they may READ documents but NOT create them — while in the 'default'
// tenant their global admin role still lets them create. Global role gates route access
// (requireRole), the per-tenant role gates the document operation (document ACL).

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const TENANT_HEADER = 'X-Tenant-Id'
const RUN = Date.now()
const VT = `vt${RUN}`            // tenant where the admin is only a 'viewer'

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

test.describe.serial('Per-tenant roles @auth', () => {
  test.beforeAll(() => {
    // Tenant vt + the admin enrolled there as a 'viewer' (downgraded from their global admin role).
    d1Exec(
      `INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at)
       VALUES ('${VT}', 'VT', '${VT}', 'active', '', '{}', 1, 1)`
    )
    d1Exec(
      `INSERT INTO auth_tenant_member (id, tenant_id, user_id, role, created_at, updated_at)
       SELECT 'm-${VT}', '${VT}', id, 'viewer', 1, 1 FROM auth_user WHERE email = 'admin@sonicjs.com'`
    )
  })

  test.afterAll(() => {
    d1Exec(`DELETE FROM auth_tenant_member WHERE id = 'm-${VT}'`)
    d1Exec(`DELETE FROM auth_tenant WHERE slug = '${VT}'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('viewer-in-tenant is DENIED create even though globally admin', async ({ page }) => {
    const res = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { [TENANT_HEADER]: VT, 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title: `Should Fail ${RUN}`, data: { author: 'x' } },
    })
    expect(res.status()).toBe(403)
  })

  test('viewer-in-tenant is ALLOWED read in that tenant', async ({ page }) => {
    const res = await page.request.get(`${BASE_URL}/admin/documents?type=blog_post&status=all&limit=10`, {
      headers: { [TENANT_HEADER]: VT },
    })
    expect(res.ok()).toBeTruthy()
  })

  test('same user retains global admin create in the default tenant (no header)', async ({ page }) => {
    const res = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title: `Default OK ${RUN}`, data: { author: 'x' } },
    })
    expect(res.ok()).toBeTruthy()
    expect((await res.json()).data.tenantId).toBe('default')
  })

  test('teardown: deactivate plugin to restore single-tenant baseline', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
