import { test, expect, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { loginAsAdmin, ensureAdminUserExists, isFeatureAvailable, IS_REMOTE_DEPLOYMENT } from './utils/test-helpers'

// G5 — shared/global document types end-to-end through the canonical admin-documents route. A type
// with settings.global=true is created from one tenant and is visible from another (shared pool),
// while a normal type stays tenant-isolated.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'
const PLUGIN_ID = 'multi-tenant'
const TENANT_HEADER = 'X-Tenant-Id'
const RUN = Date.now()
const T_A = `gacme${RUN}`
const T_B = `gbeta${RUN}`
const GLOBAL_TYPE = `global_note${RUN}`

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../my-sonicjs-app')
function d1Exec(sql: string) {
  execFileSync('npx', ['wrangler', 'd1', 'execute', 'DB', '--local', '--command', sql], { cwd: APP_DIR, stdio: 'pipe' })
}
async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
  await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
  await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
}

test.describe.serial('Global document types @content', () => {
  let featureAvailable = false
  test.beforeAll(async ({ request }) => {
    featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
  })
  test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

  test.beforeAll(() => {
    if (!featureAvailable) return
    // A global document type (settings.global=true) with admin base grants.
    const settings = JSON.stringify({ global: true, baseGrants: { admin: ['read', 'create', 'update', 'delete', 'manage'] } }).replace(/'/g, "''")
    d1Exec(`INSERT INTO document_types (id, name, display_name, settings, source, is_active) VALUES ('${GLOBAL_TYPE}', '${GLOBAL_TYPE}', 'Global Note', '${settings}', 'system', 1)`)
    // Two tenants + the admin as a member ('admin' role) of each so header resolution + create pass.
    for (const t of [T_A, T_B]) {
      d1Exec(`INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at) VALUES ('${t}', '${t}', '${t}', 'active', '', '{}', 1, 1)`)
      d1Exec(`INSERT INTO auth_tenant_member (id, tenant_id, user_id, role, created_at, updated_at) SELECT 'm-${t}', '${t}', id, 'admin', 1, 1 FROM auth_user WHERE email = 'admin@sonicjs.com'`)
    }
  })

  test.afterAll(() => {
    if (!featureAvailable) return
    d1Exec(`DELETE FROM auth_tenant_member WHERE tenant_id IN ('${T_A}','${T_B}')`)
    d1Exec(`DELETE FROM auth_tenant WHERE slug IN ('${T_A}','${T_B}')`)
    // Documents reference the type — delete them before the type row (FK).
    d1Exec(`DELETE FROM documents WHERE type_id = '${GLOBAL_TYPE}'`)
    d1Exec(`DELETE FROM document_types WHERE id = '${GLOBAL_TYPE}'`)
  })

  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
    await setPluginState(page, 'activate')
  })

  test('a global-type doc created in tenant A is stored in the shared pool and visible from tenant B', async ({ page }) => {
    const title = `Shared ${RUN}`
    const createRes = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { [TENANT_HEADER]: T_A, 'Content-Type': 'application/json' },
      data: { typeId: GLOBAL_TYPE, title, data: {} },
    })
    expect(createRes.ok()).toBeTruthy()
    // Stamped into the shared pool, not tenant A.
    expect((await createRes.json()).data.tenantId).toBe('__global__')

    // Visible when listing the global type from tenant B (cross-tenant).
    const fromB = await page.request.get(`${BASE_URL}/admin/documents?type=${GLOBAL_TYPE}&status=all&limit=50`, {
      headers: { [TENANT_HEADER]: T_B },
    })
    expect(fromB.ok()).toBeTruthy()
    expect(((await fromB.json()).data ?? []).map((d: any) => d.title)).toContain(title)
  })

  test('a normal-type doc created in tenant A is NOT visible from tenant B (isolation preserved)', async ({ page }) => {
    const title = `Isolated ${RUN}`
    const createRes = await page.request.post(`${BASE_URL}/admin/documents`, {
      headers: { [TENANT_HEADER]: T_A, 'Content-Type': 'application/json' },
      data: { typeId: 'blog_post', title, data: { author: 'x' } },
    })
    expect(createRes.ok()).toBeTruthy()
    expect((await createRes.json()).data.tenantId).toBe(T_A)

    const fromB = await page.request.get(`${BASE_URL}/admin/documents?type=blog_post&status=all&limit=100`, {
      headers: { [TENANT_HEADER]: T_B },
    })
    expect(((await fromB.json()).data ?? []).map((d: any) => d.title)).not.toContain(title)
  })

  test('teardown: deactivate plugin', async ({ page }) => {
    await setPluginState(page, 'deactivate')
  })
})
