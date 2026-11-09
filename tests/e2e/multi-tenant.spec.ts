import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { isFeatureAvailable } from "./utils/test-helpers"
import { flashedTo } from "./utils/test-helpers"
import { ADMIN_CREDENTIALS } from "./utils/test-helpers"
import { IS_REMOTE_DEPLOYMENT } from "./utils/test-helpers"
import { d1Exec } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 70-multi-tenant.spec.ts", () => {
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

  test.describe.serial('Multi-Tenant plugin @auth @lock-plugin-multi-tenant', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/tenants')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    // Always deactivate on cleanup so other tests see single-tenant
    test.afterAll(async ({ request }) => {
      if (!featureAvailable) return
      const baseURL = process.env.BASE_URL || 'http://localhost:8787'
      await request.post('/auth/seed-admin').catch(() => {})
      await request.post('/auth/sign-in/email', {
        data: { email: 'admin@sonicjs.com', password: 'sonicjs!' },
        headers: { 'Content-Type': 'application/json', Origin: baseURL },
      }).catch(() => {})
      await request.post(`/admin/plugins/${PLUGIN_ID}/deactivate`).catch(() => {})
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

    test('stays active for every admin request, not just the isolate that served the toggle', async ({ page }) => {
      await setPluginState(page, 'activate')

      // Two independent readers of "is the plugin on", on the same page: the Tenants nav link comes
      // from pluginMenuMiddleware, which queries the DB per request, while the switcher comes from
      // tenantMiddleware. tenantMiddleware used to answer from a 30s TTL cache that is per-isolate —
      // as is invalidateTenantCache() — so activating the plugin only took effect immediately on
      // whichever isolate happened to serve the toggle. Measured against a preview deployment right
      // after activation: nav link on 10/10 admin loads, switcher on 5/10. The cosmetic half of that
      // is the switcher; the real half is that an isolate reporting the plugin inactive also ignores
      // the tenant header, the cookie and the domain map and serves everything as 'default'.
      //
      // One load can pass on the stale path by luck, so sample enough of them to be conclusive.
      for (let i = 1; i <= 8; i++) {
        await page.goto(`${BASE_URL}/admin/content`)
        await expect(
          page.locator('a[href="/admin/tenants"]').first(),
          `Tenants nav link missing on admin load #${i}`
        ).toBeAttached()
        await expect(
          page.locator('[data-tenant-switcher]').first(),
          `tenant switcher missing on admin load #${i} — tenant state went stale between isolates`
        ).toBeVisible()
      }
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
        page.waitForURL(flashedTo('/admin/tenants', 'Tenant created')),
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

      // Switch to the created tenant via the row action. POST /admin/tenants/switch redirects to
      // the same /admin/tenants the form was submitted from and sets no flash, so there is no URL
      // change to wait for. The current tenant renders no Switch button, so that button going away
      // is the re-render landing — and unlike the badge, it is not already true before the click.
      await page.locator(`[data-switch-tenant="${TENANT_SLUG}"]`).click()
      await expect(page.locator(`[data-switch-tenant="${TENANT_SLUG}"]`)).toHaveCount(0)

      // The created tenant row now carries the "Current" badge.
      await expect(
        page.locator(`[data-tenant-row="${TENANT_SLUG}"] [data-current-tenant-badge]`)
      ).toBeVisible()

      // Switch back to default so later tests/specs are unaffected.
      await page.locator('[data-switch-tenant="default"]').click()
      await expect(page.locator('[data-switch-tenant="default"]')).toHaveCount(0)
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 71-tenant-membership-gate.spec.ts", () => {
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


  async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
    await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
    await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
  }

  test.describe.serial('Multi-Tenant membership gate @auth @lock-plugin-multi-tenant', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test.beforeAll(() => {
      if (!featureAvailable) return
      // An active tenant with NO membership rows — the admin is not a member.
      d1Exec(
        `INSERT INTO auth_tenant (id, name, slug, status, notes, metadata, created_at, updated_at)
       VALUES ('${ORPHAN_SLUG}', 'Orphan', '${ORPHAN_SLUG}', 'active', '', '{}', 1, 1)`
      )
    })

    test.afterAll(() => {
      if (!featureAvailable) return
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
        page.waitForURL(flashedTo('/admin/tenants', 'Tenant created')),
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 72-per-tenant-roles.spec.ts", () => {
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


  async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
    await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
    await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
  }

  test.describe.serial('Per-tenant roles @auth @lock-plugin-multi-tenant', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = !IS_REMOTE_DEPLOYMENT && await isFeatureAvailable(request, '/admin/tenants')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test.beforeAll(() => {
      if (!featureAvailable) return
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
      if (!featureAvailable) return
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 73-tenant-members.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 74-tenant-invitations.spec.ts", () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 75-global-document-types.spec.ts", () => {
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

  async function setPluginState(page: Page, action: 'activate' | 'deactivate') {
    await page.request.post(`${BASE_URL}/admin/plugins/install`, { data: { name: PLUGIN_ID } }).catch(() => {})
    await page.request.post(`${BASE_URL}/admin/plugins/${PLUGIN_ID}/${action}`).catch(() => {})
  }

  test.describe.serial('Global document types @content @lock-plugin-multi-tenant', () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 76-user-tenant-memberships.spec.ts", () => {
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
})
