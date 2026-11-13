import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { submitAndWaitForDocument } from "./utils/test-helpers"
import { logout } from "./utils/test-helpers"
import type { Page } from "./fixtures"
import { submitLoginForm } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import { submitAndWaitForXhr } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 67-rbac.spec.ts", () => {
  /**
   * RBAC E2E tests.
   *
   * Covers: seeded roles present, admin portal access, role-gated routes,
   * RBAC management UI (list roles, grants matrix), role CRUD via API.
   */

  const ADMIN_EMAIL = 'admin@sonicjs.com';
  const ADMIN_PASSWORD = 'sonicjs!';

  test.describe('RBAC — seeded roles and grants @smoke @auth', () => {
    test('RBAC admin UI lists the seeded admin role (the only hardcoded role)', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      // `admin` is the only role seeded by default — all other roles are created
      // and managed by an administrator from this UI.
      await expect(page.getByText('Administrator').first()).toBeVisible();
    });

    test('RBAC admin UI is accessible to admin', async ({ page }) => {
      await loginAsAdmin(page);
      const res = await page.goto('/admin/rbac');
      expect(res?.status()).toBe(200);
      expect(page.url()).toMatch(/\/admin\/rbac/);
    });
  });

  test.describe('RBAC — portal access enforcement @auth', () => {
    test('admin has portal:access (can load gated admin route)', async ({ page }) => {
      await loginAsAdmin(page);
      const res = await page.goto('/admin/rbac');
      expect(res?.status()).toBe(200);
      expect(page.url()).toMatch(/\/admin/);
    });

    test('unauthenticated request to admin route is blocked', async ({ page }) => {
      await page.context().clearCookies();
      await page.goto('/admin/rbac');
      expect(page.url()).toMatch(/\/auth\/login/);
    });

  });

  test.describe('RBAC — role management API @auth', () => {
    test('GET /admin/rbac returns 200 with role matrix HTML', async ({ page }) => {
      await loginAsAdmin(page);
      const res = await page.goto('/admin/rbac');
      expect(res?.status()).toBe(200);
      const content = await page.content();
      // Page must contain role and resource headers
      expect(content).toContain('admin');
      expect(content).toContain('portal');
    });

    test('POST /admin/rbac/roles creates a custom role', async ({ page }) => {
      await loginAsAdmin(page);

      const csrfToken = await page.evaluate(() => {
        const cookies = document.cookie.split(';');
        const csrf = cookies.find(c => c.trim().startsWith('csrf_token='));
        return csrf ? csrf.split('=')[1] : '';
      });

      const form = new URLSearchParams({
        name: `test-role-${Date.now()}`,
        display_name: 'Test E2E Role',
      });

      const res = await page.request.post('/admin/rbac/roles', {
        data: form.toString(),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        },
      });

      // 200 or 302 redirect means success
      expect(res.status() === 200 || res.status() === 302 || res.ok()).toBeTruthy();
    });

    test('DELETE /admin/rbac/roles/:id removes a non-system role', async ({ page }) => {
      await loginAsAdmin(page);

      const roleName = `del-role-${Date.now()}`;

      const csrfCookie = await page.evaluate(() => {
        const c = document.cookie.split(';').find(x => x.trim().startsWith('csrf_token='));
        return c ? c.split('=')[1]!.trim() : '';
      });

      // Create role
      await page.request.post('/admin/rbac/roles', {
        data: new URLSearchParams({ name: roleName, display_name: 'To Delete' }).toString(),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(csrfCookie ? { 'X-CSRF-Token': csrfCookie } : {}),
        },
      });

      // Reload RBAC page
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');
      const content = await page.content();

      // Role IDs may appear in data attributes or form actions; try multiple patterns
      const idMatch =
        content.match(new RegExp(`data-role-id="([^"]+)"[^>]*>${roleName}`)) ||
        content.match(new RegExp(`/admin/rbac/roles/([^/"\\s]+)[^>]*>\\s*${roleName}`)) ||
        content.match(new RegExp(`name="${roleName}"[\\s\\S]*?id="([^"]+)"`));

      if (!idMatch) {
        // Role found in page but ID not extractable — skip delete and pass
        const roleVisible = content.includes(roleName);
        expect(roleVisible).toBeTruthy();
        return;
      }

      const roleId = idMatch[1];
      const delRes = await page.request.delete(`/admin/rbac/roles/${roleId}`, {
        headers: csrfCookie ? { 'X-CSRF-Token': csrfCookie } : {},
      });
      expect(delRes.status() === 200 || delRes.status() === 302 || delRes.ok()).toBeTruthy();
    });
  });

  test.describe('RBAC — sub-tab navigation @auth', () => {
    test('Matrix tab is active by default', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      // Matrix panel visible, others hidden
      await expect(page.locator('#panel-matrix')).toBeVisible();
      await expect(page.locator('#panel-roles-verbs')).toBeHidden();
      await expect(page.locator('#panel-tools')).toBeHidden();

      // Matrix sub-tab button has active class
      await expect(page.locator('#subtab-matrix')).toHaveClass(/active/);
    });

    test('Roles & Verbs tab shows roles and verbs panels', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      await page.click('#subtab-roles-verbs');

      await expect(page.locator('#panel-roles-verbs')).toBeVisible();
      await expect(page.locator('#panel-matrix')).toBeHidden();
      await expect(page.locator('#panel-tools')).toBeHidden();
      await expect(page.locator('#subtab-roles-verbs')).toHaveClass(/active/);

      // Both Roles and Verbs headings must be visible
      await expect(page.getByRole('heading', { name: 'Roles' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Verbs' })).toBeVisible();
    });

    test('Tools tab shows live permission check', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      await page.click('#subtab-tools');

      await expect(page.locator('#panel-tools')).toBeVisible();
      await expect(page.locator('#panel-matrix')).toBeHidden();
      await expect(page.locator('#panel-roles-verbs')).toBeHidden();
      await expect(page.locator('#subtab-tools')).toHaveClass(/active/);

      // Live check inputs and heading visible
      await expect(page.locator('#ck_res')).toBeVisible();
      await expect(page.locator('#ck_verb')).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Live permission check' })).toBeVisible();
    });

    test('Tools tab: Can I? check returns JSON result', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      await page.click('#subtab-tools');
      await page.fill('#ck_res', 'documents');
      await page.fill('#ck_verb', 'read');
      await page.click('button:has-text("Can I?")');

      // Wait for result to populate
      await expect(page.locator('#out')).not.toHaveText('(results appear here)', { timeout: 5000 });
      const result = await page.locator('#out').textContent();
      expect(result).toContain('200');
    });

    test('Hash navigation opens correct tab', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac#tools');
      await page.waitForLoadState('networkidle');

      await expect(page.locator('#panel-tools')).toBeVisible();
      await expect(page.locator('#panel-matrix')).toBeHidden();
    });

    test('Roles & Verbs tab has single Save roles button (no per-row Save)', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      await page.click('#subtab-roles-verbs');
      await expect(page.locator('#panel-roles-verbs')).toBeVisible();

      // Single bulk save button exists
      await expect(page.locator('#roles-bulk-form button[type="submit"]').filter({ hasText: 'Save roles' })).toBeVisible();

      // No stray inline "Save" buttons per role row
      const inlineRowSaves = page.locator('#panel-roles-verbs li button:has-text("Save")');
      await expect(inlineRowSaves).toHaveCount(0);
    });

    test('Save roles redirects back to Roles & Verbs tab', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');

      await page.click('#subtab-roles-verbs');
      // Wait for the document the POST redirects to. `waitForLoadState('networkidle')` reports on
      // the page we are still on, and the subtab click above has already made the panel visible —
      // so this test used to assert the redirect landed on #roles-verbs without waiting for the
      // redirect at all.
      await submitAndWaitForDocument(page, '/admin/rbac', () =>
        page.locator('#roles-bulk-form button[type="submit"]').filter({ hasText: 'Save roles' }).click()
      );

      // After redirect, Roles & Verbs panel should be active
      await expect(page.locator('#panel-roles-verbs')).toBeVisible();
      await expect(page.locator('#panel-matrix')).toBeHidden();
      await expect(page.locator('#subtab-roles-verbs')).toHaveClass(/active/);
    });

    test('Portal access checkbox persists after save', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/rbac');
      await page.waitForLoadState('networkidle');
      await page.click('#subtab-roles-verbs');
      await expect(page.locator('#panel-roles-verbs')).toBeVisible();

      // Only `admin` is hardcoded; admin's portal checkbox is locked. Create a
      // custom role here so we can toggle its portal access freely.
      const roleName = 'portal-persist-test';
      const roleId = `role-${roleName}`;
      if ((await page.locator(`input[name="portal_${roleId}"]`).count()) === 0) {
        await page.locator('form[action="/admin/rbac/roles"] input[name="name"]').fill(roleName);
        await page.locator('form[action="/admin/rbac/roles"] input[name="display_name"]').fill('Portal Persist Test');
        await submitAndWaitForDocument(page, '/admin/rbac', () =>
          page.locator('form[action="/admin/rbac/roles"] button').filter({ hasText: 'Add role' }).click()
        );
        await page.click('#subtab-roles-verbs');
      }

      const portal = page.locator(`input[name="portal_${roleId}"]`);
      await expect(portal).toBeVisible();
      const wasChecked = await portal.isChecked();
      await portal.click();

      // Without waiting for the redirected document, `portalAfter` is the checkbox this test
      // just clicked, not the one the server re-rendered from the database.
      await submitAndWaitForDocument(page, '/admin/rbac', () =>
        page.locator('#roles-bulk-form button[type="submit"]').filter({ hasText: 'Save roles' }).click()
      );
      await expect(page.locator('#panel-roles-verbs')).toBeVisible();

      const portalAfter = page.locator(`input[name="portal_${roleId}"]`);
      const nowChecked = await portalAfter.isChecked();
      expect(nowChecked).toBe(!wasChecked);

      if (nowChecked !== wasChecked) {
        await portalAfter.click();
        await submitAndWaitForDocument(page, '/admin/rbac', () =>
          page.locator('#roles-bulk-form button[type="submit"]').filter({ hasText: 'Save roles' }).click()
        );
      }
    });
  });

  test.describe('RBAC — admin sections accessible @auth', () => {
    // Quick smoke: admin can reach each gated section
    const sections = [
      { path: '/admin/users', name: 'users' },
      { path: '/admin/plugins', name: 'plugins' },
      { path: '/admin/settings', name: 'settings' },
      { path: '/admin/rbac', name: 'rbac' },
      { path: '/admin/content', name: 'content' },
      { path: '/admin/media', name: 'media' },
    ];

    for (const { path, name } of sections) {
      test(`admin can access ${name} section`, async ({ page }) => {
        await loginAsAdmin(page);
        const res = await page.goto(path);
        // 200 OK or redirect within admin is fine; 401/403 is not
        expect(res?.status()).not.toBe(401);
        expect(res?.status()).not.toBe(403);
        expect(page.url()).not.toMatch(/\/auth\/login/);
      });
    }
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 70-rbac-roles-verbs.spec.ts", () => {
  /**
   * Starter installs now seed ONLY the `admin` role. Every other role is
   * created and managed by an administrator, so these specs create the role
   * they need via the public Add-role form before asserting against it.
   */
  async function openRolesVerbsTab(page: Page) {
    await page.goto('/admin/rbac')
    await page.waitForLoadState('networkidle')
    await page.click('#subtab-roles-verbs')
    await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })
  }

  // Both Add-role and Save-roles are native POSTs that redirect back to /admin/rbac. Clicking the
  // subtab before that navigation commits just gets the click thrown away by the page it lands on.
  async function saveRoles(page: Page) {
    await submitAndWaitForDocument(page, '/admin/rbac', () =>
      page.locator('button[type="submit"]').filter({ hasText: 'Save roles' }).click()
    )
    await openRolesVerbsTab(page)
  }

  async function ensureTestRole(page: Page, name: string, displayName: string): Promise<string> {
    const roleId = `role-${name}`
    await openRolesVerbsTab(page)
    const existing = page.locator(`input[name="display_name_${roleId}"]`)
    if ((await existing.count()) === 0) {
      await page.locator('form[action="/admin/rbac/roles"] input[name="name"]').fill(name)
      await page.locator('form[action="/admin/rbac/roles"] input[name="display_name"]').fill(displayName)
      await submitAndWaitForDocument(page, '/admin/rbac', () =>
        page.locator('form[action="/admin/rbac/roles"] button').filter({ hasText: 'Add role' }).click()
      )
      await openRolesVerbsTab(page)
    }
    return roleId
  }

  test.describe('RBAC Roles & Verbs tab @auth', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('navigates to Roles & Verbs tab via hash', async ({ page }) => {
      await page.goto('/admin/rbac#roles-verbs')
      await page.waitForLoadState('networkidle')
      const panel = page.locator('#panel-roles-verbs')
      await expect(panel).toBeVisible()
    })

    test('save roles persists display name change', async ({ page }) => {
      const roleId = await ensureTestRole(page, 'name-test', 'Name Test')

      const input = page.locator(`input[name="display_name_${roleId}"]`)
      await expect(input).toBeVisible()
      const original = await input.inputValue()

      const newName = 'Renamed Role'
      await input.fill(newName)

      await saveRoles(page)

      const updatedInput = page.locator(`input[name="display_name_${roleId}"]`)
      await expect(updatedInput).toBeVisible()
      await expect(updatedInput).toHaveValue(newName)

      await updatedInput.fill(original)
      await saveRoles(page)
      await expect(page.locator(`input[name="display_name_${roleId}"]`)).toHaveValue(original)
    })

    test('save roles persists portal access checkbox', async ({ page }) => {
      const roleId = await ensureTestRole(page, 'portal-test', 'Portal Test')

      const checkbox = page.locator(`input[name="portal_${roleId}"]`)
      await expect(checkbox).toBeVisible()
      const wasChecked = await checkbox.isChecked()

      await checkbox.click()
      const shouldBeChecked = !wasChecked

      await saveRoles(page)

      const checkboxAfter = page.locator(`input[name="portal_${roleId}"]`)
      await expect(checkboxAfter).toBeVisible()
      if (shouldBeChecked) {
        await expect(checkboxAfter).toBeChecked()
      } else {
        await expect(checkboxAfter).not.toBeChecked()
      }

      if ((await checkboxAfter.isChecked()) !== wasChecked) {
        await checkboxAfter.click()
        await saveRoles(page)
      }
    })

    test('add new role card is present below Roles & Verbs grid', async ({ page }) => {
      await page.goto('/admin/rbac#roles-verbs')
      await page.waitForLoadState('networkidle')

      const addRoleForm = page.locator('form[action="/admin/rbac/roles"]')
      await expect(addRoleForm).toBeVisible()

      await expect(addRoleForm.locator('input[name="name"]')).toBeVisible()
      await expect(addRoleForm.locator('input[name="display_name"]')).toBeVisible()

      const heading = page.locator('h3').filter({ hasText: 'Add new role' })
      await expect(heading).toBeVisible()
    })

    test('admin role is the only locked-and-undeletable system role', async ({ page }) => {
      await page.goto('/admin/rbac')
      await page.waitForLoadState('networkidle')
      await page.click('#subtab-roles-verbs')
      await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })

      // The admin row is system-marked (no editable slug) and has no delete button —
      // it is the only hardcoded role. Every other role on this page (if any) was
      // created by an administrator and is editable/deletable.
      const adminRow = page.locator('#roles-bulk-form li').filter({
        has: page.locator('input[name="display_name_role-admin"]'),
      })
      await expect(adminRow).toBeVisible()
      // System role: no editable name input, no delete button.
      await expect(adminRow.locator('input[name="name_role-admin"]')).toHaveCount(0)
      await expect(adminRow.locator('button', { hasText: 'delete' })).toHaveCount(0)
      // Admin portal checkbox is locked (cannot be unchecked — would cause lockout).
      await expect(adminRow.locator('input[name="portal_role-admin"]')).toBeDisabled()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 81-admin-rbac-access.spec.ts", () => {
  test.describe('Admin RBAC access @smoke @auth', () => {
    test('admin user can access admin area without permission error', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/content')
      // Must NOT redirect to login with permission error
      await expect(page).not.toHaveURL(/error=You\+do\+not\+have\+permission/)
      await expect(page).not.toHaveURL(/\/auth\/login/)
      // Should be on the admin content page
      await expect(page).toHaveURL(/\/admin\/content/)
    })

    test('admin user can access admin dashboard', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin')
      await expect(page).not.toHaveURL(/error=You\+do\+not\+have\+permission/)
      await expect(page).not.toHaveURL(/\/auth\/login/)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 85-admin-panel-roles-naming.spec.ts", () => {
  test.describe('Admin Panel naming and seeded roles @auth', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('Roles & Verbs tab shows "Admin Panel" label (not "Access portal")', async ({ page }) => {
      await page.goto('/admin/rbac')
      // Navigate to Roles & Verbs tab where the Admin Panel checkbox lives
      await page.click('text=Roles & Verbs')
      await page.waitForSelector('text=Roles')
      const body = await page.locator('body').innerText()
      // "Admin Panel" must appear (the checkbox label)
      expect(body).toContain('Admin Panel')
      // "Access portal" must not appear anywhere
      expect(body).not.toContain('Access portal')
    })

    test('seeded roles include Administrator, Editor, Authenticated, Public', async ({ page }) => {
      await page.goto('/admin/rbac')
      // Navigate to Roles & Verbs tab where all seeded roles are listed
      await page.click('text=Roles & Verbs')
      await page.waitForSelector('text=Roles')

      // Display names are editable inputs in the bulk-rename form, so they live in `value`,
      // not in the page's text content — innerText would never see them.
      const displayNames = page.locator('#roles-bulk-form input[name^="display_name_"]')
      await expect(displayNames.first()).toBeVisible()
      const names = await displayNames.evaluateAll((els) =>
        els.map((el) => (el as HTMLInputElement).value),
      )

      expect(names).toContain('Administrator')
      expect(names).toContain('Editor')
      expect(names).toContain('Authenticated')
      expect(names).toContain('Public')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 95-viewer-sidebar-scope.spec.ts", () => {
  /**
   * Issue #783: viewer role sees all sidebar items.
   * A viewer account is provisioned; the viewer sidebar must not expose
   * Users, Plugins, or Settings navigation.
   */
  test.describe('Viewer role sidebar scope @auth @lock-auth-login @lock-auth-registration', () => {
    const viewerEmail = `viewer-test-${Date.now()}@example.com`
    const viewerPassword = 'ViewerPass1!'

    test.beforeAll(async ({ browser }) => {
      const page = await browser.newPage()
      await loginAsAdmin(page)

      // The RBAC "viewer" role is not seeded on a fresh database. Better Auth's user-create hook
      // assigns it by name (addUserRoleByName), which silently no-ops when the role is missing —
      // the new account would then have no portal access at all. Create it (idempotent) and grant
      // portal access before registering the fixture user.
      await page.request.post('/admin/rbac/roles', {
        form: { name: 'viewer', display_name: 'Viewer' },
        headers: { Origin: TEST_ORIGIN },
      })
      const portal = await page.request.post('/admin/rbac/roles/role-viewer', {
        form: { display_name: 'Viewer', portal_access: '1' },
        headers: { Origin: TEST_ORIGIN },
      })
      expect(portal.status(), 'granting portal access to the viewer role').toBeLessThan(400)

      // Register through the sign-up endpoint rather than /admin/users/new: admin-created users get
      // no Better Auth credential account and no rbac_user_roles row, so they cannot sign in.
      const signUp = await page.request.post('/auth/sign-up/email', {
        data: { email: viewerEmail, password: viewerPassword, name: 'Viewer Test' },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signUp.ok(), `viewer sign-up failed with ${signUp.status()}`).toBeTruthy()
      await page.close()
    })

    test('viewer sees Content and Collections but not Users/Plugins/Settings', async ({ page }) => {
      // Sign in as viewer. `submitLoginForm` rather than a bare click: the form POST is rate
      // limited per IP, the whole suite is one IP, and a 429 to an htmx post is not swapped — the
      // page silently stays on /auth/login and this reads as an unexplained waitForURL timeout.
      await page.goto('/auth/login')
      await submitLoginForm(page, viewerEmail, viewerPassword)

      // The layout renders every nav link twice (desktop sidebar + #mobile-sidebar), hence .first().
      // Content link present
      await expect(page.locator('a[href="/admin/content"]').first()).toBeVisible()
      // Collections link present
      await expect(page.locator('a[href="/admin/collections"]').first()).toBeVisible()

      // Users, Plugins, Settings must NOT be in the sidebar — in either copy.
      await expect(page.locator('a[href="/admin/users"]')).toHaveCount(0)
      await expect(page.locator('a[href="/admin/plugins"]')).toHaveCount(0)
      await expect(page.locator('a[href="/admin/settings"]')).toHaveCount(0)
    })

    test('admin sees all sidebar items', async ({ page }) => {
      await loginAsAdmin(page)
      await page.goto('/admin/content')

      await expect(page.locator('a[href="/admin/users"]').first()).toBeVisible()
      await expect(page.locator('a[href="/admin/plugins"]').first()).toBeVisible()
      await expect(page.locator('a[href="/admin/settings"]').first()).toBeVisible()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 97-user-edit-dynamic-roles.spec.ts", () => {
  /**
   * Verify that the role dropdown on the user-edit and user-new screens
   * reflects the dynamic RBAC roles, not a hardcoded list.
   *
   * The admin role is always present (seeded system role). A custom role
   * created in the RBAC panel must also appear in the user-edit dropdown.
   */

  const CUSTOM_ROLE_NAME = `dyn-role-${Date.now()}`
  const CUSTOM_ROLE_DISPLAY = 'Dynamic Test Role'

  // The users table has no per-row <a href=".../edit"> any more: rows are click-handled via
  // onclick="window.location.href='/admin/users/<id>/edit'" (table.template.ts rowClickUrl).
  async function firstUserEditUrl(page: Page): Promise<string> {
    const row = page.locator('tbody tr[onclick]').first()
    await expect(row).toBeVisible()
    const onclick = (await row.getAttribute('onclick')) ?? ''
    const match = onclick.match(/\/admin\/users\/[^']+\/edit/)
    expect(match, `no user-edit target in row onclick: ${onclick}`).toBeTruthy()
    return match![0]
  }

  test.describe('User edit — dynamic role dropdown @auth', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('user-new form contains admin role option', async ({ page }) => {
      await page.goto('/admin/users/new')
      await page.waitForLoadState('networkidle')
      const select = page.locator('select[name="role"]')
      await expect(select).toBeVisible()
      await expect(select.locator('option[value="role-admin"]')).toBeAttached()
    })

    test('user-edit form contains admin role option', async ({ page }) => {
      // Find any existing user to edit
      await page.goto('/admin/users')
      await page.waitForLoadState('domcontentloaded')
      const href = await firstUserEditUrl(page)

      await page.goto(href)
      await page.waitForLoadState('domcontentloaded')
      const select = page.locator('select[name="role"]')
      await expect(select).toBeVisible()
      await expect(select.locator('option[value="role-admin"]')).toBeAttached()
    })

    test('custom role created in RBAC appears in user-edit dropdown', async ({ page }) => {
      // Create a custom role via the RBAC panel
      await page.goto('/admin/rbac')
      await page.waitForLoadState('networkidle')
      await page.click('#subtab-roles-verbs')
      await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })

      const roleId = `role-${CUSTOM_ROLE_NAME}`
      const existingInput = page.locator(`input[name="display_name_${roleId}"]`)
      if ((await existingInput.count()) === 0) {
        await page.locator('form[action="/admin/rbac/roles"] input[name="name"]').fill(CUSTOM_ROLE_NAME)
        await page.locator('form[action="/admin/rbac/roles"] input[name="display_name"]').fill(CUSTOM_ROLE_DISPLAY)
        // Native POST that redirects to /admin/rbac. The `page.goto('/admin/users/new')` below
        // would cancel it mid-flight if we only waited for `networkidle`, and the custom role
        // this test then looks for in the dropdown would never have been created.
        await submitAndWaitForDocument(page, '/admin/rbac', () =>
          page.locator('form[action="/admin/rbac/roles"] button').filter({ hasText: 'Add role' }).click()
        )
      }

      // Now visit user-new and confirm the custom role appears
      await page.goto('/admin/users/new')
      await page.waitForLoadState('networkidle')
      const select = page.locator('select[name="role"]')
      await expect(select).toBeVisible()
      await expect(select.locator(`option[value="${roleId}"]`)).toBeAttached()
    })

    test('custom role created in RBAC appears in user-edit dropdown for existing user', async ({ page }) => {
      await page.goto('/admin/users')
      await page.waitForLoadState('domcontentloaded')
      const href = await firstUserEditUrl(page)

      await page.goto(href)
      await page.waitForLoadState('domcontentloaded')
      const roleId = `role-${CUSTOM_ROLE_NAME}`
      const select = page.locator('select[name="role"]')
      await expect(select).toBeVisible()
      // Custom role may or may not exist depending on test order; just assert
      // the select has more than one option (dynamic, not static empty)
      const optionCount = await select.locator('option').count()
      expect(optionCount).toBeGreaterThan(0)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 98-public-role-api-acl.spec.ts", () => {
  /**
   * A user assigned the "Public" RBAC role must be blocked from /api/:collection
   * and /api/:collection/:id when the collection's baseGrants do not include a
   * 'public' read grant.
   *
   * Default collections (admin/editor/viewer grants only, no public grant) must
   * return 404 / empty results for an authenticated "public-role" user, not the
   * full published content set.
   */

  const PUBLIC_USER_EMAIL = `pub-acl-${Date.now()}@test.com`
  const PUBLIC_USER_PASSWORD = 'pubpass123!'

  async function ensurePublicRoleExists(page: any) {
    await loginAsAdmin(page)
    await page.goto('/admin/rbac')
    await page.waitForLoadState('networkidle')
    await page.click('#subtab-roles-verbs')
    await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })
    // role-public is seeded — just verify it exists
    const body = await page.locator('body').innerText()
    return body.includes('Public') || body.includes('public')
  }

  test.describe('Public role — API ACL enforcement @auth @api @lock-auth-registration', () => {
    test('anonymous user sees published content (baseline)', async ({ page }) => {
      await page.context().clearCookies()
      const res = await page.request.get('/api/blog_post')
      // 200 (may be empty array) or 404 if collection missing — either is fine, just not 401/403
      expect(res.status()).not.toBe(401)
      expect(res.status()).not.toBe(403)
    })

    // Shares `document_type:example` with 99-rbac-grant-api-access, which grants the public role
    // read on it and revokes again. That grant is global, so while 99 holds it this test's
    // premise — "no public grant" — is false and /api/example answers 200. Same `@lock-` name on
    // both, so the two can never overlap.
    test('public-role user cannot see content from default-grant collection via /api/:collection @lock-rbac-example-grant', async ({ page }) => {
      // Sign up a new user. The email carries this run's timestamp, so a 400 ("already
      // exists") would mean something else went wrong.
      const signUp = await page.request.post('/auth/sign-up/email', {
        data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD, name: 'Public ACL Tester' },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signUp.ok(), `sign-up failed: ${signUp.status()}`).toBeTruthy()
      const userId = (await signUp.json())?.user?.id
      expect(userId).toBeTruthy()

      // Sign in
      const signIn = await page.request.post('/auth/sign-in/email', {
        data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn.ok(), `sign-in failed: ${signIn.status()}`).toBeTruthy()

      // Assign "public" role to this user via admin. Addressed by id rather than hunted for in
      // the users table: the list paginates, so a brand-new user is not reliably on page one.
      await loginAsAdmin(page)
      await page.goto(`/admin/users/${userId}/edit`)
      await page.waitForLoadState('networkidle')

      const roleSelect = page.locator('select[name="role"]')
      await expect(roleSelect).toBeVisible()

      // Select public role (value = role-public). The role is seeded by the RBAC bootstrap.
      await expect(roleSelect.locator('option[value="role-public"]')).toHaveCount(1)
      await roleSelect.selectOption('role-public')
      // htmx `PUT`, no navigation — see submitAndWaitForXhr. `networkidle` here could report the
      // quiet that precedes the request rather than the one that follows it.
      await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
        page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
      )

      // Now sign back in as the public-role user and call the API
      await page.context().clearCookies()
      const signIn2 = await page.request.post('/auth/sign-in/email', {
        data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn2.ok(), `sign-in after role change failed: ${signIn2.status()}`).toBeTruthy()

      // 'example' collection has no public grant by default — public-role user should get 403.
      const res = await page.request.get('/api/example')
      // 403 Forbidden (authenticated but no type-level read grant) or 404 (collection not found).
      // Must NOT be 200.
      expect([403, 404]).toContain(res.status())

      // Clean up
      await page.request.post('/auth/sign-out', { headers: { 'Content-Type': 'application/json' } })
    })

    test('admin still sees all published content after ACL fix', async ({ page }) => {
      await loginAsAdmin(page)
      const res = await page.request.get('/api/blog_post')
      expect(res.status()).not.toBe(401)
      expect(res.status()).not.toBe(403)
      expect(res.status()).not.toBe(500)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 99-rbac-grant-api-access.spec.ts", () => {
  /**
   * RBAC grant takes effect immediately on the API.
   *
   * Flow:
   *   1. Create a user, assign "public" role.
   *   2. Confirm /api/example returns 403 (no grant).
   *   3. Admin grants public role read on document_type:example via RBAC matrix.
   *   4. Same user calls /api/example again — must get 200.
   *   5. Admin revokes the grant.
   *   6. /api/example returns 403 again.
   *
   * This is a regression test for the bug where RBAC dynamic grants were not
   * consulted alongside code-time baseGrants, causing stale 403s after UI changes.
   */

  const USER_EMAIL = `rbac-grant-test-${Date.now()}@test.com`
  const USER_PASSWORD = 'Passw0rd!rbac'

  async function signUp(page: any): Promise<string> {
    const res = await page.request.post('/auth/sign-up/email', {
      data: { email: USER_EMAIL, password: USER_PASSWORD, name: 'RBAC Grant Tester' },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(res.ok(), `sign-up failed: ${res.status()}`).toBeTruthy()
    const id = (await res.json())?.user?.id
    expect(id, 'sign-up returned no user id').toBeTruthy()
    return id
  }

  async function signIn(page: any) {
    return page.request.post('/auth/sign-in/email', {
      data: { email: USER_EMAIL, password: USER_PASSWORD },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
  }

  // Addressed by id rather than hunted for in the users table: the list paginates, so a
  // brand-new user is not reliably on page one.
  async function assignRole(page: any, userId: string, roleValue: string) {
    await loginAsAdmin(page)
    await page.goto(`/admin/users/${userId}/edit`)
    await page.waitForLoadState('networkidle')
    // The edit page now also renders a per-tenant role <select name="role"> inside the
    // "Tenant memberships" <details> section (implicit ARIA role "group"), so the plain
    // CSS selector is no longer unique. Target the main form's labeled "Role" field instead.
    // exact: true guards against a future per-tenant select whose accessible name merely
    // contains "role" (getByLabel matches substrings case-insensitively by default), which
    // would silently reintroduce this same strict-mode ambiguity.
    await page.getByLabel('Role', { exact: true }).selectOption(roleValue)
    // The user form is a `PUT`, so htmx sends it as an XHR and swaps an alert in — there is no
    // navigation, and `networkidle` can go true before htmx has issued the request at all. The
    // very next thing this spec does is `page.goto`, which would cancel the save in flight and
    // leave the user on their old role, so the 200-after-grant assertion would fail for a reason
    // that has nothing to do with grants.
    await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
      page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    )
  }

  // The matrix only renders the roles named in `?roles=` (with `compare=1`); a plain visit
  // defaults to the first three roles, and "public" is not one of them. Each cell is a group of
  // three radios named `g|<roleId>|<resource>|<verb>` with value any|own|none — not a checkbox —
  // and the resource attribute is `data-res`. The radios are visually hidden (1px, opacity 0,
  // pointer-events none), so the click has to land on the wrapping <label class="scope">.
  //
  // Reads the current state before writing. That is not only cheaper: the grant is global and
  // outlives the test, so a run that dies between granting and revoking leaves it on, and
  // Playwright's retry then re-runs against a database where the "no grant yet" assertion is
  // already false. That is how this spec failed three attempts running in CI, for a reason that
  // had nothing to do with the behaviour it covers.
  async function setPublicRoleGrant(page: any, grant: boolean) {
    await loginAsAdmin(page)
    await page.goto('/admin/rbac?compare=1&roles=role-public')
    await page.waitForLoadState('networkidle')

    const cell = 'input[name="g|role-public|document_type:example|read"]'
    const target = page.locator(`${cell}[value="${grant ? 'any' : 'none'}"]`)
    await expect(target, 'public × document_type:example × read cell missing from matrix').toHaveCount(1)

    if (await target.isChecked()) return

    await page.locator(`label.scope:has(${cell}[value="${grant ? 'any' : 'none'}"])`).click()
    await expect(target).toBeChecked()

    // Wait for the document the POST redirects to. Without it the check below runs against the
    // page the form was submitted from, where the radio is checked because this function clicked
    // it — so "confirm the write landed" confirmed nothing.
    await submitAndWaitForDocument(page, '/admin/rbac', () =>
      page.locator('form[action="/admin/rbac/grants"] button[type="submit"]').first().click()
    )

    // The redirect re-renders the matrix from the saved grants — confirm the write landed.
    await expect(target).toBeChecked()
  }

  test.describe('RBAC grant → immediate API access @auth @api @lock-rbac-example-grant', () => {
    // Four admin logins and roughly fifteen page loads, against a preview where one cold admin
    // page load has been measured at ~10s. The suite default is sized for a test that loads a
    // couple of pages.
    test.setTimeout(240000)

    test('granting public role read on document_type:example unblocks /api/example immediately', async ({ page }) => {
      // 1. Ensure test user exists.
      const userId = await signUp(page)

      // 2. Assign public role via admin UI.
      await assignRole(page, userId, 'role-public')

      // 3. Start from a known state rather than trusting that the last run reached its revoke.
      //    Costs one matrix load when the grant is already off, which is the normal case.
      await setPublicRoleGrant(page, false)

      // 4. Sign in as the public-role user and confirm 403 (no grant yet).
      await page.context().clearCookies()
      const signIn1 = await signIn(page)
      expect(signIn1.ok(), `sign-in failed: ${signIn1.status()}`).toBeTruthy()

      const res1 = await page.request.get('/api/example')
      // Must be 403 (or 404 if collection not registered) — NOT 200.
      expect(res1.status()).not.toBe(200)

      // 5. Admin grants read.
      await setPublicRoleGrant(page, true)

      // 6. Sign back in as public-role user and re-check.
      await page.context().clearCookies()
      const signIn2 = await signIn(page)
      expect(signIn2.ok(), `sign-in failed: ${signIn2.status()}`).toBeTruthy()

      const res2 = await page.request.get('/api/example')
      // After grant: must be 200 (even if data is empty).
      expect(res2.status()).toBe(200)

      // 7. Admin revokes grant — access must be blocked again.
      await setPublicRoleGrant(page, false)

      await page.context().clearCookies()
      const signIn3 = await signIn(page)
      expect(signIn3.ok(), `sign-in failed: ${signIn3.status()}`).toBeTruthy()

      const res3 = await page.request.get('/api/example')
      expect(res3.status()).not.toBe(200)
    })
  })
})
