import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { getCsrfTokenFromPage } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import type { Page } from "./fixtures"
import { ADMIN_CREDENTIALS } from "./utils/test-helpers"
import { requestLoginToken } from "./utils/test-helpers"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { submitAndWaitForXhr } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 115-admin-set-password.spec.ts", () => {
  /**
   * A password set by an admin is the password that signs in.
   *
   * Better Auth signs in against `auth_account.password`. Admin create-user and admin edit-user
   * used to write only `auth_user.password_hash`, so an admin-created user could not sign in at
   * all, and after an admin set a new password the old one kept working and the new one failed.
   */
  test.describe('Admin-set passwords sign in @auth', () => {
    test('create a user, then change their password: new one works, old one does not', async ({ page, request }) => {
      await loginAsAdmin(page)

      const unique = Date.now()
      const email = `admin-pw-test-${unique}@example.com`
      const firstPassword = `FirstPass${unique}!`
      const changedPassword = `Changed${unique}!`

      // Create user via admin UI API
      const csrfToken = await getCsrfTokenFromPage(page)
      const createRes = await page.request.post('/admin/users/new', {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        },
        // The handler reads snake_case names and rejects the submission unless
        // `confirm_password` matches.
        form: {
          email,
          first_name: 'PW',
          last_name: 'Test',
          password: firstPassword,
          confirm_password: firstPassword,
          // RBAC role ids are prefixed; an unknown value is rejected.
          role: 'role-editor',
          is_active: '1',
          email_verified: '1',
        },
      })
      // Accept redirect (200 with HX-Redirect) or 302
      expect([200, 302].includes(createRes.status())).toBeTruthy()
      // A validation failure also comes back as a 200, as an inline alert — so check the
      // body rather than trusting the status.
      expect(await createRes.text()).not.toContain('bg-error/10')

      // Sign in with the first password
      const signIn1 = await request.post('/auth/sign-in/email', {
        data: { email, password: firstPassword },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn1.ok()).toBeTruthy()

      // Sign out
      await request.post('/auth/sign-out', {
        data: {},
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })

      // Change password via admin edit
      await loginAsAdmin(page)

      // Find the user ID
      const usersRes = await page.request.get(`/admin/users`)
      expect(usersRes.ok()).toBeTruthy()

      // Navigate to admin and change password via the edit form
      await page.goto('/admin/users')
      await page.waitForLoadState('networkidle')

      // Open the user's edit page. The only anchor carrying the address is a `mailto:`
      // link — the row itself navigates, through an onclick rather than an href.
      const row = page.locator(`tr:has-text("${email}")`).first()
      await expect(row).toBeVisible({ timeout: 15000 })
      const rowOnClick = (await row.getAttribute('onclick')) || ''
      const editPath = rowOnClick.match(/\/admin\/users\/[^']+\/edit/)?.[0]
      expect(editPath).toBeTruthy()
      await page.goto(editPath!)
      await page.waitForLoadState('networkidle')

      // Fill in the new password. The edit form posts snake_case names and refuses the
      // change unless `confirm_password` matches, so both fields have to be filled.
      await page.locator('input[name="new_password"]').fill(changedPassword)
      await page.locator('input[name="confirm_password"]').fill(changedPassword)
      await page.locator('button[type="submit"]').first().click()
      await page.waitForTimeout(2000)

      // Sign out admin
      await request.post('/auth/sign-out', {
        data: {},
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })

      // New password works
      const signIn2 = await request.post('/auth/sign-in/email', {
        data: { email, password: changedPassword },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn2.ok()).toBeTruthy()

      await request.post('/auth/sign-out', {
        data: {},
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })

      // …and the password it replaced does not
      const signIn3 = await request.post('/auth/sign-in/email', {
        data: { email, password: firstPassword },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn3.ok()).toBeFalsy()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 116-register-credential.spec.ts", () => {
  /**
   * The register form must create both auth_user AND auth_account credential row
   * so that Better Auth's sign-in/email endpoint can authenticate the new user.
   */
  test.describe('Register creates sign-in credential @smoke @auth @lock-auth-registration', () => {
    test('registered user can sign in immediately', async ({ request }) => {
      const unique = Date.now()
      const email = `regtest-${unique}@example.com`
      const password = `RegTest${unique}!`

      // Register via the form endpoint
      const regRes = await request.post('/auth/register/form', {
        form: {
          email,
          password,
          firstName: 'Reg',
          lastName: 'Test',
        },
      })
      // Register returns 200 or redirects
      expect([200, 302].includes(regRes.status())).toBeTruthy()

      // Now sign in via Better Auth — this requires the auth_account credential row
      const signIn = await request.post('/auth/sign-in/email', {
        data: { email, password },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
      expect(signIn.ok()).toBe(true)

      // Clean up
      await request.post('/auth/sign-out', {
        data: {},
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      })
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 15-user-xss-prevention.spec.ts", () => {
  // The admin user form no longer has `username` or `bio` fields, and the role <select> now holds
  // RBAC role ids (`role-viewer`) instead of bare role names. The payloads below therefore go into
  // the fields that still exist, and the escaping assertions run against the created user's edit
  // form — that is where stored values are rendered back into `value="…"` attributes (the users
  // list page renders no form holding user data).

  /** Pick the viewer role when it exists; the RBAC seed does not guarantee it. */
  async function selectLowPrivilegeRole(page: Page) {
    const roleSelect = page.locator('select[name="role"]');
    await expect(roleSelect).toBeVisible();
    const viewerOption = roleSelect.locator('option[value="role-viewer"]');
    if (await viewerOption.count()) {
      await roleSelect.selectOption('role-viewer');
    } else {
      await roleSelect.selectOption({ index: 0 });
    }
  }

  /** Open the edit form of the user just created and return its raw HTML. */
  async function createdUserFormHtml(page: Page, email: string): Promise<string> {
    await page.goto(`/admin/users?search=${encodeURIComponent(email)}`);
    // Rows are click-handled, not anchors: onclick="window.location.href='/admin/users/<id>/edit'".
    const row = page.locator('tbody tr[onclick]').first();
    await expect(row, `created user ${email} should appear in the users list`).toBeVisible();
    const onclick = (await row.getAttribute('onclick')) ?? '';
    const editUrl = onclick.match(/\/admin\/users\/[^']+\/edit/)?.[0];
    expect(editUrl, `no edit URL in row onclick: ${onclick}`).toBeTruthy();

    await page.goto(editUrl!);
    await expect(page.locator('form#user-edit-form input[name="first_name"]')).toBeVisible();
    const pageHtml = await page.content();
    const formSection = pageHtml.match(/<form[\s\S]*?<\/form>/gi)?.join('') || '';
    expect(formSection.length, 'user edit form should be present').toBeGreaterThan(0);
    return formSection;
  }

  test.describe('User XSS Prevention @auth', () => {
    test('should prevent XSS in user creation via API', async ({ page }) => {
      // Set up a flag to detect if any alert() is triggered
      let alertTriggered = false;
      page.on('dialog', async (dialog) => {
        alertTriggered = true;
        await dialog.dismiss();
      });

      // Login first
      await loginAsAdmin(page);

      // Navigate to user creation page
      await page.goto('/admin/users/new');

      // Fill form with XSS payloads
      const timestamp = Date.now();
      const xssPayloads = {
        firstName: '<script>alert("XSS")</script>',
        lastName: '"><img src=x onerror=alert("XSS")>',
        email: `xsstest${timestamp}@example.com`,
        phone: '<script>alert("phone")</script>',
      };

      await page.fill('input[name="first_name"]', xssPayloads.firstName);
      await page.fill('input[name="last_name"]', xssPayloads.lastName);
      await page.fill('input[name="email"]', xssPayloads.email);
      await page.fill('input[name="phone"]', xssPayloads.phone);
      await selectLowPrivilegeRole(page);
      await page.fill('input[name="password"]', 'SecurePassword123!');
      await page.fill('input[name="confirm_password"]', 'SecurePassword123!');

      // Submit the form (HTMX posts, then HX-Redirect sends us to the users list)
      await page.click('button[type="submit"]');
      await page.waitForURL((url) => url.pathname === '/admin/users');

      // Check if we're redirected to users list or edit page
      const currentUrl = page.url();
      expect(currentUrl).toContain('/admin/users');

      // CRITICAL: Verify no JavaScript execution occurred
      expect(alertTriggered).toBe(false);

      // Get the form HTML that renders the stored user data back to the browser
      const formSection = await createdUserFormHtml(page, xssPayloads.email);

      // Check for unescaped dangerous HTML in attribute values
      expect(formSection).not.toMatch(/value="[^"]*<script[^>]*>/i);
      expect(formSection).not.toMatch(/value="[^"]*<\/script>/i);
      expect(formSection).not.toMatch(/value="[^"]*"[^>]*onerror=/i);
      expect(formSection).not.toMatch(/value="[^"]*<img[^>]*onerror=/i);

      // Verify content IS properly escaped (contains HTML entities)
      expect(formSection).toMatch(/&(lt|gt|quot|amp);/);

      // Rendering the stored payloads must not execute anything either
      expect(alertTriggered).toBe(false);
    });


    test('should sanitize user data in database', async ({ page }) => {
      // Set up a flag to detect if any alert() is triggered
      let alertTriggered = false;
      page.on('dialog', async (dialog) => {
        alertTriggered = true;
        await dialog.dismiss();
      });

      // Login first
      await loginAsAdmin(page);

      // Navigate to user creation page
      await page.goto('/admin/users/new');

      // Create user with XSS payloads
      const timestamp = Date.now();
      const email = `xsstest_db_${timestamp}@example.com`;
      await page.fill('input[name="first_name"]', '<script>alert("test")</script>');
      // The iframe payload rides along with the last name now that the bio field is gone.
      await page.fill('input[name="last_name"]', `XSSTest${timestamp}<iframe src="javascript:alert('XSS')">`);
      await page.fill('input[name="email"]', email);
      await page.fill('input[name="phone"]', '"><img src=x onerror=alert(1)>');
      await selectLowPrivilegeRole(page);
      await page.fill('input[name="password"]', 'SecurePassword123!');
      await page.fill('input[name="confirm_password"]', 'SecurePassword123!');

      // Submit the form
      await page.click('button[type="submit"]');
      await page.waitForURL((url) => url.pathname === '/admin/users');

      // Verify user was created and redirected
      const currentUrl = page.url();
      expect(currentUrl).toContain('/admin/users');

      // CRITICAL: Verify no JavaScript execution occurred
      expect(alertTriggered).toBe(false);

      // Read back what the server stored and re-rendered
      const formSection = await createdUserFormHtml(page, email);

      // Check for unescaped dangerous HTML in attribute values
      expect(formSection).not.toMatch(/value="[^"]*<script[^>]*>/i);
      expect(formSection).not.toMatch(/value="[^"]*<\/script>/i);
      expect(formSection).not.toMatch(/value="[^"]*"[^>]*onerror=/i);
      expect(formSection).not.toMatch(/value="[^"]*<img[^>]*onerror=/i);
      expect(formSection).not.toMatch(/value="[^"]*<iframe[^>]*src=["']javascript:/i);

      // Verify content IS properly escaped (contains HTML entities)
      expect(formSection).toMatch(/&(lt|gt|quot|amp);/);

      expect(alertTriggered).toBe(false);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 16-user-management.spec.ts", () => {
  test.describe('User Management - Hard Delete @auth @lock-auth-login @lock-auth-registration', () => {
    let authToken: string;

    test.beforeAll(async ({ request }) => {
      // `requestLoginToken`, not a bare POST: /auth/login is rate limited to 30/min per IP and the
      // whole suite shares one IP. The `@lock-auth-login` tag serialises the *tests* that drain that
      // bucket, but this is a beforeAll hook — it runs before any test's fixtures are set up, so the
      // lock does not cover it. A 429 here used to leave `authToken` undefined and every test below
      // failed on its DELETE with a bare `expect(deleteResponse.ok()).toBeTruthy()` → false, which
      // pointed at the wrong endpoint entirely.
      authToken = await requestLoginToken(request, ADMIN_CREDENTIALS);
    });

    test('should soft delete a user via API (deactivate)', async ({ request }) => {
      // Create a test user
      const timestamp = Date.now();
      const testEmail = `softdelete${timestamp}@example.com`;
      const testUsername = `softdelete${timestamp}`;

      const registerResponse = await request.post('/auth/register', {
        data: {
          email: testEmail,
          username: testUsername,
          password: 'TestPassword123!',
          firstName: 'Soft',
          lastName: 'Delete'
        }
      });

      expect(registerResponse.ok()).toBeTruthy();
      const userData = await registerResponse.json();
      const userId = userData.user?.id;
      expect(userId).toBeDefined();

      // Soft delete the user (hardDelete: false)
      const deleteResponse = await request.delete(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        data: {
          hardDelete: false
        }
      });

      expect(deleteResponse.ok()).toBeTruthy();
      const deleteData = await deleteResponse.json();
      expect(deleteData.success).toBe(true);
      expect(deleteData.message).toContain('deactivated');

      // Verify user still exists but is inactive
      const checkResponse = await request.get(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      // Debug: log the response if it's not OK
      if (!checkResponse.ok()) {
        console.error('GET user request details:');
        console.error('  URL:', `/admin/users/${userId}`);
        console.error('  Status:', checkResponse.status());
        console.error('  Status Text:', checkResponse.statusText());
        try {
          const errorData = await checkResponse.json();
          console.error('  Response:', JSON.stringify(errorData));
        } catch (e) {
          const responseText = await checkResponse.text();
          console.error('  Response (text):', responseText.substring(0, 500));
        }
      }

      expect(checkResponse.ok()).toBeTruthy();

      const checkData = await checkResponse.json();
      expect(checkData.user).toBeDefined();
      expect(checkData.user.is_active).toBe(0);
    });

    test('should hard delete a user via API (permanent deletion)', async ({ request }) => {
      // Create a test user
      const timestamp = Date.now();
      const testEmail = `harddelete${timestamp}@example.com`;
      const testUsername = `harddelete${timestamp}`;

      const registerResponse = await request.post('/auth/register', {
        data: {
          email: testEmail,
          username: testUsername,
          password: 'TestPassword123!',
          firstName: 'Hard',
          lastName: 'Delete'
        }
      });

      expect(registerResponse.ok()).toBeTruthy();
      const userData = await registerResponse.json();
      const userId = userData.user?.id;
      expect(userId).toBeDefined();

      // Hard delete the user (hardDelete: true)
      const deleteResponse = await request.delete(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        data: {
          hardDelete: true
        }
      });

      expect(deleteResponse.ok()).toBeTruthy();
      const deleteData = await deleteResponse.json();
      expect(deleteData.success).toBe(true);
      expect(deleteData.message).toContain('permanently');

      // Verify user no longer exists
      const checkResponse = await request.get(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });
      expect(checkResponse.status()).toBe(404);
    });

    test('should default to soft delete when hardDelete is not specified', async ({ request }) => {
      // Create a test user
      const timestamp = Date.now();
      const testEmail = `defaultdelete${timestamp}@example.com`;
      const testUsername = `defaultdelete${timestamp}`;

      const registerResponse = await request.post('/auth/register', {
        data: {
          email: testEmail,
          username: testUsername,
          password: 'TestPassword123!',
          firstName: 'Default',
          lastName: 'Delete'
        }
      });

      expect(registerResponse.ok()).toBeTruthy();
      const userData = await registerResponse.json();
      const userId = userData.user?.id;
      expect(userId).toBeDefined();

      // Delete without specifying hardDelete (should default to soft delete)
      const deleteResponse = await request.delete(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      expect(deleteResponse.ok()).toBeTruthy();
      const deleteData = await deleteResponse.json();
      expect(deleteData.success).toBe(true);

      // Verify user still exists but is inactive
      const checkResponse = await request.get(`/admin/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      // Debug: log the response if it's not OK
      if (!checkResponse.ok()) {
        const errorData = await checkResponse.json();
        console.error('GET user failed (default delete):', checkResponse.status(), errorData);
      }

      expect(checkResponse.ok()).toBeTruthy();

      const checkData = await checkResponse.json();
      expect(checkData.user).toBeDefined();
      expect(checkData.user.is_active).toBe(0);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 27-profile-picture-upload.spec.ts", () => {
  test.describe('Profile Picture Upload @media @auth', () => {
    test('should update profile picture and display it immediately', async ({ page }) => {
      // Login as admin
      await loginAsAdmin(page);

      // Navigate to profile page
      await page.goto('/admin/profile');
      await page.waitForLoadState('networkidle');

      // Verify profile page loaded
      await expect(page.locator('h1')).toContainText('User Profile');

      // Get initial avatar state (check if there's an image or initials)
      const avatarContainer = page.locator('#avatar-image-container');
      await expect(avatarContainer).toBeVisible();

      // Create a test image buffer (1x1 pixel JPEG)
      const testImageBuffer = Buffer.from([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
        0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
        0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
        0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
      ]);

      const uniqueFilename = `profile-avatar-${Date.now()}.jpg`;

      // Upload avatar by setting the file input
      // The form will auto-submit on file selection
      await page.setInputFiles('#avatar-input', {
        name: uniqueFilename,
        mimeType: 'image/jpeg',
        buffer: testImageBuffer
      });

      // Wait for HTMX to complete the upload and update the DOM
      await page.waitForTimeout(2000);

      // Verify success message appears
      await expect(page.locator('#avatar-messages')).toContainText('Profile picture updated successfully', { timeout: 5000 });

      // Verify the avatar image was updated
      // The avatar should now contain an img tag instead of initials
      const avatarImage = avatarContainer.locator('img');
      await expect(avatarImage).toBeVisible({ timeout: 5000 });

      // Verify the image src contains the avatar URL pattern
      const imgSrc = await avatarImage.getAttribute('src');
      expect(imgSrc).toBeTruthy();
      expect(imgSrc).toContain('/uploads/avatars/');

      // Verify the image src has a cache-busting timestamp parameter
      expect(imgSrc).toMatch(/\?t=\d+/);
    });

    test('should validate file type on upload', async ({ page }) => {
      // Login as admin
      await loginAsAdmin(page);

      // Navigate to profile page
      await page.goto('/admin/profile');
      await page.waitForLoadState('networkidle');

      // Try to upload a text file instead of an image
      const textBuffer = Buffer.from('This is not an image file');

      await page.setInputFiles('#avatar-input', {
        name: 'invalid-file.txt',
        mimeType: 'text/plain',
        buffer: textBuffer
      });

      // Wait for response
      await page.waitForTimeout(2000);

      // Verify error message appears
      await expect(page.locator('#avatar-messages')).toContainText('valid image file', { timeout: 5000 });
    });

    test('should handle large file size validation', async ({ page }) => {
      // Login as admin
      await loginAsAdmin(page);

      // Navigate to profile page
      await page.goto('/admin/profile');
      await page.waitForLoadState('networkidle');

      // Create a buffer larger than 5MB (5 * 1024 * 1024 bytes)
      const largeBuffer = Buffer.alloc(6 * 1024 * 1024, 0xFF);

      await page.setInputFiles('#avatar-input', {
        name: 'large-image.jpg',
        mimeType: 'image/jpeg',
        buffer: largeBuffer
      });

      // Wait for response
      await page.waitForTimeout(2000);

      // Verify error message appears about file size
      await expect(page.locator('#avatar-messages')).toContainText('smaller than 5MB', { timeout: 5000 });
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 78-author-user-search.spec.ts", () => {
  test.describe('Author user-search field @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('user search API returns results for known user', async ({ page }) => {
      const res = await page.request.get('/admin/api/users/search?q=admin')
      expect(res.status()).toBe(200)
      const json = await res.json()
      expect(json).toHaveProperty('users')
      expect(Array.isArray(json.users)).toBe(true)
      if (json.users.length > 0) {
        const user = json.users[0]
        expect(user).toHaveProperty('id')
        expect(user).toHaveProperty('name')
        expect(user).toHaveProperty('email')
      }
    })

    test('user search API returns empty array for empty query', async ({ page }) => {
      const res = await page.request.get('/admin/api/users/search?q=')
      expect(res.status()).toBe(200)
      const json = await res.json()
      expect(json.users).toEqual([])
    })

    test('blog post create form renders author field with autocomplete', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForLoadState('networkidle')

      const authorDisplay = page.locator('#field-author-display')
      await expect(authorDisplay).toBeVisible()
      await expect(authorDisplay).toHaveAttribute('autocomplete', 'off')

      const authorHidden = page.locator('#field-author')
      await expect(authorHidden).toHaveCount(1)
    })

    test('user by ID endpoint returns display name', async ({ page }) => {
      const adminRes = await page.request.get('/admin/api/users/search?q=admin')
      const { users } = await adminRes.json()
      const adminId = users[0]?.id
      expect(adminId).toBeTruthy()

      const res = await page.request.get(`/admin/api/users/${adminId}`)
      expect(res.status()).toBe(200)
      const json = await res.json()
      expect(json.name).toBeTruthy()
      expect(json.id).toBe(adminId)
    })

    test('user search HTML endpoint returns results for admin', async ({ page }) => {
      // Verify the search-html endpoint returns button HTML (used by HTMX dropdown)
      const res = await page.request.get('/admin/api/users/search-html?fieldId=field-author&q=admin')
      expect(res.status()).toBe(200)
      const html = await res.text()
      expect(html).toContain('Admin')
      expect(html).toContain('admin@sonicjs.com')
      expect(html).toContain('sonicSelectUser')
    })

    test('custom author name syncs to hidden input on form submit', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForLoadState('networkidle')

      const authorDisplay = page.locator('#field-author-display')
      const authorHidden = page.locator('#field-author')

      await authorDisplay.fill('Guest Writer')

      // Simulate the submit event to trigger the sync listener
      await page.evaluate(() => {
        const form = document.querySelector('form')
        if (form) form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      })

      await expect(authorHidden).toHaveValue('Guest Writer')
    })

    test('typing in author field shows user dropdown', async ({ page }) => {
      await page.goto('/admin/content/new?collection=blog_post')
      await page.waitForLoadState('networkidle')

      // Confirm HTMX is loaded
      const htmxLoaded = await page.evaluate(() => typeof (window as any).htmx !== 'undefined')
      expect(htmxLoaded).toBe(true)

      // Use htmx.ajax() directly to populate the dropdown, then verify the interaction
      await page.evaluate(() => {
        ;(window as any).htmx.ajax(
          'GET',
          '/admin/api/users/search-html?fieldId=field-author&q=admin',
          { target: '#field-author-dropdown', swap: 'innerHTML' }
        )
      })

      const dropdown = page.locator('#field-author-dropdown')
      await expect(dropdown.locator('button').first()).toBeVisible({ timeout: 5000 })
      await expect(dropdown.locator('button').first()).toContainText('Admin')

      // Click the result — sonicSelectUser should populate the hidden input
      await dropdown.locator('button').first().click()

      const authorHidden = page.locator('#field-author')
      const hiddenValue = await authorHidden.inputValue()
      expect(hiddenValue).toBeTruthy()
      expect(hiddenValue).not.toBe('')

      // Display field should show user name
      const authorDisplay = page.locator('#field-author-display')
      await expect(authorDisplay).toHaveValue(/Admin/)
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 80-user-profile-code-config.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

  // User profile fields are a CODE-DEFINED data model (defineUserProfile() in the
  // app entry point), not editable through the admin UI. Until the developer calls
  // defineUserProfile(), the "Profile Information" section stays hidden on the user
  // create/edit pages, and the plugin detail page explains where to define fields.
  //
  // The default app entry (my-sonicjs-app/src/index.ts) does NOT call
  // defineUserProfile(), so these tests assert the "unconfigured" state.
  test.describe('User Profiles — code-defined config @auth', () => {
    test.beforeEach(async ({ page }) => {
      await ensureAdminUserExists(page)
      await loginAsAdmin(page)
    })

    test('plugin detail page explains where to define fields in code', async ({ page }) => {
      // A fresh deploy has no `plugins` row for user-profiles, and an uninstalled plugin
      // renders the Info tab only — the guidance panel lives behind the Settings tab.
      // Install first (no-op once installed) so the panel is on the page.
      await page.request
        .post(`${BASE_URL}/admin/plugins/install`, { data: { name: 'user-profiles' } })
        .catch(() => {})

      const resp = await page.goto(`${BASE_URL}/admin/plugins/user-profiles`)
      await page.waitForLoadState('networkidle')

      expect(resp?.status()).not.toBe(404)
      expect(resp?.status()).not.toBe(500)

      const body = (await page.locator('body').textContent()) || ''

      // Points the developer at the code-defined data model.
      expect(body).toContain('defineUserProfile')
      expect(body).toContain('my-sonicjs-app/src/index.ts')

      // Explains the section is hidden until fields are defined.
      expect(body.toLowerCase()).toContain('profile information')
      expect(body).toContain('No profile fields defined yet')
    })

    test('user edit page hides Profile Information when no fields are defined', async ({ page }) => {
      // Grab the current admin user id from the users list.
      await page.goto(`${BASE_URL}/admin/users`)
      await page.waitForLoadState('networkidle')

      // Rows navigate via `onclick`, not an anchor — an <a href$="/edit"> locator finds nothing.
      const row = page.locator('tr[onclick*="/admin/users/"]').first()
      await expect(row).toBeVisible({ timeout: 10000 })
      const onclick = await row.getAttribute('onclick')
      const href = onclick?.match(/'(\/admin\/users\/[^']+\/edit)'/)?.[1]
      expect(href).toBeTruthy()

      await page.goto(`${BASE_URL}${href}`)
      await page.waitForLoadState('networkidle')

      // Basic Information always present; Profile Information only when configured.
      const body = (await page.locator('body').textContent()) || ''
      expect(body).toContain('Basic Information')
      expect(body).not.toContain('Profile Information')
      // The old hard-coded "edit the template" hint must be gone.
      expect(body).not.toContain('admin-user-edit.template.ts')

      // No display-name / custom profile inputs rendered.
      await expect(page.locator('input[name="profile_display_name"]')).toHaveCount(0)
    })

    test('new user page hides Profile Information when no fields are defined', async ({ page }) => {
      await page.goto(`${BASE_URL}/admin/users/new`)
      await page.waitForLoadState('networkidle')

      const body = (await page.locator('body').textContent()) || ''
      expect(body).toContain('Basic Information')
      expect(body).not.toContain('Profile Information')

      // No registration profile inputs (custom_* fields) rendered.
      await expect(page.locator('input[name^="custom_"]')).toHaveCount(0)
    })
  })
})

// Roles chosen in the admin Users screen are real RBAC roles, and saving a user never promotes them.
test.describe('Admin user roles @auth @lock-auth-registration', () => {
  const signIn = async (playwright: any, email: string, password: string) => {
    const ctx = await playwright.request.newContext({ baseURL: TEST_ORIGIN, extraHTTPHeaders: { Origin: TEST_ORIGIN } })
    expect((await ctx.post('/auth/sign-in/email', { data: { email, password } })).ok()).toBeTruthy()
    return ctx
  }

  test('an editor created in the Users screen can use the admin', async ({ page, playwright }) => {
    await loginAsAdmin(page)
    const email = `roles-editor-${Date.now()}@example.com`
    const password = `RolesEditor${Date.now()}!`
    await page.goto('/admin/users/new')
    const form = page.locator('#user-new-form')
    await form.locator('input[name="first_name"]').fill('Role')
    await form.locator('input[name="last_name"]').fill('Editor')
    await form.locator('input[name="email"]').fill(email)
    await form.locator('select[name="role"]').selectOption('role-editor')
    await form.locator('input[name="password"]').fill(password)
    await form.locator('input[name="confirm_password"]').fill(password)
    await form.locator('input[name="email_verified"]').check()
    await submitAndWaitForXhr(page, 'POST', '/admin/users/new', () =>
      page.locator('button[form="user-new-form"]').click()
    )
    await expect(page).toHaveURL(/\/admin\/users\?success=/)

    const editor = await signIn(playwright, email, password)
    expect((await (await editor.get('/auth/get-session')).json()).user.role).toBe('editor')
    expect((await editor.get('/admin/content', { maxRedirects: 0 })).status()).toBe(200)
    await editor.dispose()
  })

  test('saving a user who is not an admin does not make them one', async ({ page, playwright }) => {
    const email = `roles-member-${Date.now()}@example.com`
    const password = `RolesMember${Date.now()}!`
    const anon = await playwright.request.newContext({ baseURL: TEST_ORIGIN, extraHTTPHeaders: { Origin: TEST_ORIGIN } })
    const signUp = await anon.post('/auth/sign-up/email', { data: { email, password, name: 'Role Member' } })
    expect(signUp.ok()).toBeTruthy()
    const userId = (await signUp.json()).user.id
    await anon.dispose()

    await loginAsAdmin(page)
    await page.goto(`/admin/users/${userId}/edit`)
    await expect(page.locator('#user-edit-form select[name="role"]')).not.toHaveValue('role-admin')
    await page.fill('input[name="phone"]', '555-0100')
    await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
      page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    )
    // A rejected save would also leave the role unchanged, so prove this one landed.
    await expect(page.locator('#form-messages')).toContainText('User updated successfully')
    await page.reload()
    await expect(page.locator('#user-edit-form input[name="phone"]')).toHaveValue('555-0100')

    const member = await signIn(playwright, email, password)
    expect(['admin', 'role-admin']).not.toContain((await (await member.get('/auth/get-session')).json()).user.role)
    await member.dispose()
  })

  test('a custom role that may read blog posts can read them through /api/documents', async ({ page, playwright }) => {
    const unique = Date.now()
    const roleId = `role-reader${unique}`
    const email = `roles-reader-${unique}@example.com`
    const password = `RolesReader${unique}!`
    const anon = await playwright.request.newContext({ baseURL: TEST_ORIGIN, extraHTTPHeaders: { Origin: TEST_ORIGIN } })
    const signUp = await anon.post('/auth/sign-up/email', { data: { email, password, name: 'Role Reader' } })
    expect(signUp.ok()).toBeTruthy()
    const userId = (await signUp.json()).user.id

    await loginAsAdmin(page)
    const headers = { 'X-CSRF-Token': (await getCsrfTokenFromPage(page)) ?? '' }
    const role = await page.request.post('/admin/rbac/roles', { headers, form: { name: `reader${unique}`, display_name: `Reader ${unique}` } })
    expect(role.ok(), await role.text()).toBeTruthy()
    const grant = await page.request.post('/admin/rbac/grants', { headers, form: { save_roles: roleId, [`g|${roleId}|document_type:blog_post|read`]: 'any' } })
    expect(grant.ok(), await grant.text()).toBeTruthy()
    const created = await page.request.post('/api/content', {
      headers,
      data: { collectionId: 'blog_post', title: `Reader post ${unique}`, slug: `reader-post-${unique}`, status: 'published', data: { content: 'x' } },
    })
    expect(created.ok(), await created.text()).toBeTruthy()
    const rootId = (await created.json()).data.id

    await page.goto(`/admin/users/${userId}/edit`)
    await page.locator('#user-edit-form select[name="role"]').selectOption(roleId)
    await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
      page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    )
    await expect(page.locator('#form-messages')).toContainText('User updated successfully')

    // Visitors can read it, so a signed-in reader must too.
    expect((await anon.get(`/api/documents/root/${rootId}`)).status()).toBe(200)
    const reader = await signIn(playwright, email, password)
    expect((await (await reader.get('/auth/get-session')).json()).user.role).toBe(roleId)
    expect((await reader.get(`/api/documents/root/${rootId}`)).status()).toBe(200)
    const list = await (await reader.get('/api/documents?type=blog_post&limit=200')).json()
    expect(list.data.map((d: any) => d.rootId)).toContain(rootId)
    await reader.dispose()
    await anon.dispose()
  })
})
