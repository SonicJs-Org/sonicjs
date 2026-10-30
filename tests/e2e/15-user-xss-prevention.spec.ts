import { test, expect, type Page } from './fixtures';
import { loginAsAdmin } from './utils/test-helpers';

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
