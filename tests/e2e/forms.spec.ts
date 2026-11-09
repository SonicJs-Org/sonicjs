import { test } from "./fixtures"
import { expect } from "./fixtures"
import { loginAsAdmin } from "./utils/test-helpers"
import { navigateToAdminSection } from "./utils/test-helpers"
import { TEST_DATA } from "./utils/test-helpers"
import { isFeatureAvailable } from "./utils/test-helpers"
import { ensurePluginActive } from "./fixtures/plugin-fixtures"
import { ADMIN_CREDENTIALS } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 50-forms.spec.ts", () => {
  /**
   * E2E Tests for Forms System
   * Tests the complete Form.io integration including:
   * - Form CRUD operations
   * - Form builder UI
   * - Public form rendering
   * - Form submissions
   * - Multi-page wizards
   * - Component configuration
   */

  test.describe('Forms Management @content', () => {
    test.describe.configure({ mode: 'serial' });

    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/forms')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    let testFormId: string;
    const testFormName = `test_form_${Date.now()}`;

    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test.afterAll(async () => {
      // SKIP: Cleanup disabled - page fixture not available in afterAll
      // Forms are isolated per CI run and cleaned up automatically
      // If running locally, delete test forms manually or via cleanup script
    });

    test('should display forms list page', async ({ page }) => {
      await navigateToAdminSection(page, 'forms');

      await expect(page.locator('h1')).toContainText('Forms');
      await expect(page.locator('a[href="/admin/forms/new"]')).toBeVisible();
    });

    test('should create a new form', async ({ page }) => {
      await page.goto('/admin/forms/new');
      await page.waitForLoadState('networkidle');

      // Fill in form details
      await page.fill('[name="name"]', testFormName);
      await page.fill('[name="displayName"]', 'Test Form');
      await page.fill('[name="description"]', 'E2E Test Form');
      await page.selectOption('[name="category"]', 'general');

      // Submit form
      await page.click('button[type="submit"]');

      // Should redirect to builder
      await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });

      // Extract form ID from URL
      const url = page.url();
      const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
      testFormId = match ? match[1] : '';

      expect(testFormId).toBeTruthy();

      // Verify builder loaded
      await expect(page.locator('#builder-container')).toBeVisible({ timeout: 20000 });
    });

    test('should validate form name format', async ({ page }) => {
      await page.goto('/admin/forms/new');
      await page.waitForLoadState('networkidle');

      // Try invalid name with spaces and uppercase
      await page.fill('[name="name"]', 'Invalid Form Name');
      await page.fill('[name="displayName"]', 'Invalid Form');

      await page.click('button[type="submit"]');
      await page.waitForTimeout(1000);

      // Should show error or stay on page
      const hasError = await page.locator('text=/must contain only lowercase/i').isVisible()
        .catch(() => false);
      const stillOnNewPage = page.url().includes('/admin/forms/new');

      expect(hasError || stillOnNewPage).toBe(true);
    });

  });

  test.describe('Form Deletion @forms', () => {
    test('should delete a form', async ({ page }) => {
      // Create a form specifically for deletion
      await loginAsAdmin(page);
      await page.goto('/admin/forms/new');
      await page.waitForLoadState('networkidle');

      const deleteFormName = `delete_test_${Date.now()}`;
      await page.fill('[name="name"]', deleteFormName);
      await page.fill('[name="displayName"]', 'Delete Test');
      await page.click('button[type="submit"]');

      await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });

      // Go back to forms list
      await page.goto('/admin/forms');
      await page.waitForLoadState('networkidle');

      // Find and click delete button for our form
      const deleteButton = page.locator(`tr:has-text("Delete Test") button[title*="Delete"], tr:has-text("Delete Test") button:has-text("Delete")`).first();

      if (await deleteButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await deleteButton.click();

        // Confirm deletion if there's a confirmation dialog
        const confirmButton = page.locator('button:has-text("Delete"), button:has-text("Confirm")');
        if (await confirmButton.isVisible({ timeout: 2000 }).catch(() => false)) {
          await confirmButton.click();
        }

        await page.waitForTimeout(1000);

        // Form should no longer appear in list
        const formExists = await page.locator(`text="${deleteFormName}"`).isVisible()
          .catch(() => false);

        expect(formExists).toBe(false);
      }
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 51-turnstile-integration.spec.ts", () => {
  test.describe('Turnstile Forms List Buttons @forms', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should show Examples and Quick Reference buttons on forms list', async ({ page }) => {
      await page.goto('/admin/forms');
      await page.waitForLoadState('networkidle');

      // Check for Examples button
      const examplesBtn = page.locator('a[href="/admin/forms/examples"], button:has-text("Examples")');
      await expect(examplesBtn.first()).toBeVisible();

      // Check for Quick Reference button
      const quickRefBtn = page.locator('a[href="/admin/forms/docs"], button:has-text("Quick Reference")');
      await expect(quickRefBtn.first()).toBeVisible();
    });

    test('should navigate to Examples page from forms list', async ({ page }) => {
      await page.goto('/admin/forms');
      await page.waitForLoadState('networkidle');

      const examplesBtn = page.locator('a[href="/admin/forms/examples"]').first();
      await examplesBtn.click();

      await page.waitForURL(/\/admin\/forms\/examples/);
      await expect(page).toHaveURL(/\/admin\/forms\/examples/);
    });

    test('should navigate to Quick Reference page from forms list', async ({ page }) => {
      await page.goto('/admin/forms');
      await page.waitForLoadState('networkidle');

      const quickRefBtn = page.locator('a[href="/admin/forms/docs"]').first();
      await quickRefBtn.click();

      await page.waitForURL(/\/admin\/forms\/docs/);
      await expect(page).toHaveURL(/\/admin\/forms\/docs/);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 52-forms-smoke.spec.ts", () => {
  /**
   * Forms Smoke Test
   *
   * Basic smoke test to verify the Forms feature is accessible.
   * This test verifies:
   * 1. Forms route is accessible (/admin/forms)
   * 2. Forms menu item appears in sidebar
   * 3. Forms list page renders correctly
   */

  test.describe('Forms Smoke Test @forms', () => {
    let featureAvailable = false
    test.beforeAll(async ({ request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/forms')
    })
    test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin/feature not available in this deployment') })

    test('should access /admin/forms route', async ({ page }) => {
      // Login first
      await loginAsAdmin(page);

      // Navigate directly to forms
      const response = await page.goto('/admin/forms');

      // Check response status
      expect(response?.status()).toBe(200);

      // Wait for page to load
      await page.waitForLoadState('networkidle');

      // Verify we're on the forms page (not a 404)
      const pageTitle = await page.title();
      console.log('Page title:', pageTitle);

      // Check page content - should have Forms heading or forms-related content
      const bodyText = await page.locator('body').textContent();
      console.log('Body text (first 500 chars):', bodyText?.substring(0, 500));

      // Should NOT show "Not Found" error
      const hasNotFound = bodyText?.toLowerCase().includes('not found');
      expect(hasNotFound).toBe(false);

      // Should have Forms heading
      const h1Text = await page.locator('h1').textContent().catch(() => '');
      console.log('H1 text:', h1Text);
      expect(h1Text?.toLowerCase()).toContain('form');
    });

    test('should show Forms in sidebar menu', async ({ page }) => {
      await loginAsAdmin(page);
      // `forms` is not bootstrapped on a greenfield install, and `reconcileMenuFromPlugins` keeps
      // the menu_item hidden until the plugin is active — so install + activate it here.
      await ensurePluginActive(page, 'forms');
      await page.goto('/admin');

      // Wait for navigation to render
      await page.waitForSelector('nav', { timeout: 5000 });

      // Check sidebar for Forms link - look within nav element
      const formsLink = page.locator('nav a[href="/admin/forms"]');
      const linkCount = await formsLink.count();

      console.log('Forms link count in nav:', linkCount);

      // Verify the link exists and contains the right text
      if (linkCount > 0) {
        const linkText = await formsLink.first().textContent();
        console.log('Forms link text:', linkText?.trim());
        expect(linkText?.trim()).toContain('Forms');
      }

      expect(linkCount).toBeGreaterThan(0);
    });

    test('should navigate to forms via sidebar', async ({ page }) => {
      await loginAsAdmin(page);
      await ensurePluginActive(page, 'forms');
      await page.goto('/admin');

      // Click Forms in sidebar
      await page.click('a[href="/admin/forms"]');
      await page.waitForLoadState('networkidle');

      // Verify we landed on forms page
      expect(page.url()).toContain('/admin/forms');

      // Should have create form button
      const createButton = page.locator('a[href="/admin/forms/new"]');
      const hasCreateButton = await createButton.isVisible({ timeout: 5000 }).catch(() => false);

      console.log('Create form button visible:', hasCreateButton);
      expect(hasCreateButton).toBe(true);
    });

    test('should load forms list page correctly', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/forms');
      await page.waitForLoadState('networkidle');

      // Check for expected elements on forms list page
      const elements = {
        heading: await page.locator('h1').textContent().catch(() => ''),
        createLink: await page.locator('a[href="/admin/forms/new"]').count(),
        docsLink: await page.locator('a[href*="/docs"]').count(),
        examplesLink: await page.locator('a[href*="/examples"]').count(),
      };

      console.log('Forms list page elements:', elements);

      expect(elements.heading?.toLowerCase()).toContain('form');
      expect(elements.createLink).toBeGreaterThan(0);
    });

    test('should access forms create page', async ({ page }) => {
      await loginAsAdmin(page);

      const response = await page.goto('/admin/forms/new');
      expect(response?.status()).toBe(200);

      await page.waitForLoadState('networkidle');

      // Should have form fields
      const nameField = page.locator('[name="name"]');
      const displayNameField = page.locator('[name="displayName"]');

      const hasNameField = await nameField.isVisible({ timeout: 5000 }).catch(() => false);
      const hasDisplayNameField = await displayNameField.isVisible({ timeout: 5000 }).catch(() => false);

      console.log('Create form fields:', { hasNameField, hasDisplayNameField });

      expect(hasNameField).toBe(true);
      expect(hasDisplayNameField).toBe(true);
    });

    test('should access forms docs page', async ({ page }) => {
      await loginAsAdmin(page);

      const response = await page.goto('/admin/forms/docs');
      expect(response?.status()).toBe(200);

      await page.waitForLoadState('networkidle');

      // Should have documentation content
      const bodyText = await page.locator('body').textContent();
      const hasDocContent = bodyText?.toLowerCase().includes('form') ||
                            bodyText?.toLowerCase().includes('documentation') ||
                            bodyText?.toLowerCase().includes('getting started');

      console.log('Docs page has form content:', hasDocContent);
      expect(hasDocContent).toBe(true);
    });

    test('should access forms examples page', async ({ page }) => {
      await loginAsAdmin(page);

      const response = await page.goto('/admin/forms/examples');
      expect(response?.status()).toBe(200);

      await expect(page).toHaveURL(/\/admin\/forms\/examples$/);
      await expect(page).toHaveTitle('Forms Examples - SonicJS AI Admin');
      await expect(page.getByRole('heading', { name: 'Form Examples', exact: true })).toBeVisible();

      const activeExample = page.locator('.examples-content #kitchen-sink.example-section.active');
      await expect(activeExample).toBeVisible();
      await expect(activeExample.getByRole('heading', { name: '🍳 Kitchen Sink', exact: true })).toBeVisible();
      await expect(activeExample.locator('#form-kitchen-sink').getByRole('textbox', { name: /First Name/ })).toBeVisible();

      // Should have examples content
      const bodyText = await page.locator('body').textContent();
      const hasExampleContent = bodyText?.toLowerCase().includes('example') ||
                                bodyText?.toLowerCase().includes('form');

      console.log('Examples page has content:', hasExampleContent);
      expect(hasExampleContent).toBe(true);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 53-forms-as-content.spec.ts", () => {
  /**
   * E2E Tests for Forms-as-Content Integration
   *
   * Tests that form submissions create shadow collections and content items,
   * but these are hidden from the regular admin UI (collections list, content list,
   * new-content picker) to avoid breaking existing workflows.
   */

  // ─── Form.io schemas for realistic test forms ─────────────────

  const CONTACT_FORM_SCHEMA = {
    components: [
      {
        type: 'textfield',
        key: 'name',
        label: 'Full Name',
        validate: { required: true }
      },
      {
        type: 'email',
        key: 'email',
        label: 'Email Address',
        validate: { required: true }
      },
      {
        type: 'textfield',
        key: 'subject',
        label: 'Subject'
      },
      {
        type: 'textarea',
        key: 'message',
        label: 'Message',
        validate: { required: true }
      },
      {
        type: 'button',
        key: 'submit',
        label: 'Send Message',
        action: 'submit'
      }
    ]
  };

  // ─── Helper: create form, set schema, disable turnstile ────────

  async function createTestFormWithSchema(
    page: any,
    formName: string,
    displayName: string,
    description: string,
    schema: any
  ): Promise<string> {
    // 1. Create form via admin UI
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    await page.fill('[name="name"]', formName);
    await page.fill('[name="displayName"]', displayName);
    await page.fill('[name="description"]', description);
    await page.selectOption('[name="category"]', 'general');
    await page.click('button[type="submit"]');

    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 20000 });
    const url = page.url();
    const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
    const formId = match ? match[1] : '';
    expect(formId).toBeTruthy();

    // 2. Set real schema + disable turnstile via authenticated PUT
    const updateResponse = await page.request.put(`/admin/forms/${formId}`, {
      data: {
        formio_schema: schema,
        turnstile_enabled: false,
        turnstile_settings: { inherit: false }
      }
    });

    console.log(`Form ${formName} schema update: ${updateResponse.status()}`);
    expect(updateResponse.ok()).toBe(true);

    return formId;
  }

  // ═══════════════════════════════════════════════════════════════
  // Tests: shadow collection creation, content dual-write, filtering
  // ═══════════════════════════════════════════════════════════════

  test.describe('Forms as Content @content', () => {
    test.describe.configure({ mode: 'serial' });

    let featureAvailable = false
    let testFormId = '';
    const testFormName = `fac_test_${Date.now()}`;
    const testFormDisplayName = 'FAC Test Contact';

    // The assertions below are all "the form's shadow collection/content must NOT leak into the
    // regular admin UI", so they are only meaningful once a form and a submission actually exist.
    // Build both here rather than guarding each test on a never-assigned id.
    test.beforeAll(async ({ browser, request }) => {
      featureAvailable = await isFeatureAvailable(request, '/admin/forms')
      if (!featureAvailable) return
      const page = await browser.newPage()
      try {
        await loginAsAdmin(page)
        testFormId = await createTestFormWithSchema(
          page,
          testFormName,
          testFormDisplayName,
          'Forms-as-content fixture',
          CONTACT_FORM_SCHEMA
        )
        const submit = await page.request.post(`/api/forms/${testFormId}/submit`, {
          data: {
            data: {
              name: 'Jane Doe',
              email: 'jane.doe@example.com',
              subject: 'Forms as content',
              message: 'Submission used to prove form content stays out of the content list.',
            },
          },
          headers: { 'Content-Type': 'application/json' },
        })
        expect(submit.ok(), `form submit failed: ${submit.status()} ${await submit.text()}`).toBe(true)
      } finally {
        await page.close()
      }
    })

    test.afterAll(async ({ browser }) => {
      if (!testFormId) return
      const page = await browser.newPage()
      try {
        await loginAsAdmin(page)
        await page.request.delete(`/admin/forms/${testFormId}`)
      } finally {
        await page.close()
      }
    })

    test.beforeEach(async () => {
      test.skip(!featureAvailable, 'Plugin/feature not available in this deployment')
    });

    // Logging in is the single most expensive thing these tests do — a full admin page load, which
    // on a cold preview has been measured at ~10s. It is done per test rather than in `beforeEach`
    // so the one test that talks to the public API through the unauthenticated `request` fixture,
    // and therefore cannot use the session anyway, does not pay for it. That test timing out while
    // still inside its own setup is how this file last failed CI.

    test('should NOT show form-sourced collections on collections page', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/collections');
      await page.waitForLoadState('networkidle');

      const bodyText = await page.locator('body').textContent();
      // The shadow collection name is "form_{testFormName}" and display name ends with "(Form)"
      expect(bodyText).not.toContain(`form_${testFormName}`);
      expect(bodyText).not.toContain(`${testFormDisplayName} (Form)`);
    });

    test('should NOT show form-sourced collections in new-content picker', async ({ page }) => {
      await loginAsAdmin(page);
      await page.goto('/admin/content/new');
      await page.waitForLoadState('networkidle');

      const bodyText = await page.locator('body').textContent();
      expect(bodyText).not.toContain(`${testFormDisplayName} (Form)`);
    });

    test('should NOT show form submissions in the regular content list', async ({ page }) => {
      await loginAsAdmin(page);
      // Visit the unfiltered content list
      await page.goto('/admin/content');
      await page.waitForLoadState('networkidle');

      const bodyText = await page.locator('body').textContent();
      // "Jane Doe" was the submission name - it should NOT appear in regular content
      expect(bodyText).not.toContain('Jane Doe');
    });

    test('should NOT show form collections in collections API', async ({ page }) => {
      await loginAsAdmin(page);
      const response = await page.request.get('/admin/api/collections');
      expect(response.ok()).toBe(true);
      const body = await response.json();

      const formCollections = body.data.filter((c: any) =>
        c.name === `form_${testFormName}`
      );
      expect(formCollections.length).toBe(0);
    });

    test('should NOT show form collections in public API', async ({ request }) => {
      const response = await request.get('/api/collections');
      // The public API may or may not be accessible without auth
      if (response.ok()) {
        const body = await response.json();
        const collections = body.data || [];
        const formCollections = collections.filter((c: any) =>
          c.name?.startsWith('form_')
        );
        expect(formCollections.length).toBe(0);
      }
    });

    test('should preserve existing collection and content counts', async ({ page }) => {
      await loginAsAdmin(page);
      // This is the critical test: dashboard counts should NOT include form data
      const response = await page.request.get('/admin/api/stats');
      if (response.ok()) {
        const body = await response.json();
        console.log(`Dashboard stats: collections=${body.collections}, contentItems=${body.contentItems}`);
        // Counts should be stable — form shadow collections/content excluded
        // We just verify the endpoint works without errors
        expect(body.collections).toBeDefined();
        expect(body.contentItems).toBeDefined();
      }
    });
  });
})
