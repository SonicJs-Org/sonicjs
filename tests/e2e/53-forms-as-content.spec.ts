import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

/**
 * E2E Tests for Forms-as-Content Integration
 *
 * Tests that form submissions appear as content items in the unified
 * content management system. Covers:
 * - Shadow collection creation when a form is created
 * - Dual-write: submission creates both form_submission and content
 * - Content list shows form submissions with Form badge
 * - Filtering content by form model
 * - Submissions page redirects to content list
 * - Form-sourced collections excluded from new-content picker
 * - Content edit view shows submission metadata panel
 */

// ═══════════════════════════════════════════════════════════════
// Structural tests: form creation, shadow collection, redirects
// These don't require form submissions and always run.
// ═══════════════════════════════════════════════════════════════

test.describe('Forms as Content - Structure', () => {
  test.describe.configure({ mode: 'serial' });

  let testFormId: string;
  const testFormName = `fac_struct_${Date.now()}`;
  const testFormDisplayName = 'FAC Struct Form';

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should create a form and its shadow collection', async ({ page }) => {
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    await page.fill('[name="name"]', testFormName);
    await page.fill('[name="displayName"]', testFormDisplayName);
    await page.fill('[name="description"]', 'E2E test for forms-as-content structure');
    await page.selectOption('[name="category"]', 'general');

    await page.click('button[type="submit"]');

    // Should redirect to builder
    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 10000 });

    const url = page.url();
    const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
    testFormId = match ? match[1] : '';
    expect(testFormId).toBeTruthy();

    // Navigate to content list and check the form model appears in the filter
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const modelFilter = page.locator('select[name="model"]');
    if (await modelFilter.isVisible({ timeout: 3000 }).catch(() => false)) {
      const options = await modelFilter.locator('option').allTextContents();
      const hasFormModel = options.some(opt =>
        opt.toLowerCase().includes(testFormName) || opt.toLowerCase().includes('fac struct')
      );
      expect(hasFormModel).toBe(true);
    }
  });

  test('should redirect submissions page to content list', async ({ page }) => {
    if (!testFormId) {
      test.skip();
      return;
    }

    await page.goto(`/admin/forms/${testFormId}/submissions`);

    // Should redirect to the content list filtered by the form model
    await page.waitForURL(/\/admin\/content/, { timeout: 10000 });

    const currentUrl = page.url();
    expect(currentUrl).toContain('/admin/content');
    expect(currentUrl).toContain(`model=form_${testFormName}`);
  });

  test('should not show form collections in new content picker', async ({ page }) => {
    if (!testFormId) {
      test.skip();
      return;
    }

    await page.goto('/admin/content/new');
    await page.waitForLoadState('networkidle');

    // Form-sourced collections should NOT appear in the new-content picker
    const bodyText = await page.locator('body').textContent();
    const hasFormCollection = bodyText?.includes(`${testFormDisplayName} (Form)`);
    expect(hasFormCollection).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// Submission tests: dual-write, content listing, badges, search
// These require form submissions and gracefully skip when
// Turnstile is globally enabled (blocking API submissions).
// ═══════════════════════════════════════════════════════════════

test.describe('Forms as Content - Submissions', () => {
  test.describe.configure({ mode: 'serial' });

  let testFormId: string;
  let submissionsCreated = false;
  const testFormName = `fac_sub_${Date.now()}`;
  const testFormDisplayName = 'FAC Sub Form';

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should create form and submit data', async ({ page, request }) => {
    // Create the form
    await page.goto('/admin/forms/new');
    await page.waitForLoadState('networkidle');

    await page.fill('[name="name"]', testFormName);
    await page.fill('[name="displayName"]', testFormDisplayName);
    await page.fill('[name="description"]', 'E2E test for form submission content');
    await page.selectOption('[name="category"]', 'general');

    await page.click('button[type="submit"]');
    await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 10000 });

    const url = page.url();
    const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
    testFormId = match ? match[1] : '';
    expect(testFormId).toBeTruthy();

    // Submit form data via the public API
    const response = await request.post(`/api/forms/${testFormName}/submit`, {
      data: {
        data: {
          name: 'Jane Doe',
          email: 'jane@example.com',
          subject: 'Test Inquiry',
          message: 'This is an E2E test submission for forms-as-content'
        }
      }
    });

    const responseBody = await response.text();
    console.log(`Form submit response: ${response.status()} - ${responseBody}`);

    // If Turnstile is blocking, skip all submission-dependent tests
    if (response.status() === 400 || response.status() === 403) {
      const parsed = JSON.parse(responseBody);
      if (parsed.code === 'TURNSTILE_MISSING' || parsed.code === 'TURNSTILE_INVALID') {
        console.log('Turnstile is enabled globally - skipping submission tests');
        test.skip();
        return;
      }
    }

    expect(response.ok()).toBe(true);
    const result = JSON.parse(responseBody);
    expect(result.success).toBe(true);
    expect(result.submissionId).toBeTruthy();
    submissionsCreated = true;

    // Verify content item appears in the content list
    await page.goto(`/admin/content?model=form_${testFormName}`);
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(1);

    // Title should be derived from submission data (name field)
    const bodyText = await page.locator('tbody').textContent();
    const hasSubmitterInfo = bodyText?.includes('Jane Doe') || bodyText?.includes('jane@example.com');
    expect(hasSubmitterInfo).toBe(true);
  });

  test('should show Form badge on form-sourced content', async ({ page }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    await page.goto(`/admin/content?model=form_${testFormName}`);
    await page.waitForLoadState('networkidle');

    // Look for the indigo "Form" badge in the model column
    const formBadge = page.locator('span:text("Form")');
    const hasBadge = await formBadge.first().isVisible({ timeout: 5000 }).catch(() => false);
    expect(hasBadge).toBe(true);
  });

  test('should show submission metadata in content edit view', async ({ page }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    await page.goto(`/admin/content?model=form_${testFormName}`);
    await page.waitForLoadState('networkidle');

    // Click the first content item to open the edit view
    const firstEditLink = page.locator('tbody tr a').first();
    if (await firstEditLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await firstEditLink.click();
      await page.waitForLoadState('networkidle');

      // Should show submission metadata panel
      const bodyText = await page.locator('body').textContent();
      const hasSubmissionInfo = bodyText?.includes('Submission Info');
      expect(hasSubmissionInfo).toBe(true);
    }
  });

  test('should show multiple submissions as content items', async ({ page, request }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    // Submit two more
    const submissions = [
      { name: 'Alice Smith', email: 'alice@example.com', message: 'Additional submission 1' },
      { name: 'Bob Jones', email: 'bob@example.com', message: 'Additional submission 2' }
    ];

    for (const sub of submissions) {
      const response = await request.post(`/api/forms/${testFormName}/submit`, {
        data: { data: sub }
      });
      expect(response.ok()).toBe(true);
    }

    await page.goto(`/admin/content?model=form_${testFormName}`);
    await page.waitForLoadState('networkidle');

    // Should have at least 3 content items (1 + 2 new)
    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(3);
  });

  test('should default submission content status to draft', async ({ page }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    await page.goto(`/admin/content?model=form_${testFormName}&status=draft`);
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(1);
  });

  test('should find form submissions via content search', async ({ page }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    await page.goto(`/admin/content?model=form_${testFormName}&search=Jane`);
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('tbody').textContent().catch(() => '');
    const found = bodyText?.includes('Jane') || bodyText?.includes('jane@example.com');
    expect(found).toBe(true);
  });

  test('should include form submissions in all-content view', async ({ page }) => {
    if (!submissionsCreated) {
      test.skip();
      return;
    }

    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('body').textContent();
    const hasFormContent = bodyText?.includes('Jane Doe') ||
      bodyText?.includes('Alice Smith') ||
      bodyText?.includes('Bob Jones');
    expect(hasFormContent).toBe(true);
  });
});
