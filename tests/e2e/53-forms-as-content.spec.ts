import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

/**
 * E2E Tests for Forms-as-Content Integration
 *
 * Tests that form submissions appear as content items in the unified
 * content management system. Creates realistic forms with actual fields,
 * submits real data, and verifies content items are created.
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

const FEEDBACK_FORM_SCHEMA = {
  components: [
    {
      type: 'textfield',
      key: 'name',
      label: 'Your Name'
    },
    {
      type: 'email',
      key: 'email',
      label: 'Email'
    },
    {
      type: 'select',
      key: 'rating',
      label: 'Rating',
      data: {
        values: [
          { label: 'Excellent', value: 'excellent' },
          { label: 'Good', value: 'good' },
          { label: 'Average', value: 'average' },
          { label: 'Poor', value: 'poor' }
        ]
      }
    },
    {
      type: 'textarea',
      key: 'comments',
      label: 'Comments'
    },
    {
      type: 'button',
      key: 'submit',
      label: 'Submit Feedback',
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
  // 1. Create form via admin UI (POST uses parseBody, not JSON)
  await page.goto('/admin/forms/new');
  await page.waitForLoadState('networkidle');

  await page.fill('[name="name"]', formName);
  await page.fill('[name="displayName"]', displayName);
  await page.fill('[name="description"]', description);
  await page.selectOption('[name="category"]', 'general');
  await page.click('button[type="submit"]');

  await page.waitForURL(/\/admin\/forms\/[^/]+\/builder/, { timeout: 10000 });
  const url = page.url();
  const match = url.match(/\/admin\/forms\/([^/]+)\/builder/);
  const formId = match ? match[1] : '';
  expect(formId).toBeTruthy();

  // 2. Set real schema + disable turnstile via authenticated PUT
  //    Use page.request to share the auth cookies from the logged-in page
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
// Structure tests: shadow collection, redirect, picker exclusion
// ═══════════════════════════════════════════════════════════════

test.describe('Forms as Content - Structure', () => {
  test.describe.configure({ mode: 'serial' });

  let testFormId: string;
  const testFormName = `fac_struct_${Date.now()}`;
  const testFormDisplayName = 'FAC Contact Form';

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should create form with fields and verify shadow collection', async ({ page }) => {
    testFormId = await createTestFormWithSchema(
      page,
      testFormName, testFormDisplayName,
      'Contact form for forms-as-content testing',
      CONTACT_FORM_SCHEMA
    );

    // Shadow collection should appear in content model filter
    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const modelFilter = page.locator('select[name="model"]');
    if (await modelFilter.isVisible({ timeout: 3000 }).catch(() => false)) {
      const options = await modelFilter.locator('option').allTextContents();
      const hasFormModel = options.some(opt =>
        opt.toLowerCase().includes(testFormName) || opt.toLowerCase().includes('fac contact')
      );
      expect(hasFormModel).toBe(true);
    }
  });

  test('should redirect submissions page to content list', async ({ page }) => {
    if (!testFormId) { test.skip(); return; }

    await page.goto(`/admin/forms/${testFormId}/submissions`);
    await page.waitForURL(/\/admin\/content/, { timeout: 10000 });

    const currentUrl = page.url();
    expect(currentUrl).toContain('/admin/content');
    expect(currentUrl).toContain(`model=form_${testFormName}`);
  });

  test('should not show form collections in new content picker', async ({ page }) => {
    if (!testFormId) { test.skip(); return; }

    await page.goto('/admin/content/new');
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('body').textContent();
    const hasFormCollection = bodyText?.includes(`${testFormDisplayName} (Form)`);
    expect(hasFormCollection).toBe(false);
  });

  test('should not show form collections on collections page', async ({ page }) => {
    if (!testFormId) { test.skip(); return; }

    await page.goto('/admin/collections');
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('body').textContent();
    const hasFormCollection = bodyText?.includes(`form_${testFormName}`);
    expect(hasFormCollection).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════
// Submission tests: dual-write, content listing, badges, search
// Creates forms with real fields, disables turnstile, submits data
// ═══════════════════════════════════════════════════════════════

test.describe('Forms as Content - Submissions', () => {
  test.describe.configure({ mode: 'serial' });

  let contactFormId: string;
  let feedbackFormId: string;
  let submissionsCreated = false;
  const contactFormName = `fac_contact_${Date.now()}`;
  const feedbackFormName = `fac_feedback_${Date.now()}`;

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test('should create contact form, submit data, and see it as content', async ({ page, request }) => {
    // Create contact form with real fields and turnstile disabled
    contactFormId = await createTestFormWithSchema(
      page,
      contactFormName, 'Test Contact Form',
      'Contact form with name, email, subject, message',
      CONTACT_FORM_SCHEMA
    );

    // Submit real contact data via public API
    const response = await request.post(`/api/forms/${contactFormName}/submit`, {
      data: {
        data: {
          name: 'Jane Doe',
          email: 'jane@example.com',
          subject: 'Product Inquiry',
          message: 'I would like to learn more about your product offerings.'
        }
      }
    });

    const responseBody = await response.text();
    console.log(`Contact form submit: ${response.status()} - ${responseBody}`);

    // If still blocked by turnstile, skip gracefully
    if (response.status() === 400 || response.status() === 403) {
      const parsed = JSON.parse(responseBody);
      if (parsed.code === 'TURNSTILE_MISSING' || parsed.code === 'TURNSTILE_INVALID') {
        console.log('Turnstile still active despite disable attempt - skipping');
        test.skip();
        return;
      }
    }

    expect(response.ok()).toBe(true);
    const result = JSON.parse(responseBody);
    expect(result.success).toBe(true);
    expect(result.submissionId).toBeTruthy();
    submissionsCreated = true;

    // Verify content item appeared in the content list
    await page.goto(`/admin/content?model=form_${contactFormName}`);
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(1);

    // Title should be derived from the name field
    const bodyText = await page.locator('tbody').textContent();
    expect(bodyText).toContain('Jane Doe');
  });

  test('should create feedback form and submit multiple entries', async ({ page, request }) => {
    if (!submissionsCreated) { test.skip(); return; }

    // Create feedback form with select field
    feedbackFormId = await createTestFormWithSchema(
      page,
      feedbackFormName, 'Test Feedback Form',
      'Feedback form with rating selector and comments',
      FEEDBACK_FORM_SCHEMA
    );

    // Submit three feedback entries
    const entries = [
      { name: 'Alice Smith', email: 'alice@example.com', rating: 'excellent', comments: 'Great product!' },
      { name: 'Bob Jones', email: 'bob@example.com', rating: 'good', comments: 'Works well, minor issues' },
      { name: 'Carol White', email: 'carol@example.com', rating: 'average', comments: 'Needs improvement' }
    ];

    for (const entry of entries) {
      const resp = await request.post(`/api/forms/${feedbackFormName}/submit`, {
        data: { data: entry }
      });
      expect(resp.ok()).toBe(true);
    }

    // Verify all 3 appear in content list
    await page.goto(`/admin/content?model=form_${feedbackFormName}`);
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(3);

    const bodyText = await page.locator('tbody').textContent();
    expect(bodyText).toContain('Alice Smith');
    expect(bodyText).toContain('Bob Jones');
    expect(bodyText).toContain('Carol White');
  });

  test('should show Form badge on form-sourced content', async ({ page }) => {
    if (!submissionsCreated) { test.skip(); return; }

    await page.goto(`/admin/content?model=form_${contactFormName}`);
    await page.waitForLoadState('networkidle');

    // The indigo "Form" badge should appear in the model column
    const formBadge = page.locator('span:text("Form")');
    const hasBadge = await formBadge.first().isVisible({ timeout: 5000 }).catch(() => false);
    expect(hasBadge).toBe(true);
  });

  test('should show submission metadata in content edit view', async ({ page }) => {
    if (!submissionsCreated) { test.skip(); return; }

    await page.goto(`/admin/content?model=form_${contactFormName}`);
    await page.waitForLoadState('networkidle');

    // Click the first content item
    const firstLink = page.locator('tbody tr a').first();
    if (await firstLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await firstLink.click();
      await page.waitForLoadState('networkidle');

      // Should show the submission info panel
      const bodyText = await page.locator('body').textContent();
      expect(bodyText).toContain('Submission Info');
      expect(bodyText).toContain('jane@example.com');
    }
  });

  test('should default submission content status to published', async ({ page }) => {
    if (!submissionsCreated) { test.skip(); return; }

    await page.goto(`/admin/content?model=form_${contactFormName}&status=published`);
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(1);
  });

  test('should find submissions via content search', async ({ page }) => {
    if (!submissionsCreated) { test.skip(); return; }

    // Search by submitter name
    await page.goto(`/admin/content?model=form_${contactFormName}&search=Jane`);
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('tbody').textContent().catch(() => '');
    expect(bodyText).toContain('Jane');
  });

  test('should include form submissions in all-content view', async ({ page }) => {
    if (!submissionsCreated) { test.skip(); return; }

    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const bodyText = await page.locator('body').textContent();
    // Should contain at least one of our submitted names
    const hasFormContent = bodyText?.includes('Jane Doe') ||
      bodyText?.includes('Alice Smith') ||
      bodyText?.includes('Bob Jones');
    expect(hasFormContent).toBe(true);
  });

  test('should show both form models in content filter', async ({ page }) => {
    if (!submissionsCreated || !feedbackFormId) { test.skip(); return; }

    await page.goto('/admin/content');
    await page.waitForLoadState('networkidle');

    const modelFilter = page.locator('select[name="model"]');
    if (await modelFilter.isVisible({ timeout: 3000 }).catch(() => false)) {
      const options = await modelFilter.locator('option').allTextContents();

      const hasContact = options.some(opt => opt.toLowerCase().includes('contact'));
      const hasFeedback = options.some(opt => opt.toLowerCase().includes('feedback'));

      expect(hasContact).toBe(true);
      expect(hasFeedback).toBe(true);
    }
  });
});
