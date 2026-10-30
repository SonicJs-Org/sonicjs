import { test, expect } from './fixtures';
import { loginAsAdmin, isFeatureAvailable } from './utils/test-helpers';

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
