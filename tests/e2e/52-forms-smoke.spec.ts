import { test, expect } from '@playwright/test';
import { loginAsAdmin, ADMIN_CREDENTIALS } from './utils/test-helpers';

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

    await page.waitForLoadState('networkidle');

    // Should have examples content
    const bodyText = await page.locator('body').textContent();
    const hasExampleContent = bodyText?.toLowerCase().includes('example') ||
                              bodyText?.toLowerCase().includes('form');

    console.log('Examples page has content:', hasExampleContent);
    expect(hasExampleContent).toBe(true);
  });
});
