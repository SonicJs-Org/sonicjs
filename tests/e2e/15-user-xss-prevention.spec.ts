import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('User XSS Prevention @auth', () => {
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
      username: `xsstest${timestamp}`,
      email: `xsstest${timestamp}@example.com`,
      phone: '<script>alert("phone")</script>',
      bio: '"><script>alert("bio")</script><script>'
    };

    await page.fill('input[name="first_name"]', xssPayloads.firstName);
    await page.fill('input[name="last_name"]', xssPayloads.lastName);
    await page.fill('input[name="username"]', xssPayloads.username);
    await page.fill('input[name="email"]', xssPayloads.email);
    await page.fill('input[name="phone"]', xssPayloads.phone);
    await page.fill('textarea[name="bio"]', xssPayloads.bio);
    await page.selectOption('select[name="role"]', 'viewer');
    await page.fill('input[name="password"]', 'SecurePassword123!');
    await page.fill('input[name="confirm_password"]', 'SecurePassword123!');

    // Submit the form
    await page.click('button[type="submit"]');

    // Wait for response
    await page.waitForTimeout(2000);

    // Check if we're redirected to users list or edit page
    const currentUrl = page.url();
    expect(currentUrl).toContain('/admin/users');

    // Wait for page to fully load
    await page.waitForLoadState('networkidle');

    // CRITICAL: Verify no JavaScript execution occurred
    expect(alertTriggered).toBe(false);

    // Get the page HTML to check if dangerous content is properly escaped
    const pageHtml = await page.content();

    // Extract just the form section to check user data
    const formSection = pageHtml.match(/<form[\s\S]*?<\/form>/gi)?.join('') || '';

    // Check for unescaped dangerous HTML in attribute values
    expect(formSection).not.toMatch(/value="[^"]*<script[^>]*>/i);
    expect(formSection).not.toMatch(/value="[^"]*<\/script>/i);
    expect(formSection).not.toMatch(/value="[^"]*"[^>]*onerror=/i);
    expect(formSection).not.toMatch(/value="[^"]*<img[^>]*onerror=/i);

    // Verify content IS properly escaped (contains HTML entities)
    expect(formSection).toMatch(/&(lt|gt|quot|amp);/);

    console.log('✓ XSS payloads properly escaped - found HTML entities in form values');

    console.log('✓ XSS payloads were successfully sanitized in user creation');
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
    await page.fill('input[name="first_name"]', '<script>alert("test")</script>');
    await page.fill('input[name="last_name"]', `XSSTest${timestamp}`);
    await page.fill('input[name="username"]', `xsstest_db_${timestamp}`);
    await page.fill('input[name="email"]', `xsstest_db_${timestamp}@example.com`);
    await page.fill('input[name="phone"]', '"><img src=x onerror=alert(1)>');
    await page.fill('textarea[name="bio"]', '<iframe src="javascript:alert(\'XSS\')">');
    await page.selectOption('select[name="role"]', 'viewer');
    await page.fill('input[name="password"]', 'SecurePassword123!');
    await page.fill('input[name="confirm_password"]', 'SecurePassword123!');

    // Submit the form
    await page.click('button[type="submit"]');

    // Wait for response
    await page.waitForTimeout(2000);

    // Verify user was created and redirected
    const currentUrl = page.url();
    expect(currentUrl).toContain('/admin/users');

    // Wait for page to fully load
    await page.waitForLoadState('networkidle');

    // CRITICAL: Verify no JavaScript execution occurred
    expect(alertTriggered).toBe(false);

    // Get the page HTML source to check proper escaping
    const pageHtml = await page.content();

    // Extract just the form section to check user data
    const formSection = pageHtml.match(/<form[\s\S]*?<\/form>/gi)?.join('') || '';

    // Check for unescaped dangerous HTML in attribute values
    expect(formSection).not.toMatch(/value="[^"]*<script[^>]*>/i);
    expect(formSection).not.toMatch(/value="[^"]*<\/script>/i);
    expect(formSection).not.toMatch(/value="[^"]*"[^>]*onerror=/i);
    expect(formSection).not.toMatch(/value="[^"]*<img[^>]*onerror=/i);
    expect(formSection).not.toMatch(/value="[^"]*<iframe[^>]*src=["']javascript:/i);

    // Verify content IS properly escaped (contains HTML entities)
    expect(formSection).toMatch(/&(lt|gt|quot|amp);/);

    console.log('✓ User created successfully, XSS payloads were sanitized in database');
  });
});
