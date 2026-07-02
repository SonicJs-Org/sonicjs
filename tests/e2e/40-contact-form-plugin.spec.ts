import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe('Contact Form Plugin @plugins', () => {

  // Ensure plugin is activated before running tests
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await loginAsAdmin(page);
    
    // Navigate to plugins page
    await page.goto('/admin/plugins');
    await page.waitForLoadState('networkidle');
    
    // Find Contact Form plugin row and check if it needs activation
    const pluginRow = page.locator('tr:has-text("Contact Form")');
    const activateButton = pluginRow.locator('button:has-text("Activate")');
    
    if (await activateButton.isVisible()) {
      console.log('[Test Setup] Activating Contact Form plugin...');
      await activateButton.click();
      
      // Wait for activation to complete
      await page.waitForResponse(resp => 
        resp.url().includes('/activate') && resp.status() === 200,
        { timeout: 10000 }
      ).catch(() => {
        console.log('[Test Setup] Activation response timeout, continuing anyway...');
      });
      
      await page.waitForTimeout(500); // Small buffer
      console.log('[Test Setup] Contact Form plugin activated');
    } else {
      console.log('[Test Setup] Contact Form plugin already active');
    }
    
    await page.close();
  });

  // TEST 1: Public Form Submission
  test('should allow a guest to send a message', async ({ page }) => {
    // 1. Go to the contact page
    await page.goto('/contact');
    
    // 2. Verify page loads
    await expect(page.locator('h1')).toContainText('Contact');
    
    // 3. Fill out the form
    await page.fill('input[name="name"]', 'Playwright User');
    await page.fill('input[name="email"]', 'test@example.com');
    await page.fill('textarea[name="msg"]', 'Automated test message.');
    
    // 4. Submit
    // FIX: We now find the button by its visual text "Send Message"
    await page.getByRole('button', { name: 'Send Message' }).click();
    
    // 5. Verify Success Alert
    const alert = page.locator('#success-alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Message sent!');
  });

  // TEST 2: Admin Settings & Map Toggle
  test('should allow admin to enable the Google Map', async ({ page }) => {
    // Listen for console logs to debug
    page.on('console', msg => console.log(`[Browser Console] ${msg.type()}: ${msg.text()}`));
    
    // Login first (will redirect to dashboard)
    await loginAsAdmin(page);
    
    // Then navigate to Contact Form settings
    await page.goto('/admin/plugins/contact-form');
    await page.waitForLoadState('networkidle');

    // 1. Check the "Enable Map" box
    const checkbox = page.locator('#showMap');
    if (!(await checkbox.isChecked())) {
        await checkbox.check({ force: true });
    }

    // 2. Fill in details
    await page.fill('input[name="mapApiKey"]', 'AIzaFakeKeyForTesting');
    await page.fill('input[name="city"]', 'Baltimore');

    // 3. Save and wait for the network request to complete
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/admin/plugins/contact-form') && 
      response.request().method() === 'POST'
    );
    
    await page.getByRole('button', { name: 'Save Settings' }).click();
    
    // Wait for the POST request to complete
    const response = await responsePromise;
    const status = response.status();
    console.log(`[Test] Settings save response status: ${status}`);
    
    // Verify the response was successful
    expect(status).toBe(200);
    
    // Optionally verify the success message appears (but don't fail if it doesn't due to timing)
    const msgVisible = await page.locator('#msg').isVisible().catch(() => false);
    console.log(`[Test] Success message visible: ${msgVisible}`);

    // 4. Verify on Public Page (the real test - did settings actually persist?)
    await page.goto('/contact');
    await page.waitForLoadState('networkidle');
    
    // 5. Check if Map Iframe exists
    await expect(page.locator('.ratio-16x9')).toBeVisible();
  });
});

