import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './utils/test-helpers';

test.describe.skip('Media Create Folder @media', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/admin/media');
    await page.waitForLoadState('networkidle');
  });

  test('should open create folder modal when clicking Create Folder button', async ({ page }) => {
    // Click the Create Folder button in the sidebar (not the submit button in modal)
    const createFolderBtn = page.locator('button[onclick="openCreateFolderModal()"]');
    await expect(createFolderBtn).toBeVisible();
    await createFolderBtn.click();

    // Verify modal is visible
    const modal = page.locator('#create-folder-modal');
    await expect(modal).toBeVisible();
    await expect(modal).not.toHaveClass(/hidden/, { timeout: 2000 });

    // Verify modal has correct title
    await expect(modal.locator('h3:has-text("Create New Folder")')).toBeVisible();

    // Verify input field is focused
    const folderInput = page.locator('#folder-name');
    await expect(folderInput).toBeVisible();
    await expect(folderInput).toBeFocused();
  });

  test('should close modal when clicking Cancel button', async ({ page }) => {
    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');
    await expect(modal).toBeVisible();

    // Click Cancel button
    const cancelBtn = modal.locator('button:has-text("Cancel")');
    await cancelBtn.click({ force: true });

    // Verify modal is hidden
    await expect(modal).not.toBeVisible({ timeout: 2000 });
  });

  test('should close modal when clicking X button', async ({ page }) => {
    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');
    await expect(modal).toBeVisible();

    // Click X button - use force since it's inside a modal overlay
    const closeBtn = page.locator('button[aria-label="Close"]');
    await closeBtn.click({ force: true });

    // Verify modal is hidden
    await expect(modal).not.toBeVisible({ timeout: 2000 });
  });

  test('should show error for empty folder name', async ({ page }) => {
    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');

    // Try to submit empty form
    const submitBtn = modal.locator('button[type="submit"]');
    await submitBtn.click();

    // Verify error message or that modal stays open
    await expect(modal).toBeVisible();
  });

  test('should show error for invalid folder name characters', async ({ page }) => {
    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');

    // Enter invalid folder name with uppercase and spaces
    const folderInput = page.locator('#folder-name');
    await folderInput.fill('Invalid Folder Name');

    // Submit form
    const submitBtn = modal.locator('button[type="submit"]');
    await submitBtn.click();

    // Wait for error response
    await page.waitForTimeout(500);

    // Verify error message appears
    const errorMessage = page.locator('text=/can only contain lowercase/i');
    await expect(errorMessage).toBeVisible({ timeout: 3000 });
  });

  test('should successfully create folder with valid name', async ({ page }) => {
    const folderName = `test-folder-${Date.now()}`;

    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');

    // Enter valid folder name
    const folderInput = page.locator('#folder-name');
    await folderInput.fill(folderName);

    // Submit form
    const submitBtn = modal.locator('button[type="submit"]');
    await submitBtn.click();

    // Wait for success and verify notification appears (within animation time)
    const notification = page.getByText(/created successfully/i);
    await expect(notification).toBeVisible({ timeout: 1500 });

    // Verify modal closes after success
    await expect(modal).not.toBeVisible({ timeout: 3000 });
  });

  test('should accept valid folder names with lowercase, numbers, hyphens, and underscores', async ({ page }) => {
    const validNames = [
      'folder-name',
      'folder_name',
      'folder123',
      'folder-name_123'
    ];

    for (const folderName of validNames) {
      // Open modal
      await page.locator('button[onclick="openCreateFolderModal()"]').click();
      const modal = page.locator('#create-folder-modal');

      // Enter valid folder name
      const folderInput = page.locator('#folder-name');
      await folderInput.fill(folderName);

      // Submit form
      const submitBtn = modal.locator('button[type="submit"]');
      await submitBtn.click();

      // Wait for response
      await page.waitForTimeout(500);

      // Verify success (no error message visible)
      const errorMessage = page.locator('text=/can only contain lowercase/i');
      await expect(errorMessage).not.toBeVisible();

      // Close modal if still open
      const cancelBtn = modal.locator('button:has-text("Cancel")');
      if (await cancelBtn.isVisible()) {
        await cancelBtn.click();
      }
      await page.waitForTimeout(300);
    }
  });

  test('should prevent form submission with Enter key when input is empty', async ({ page }) => {
    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');

    // Focus input and press Enter without typing
    const folderInput = page.locator('#folder-name');
    await folderInput.focus();
    await folderInput.press('Enter');

    // Modal should stay open
    await expect(modal).toBeVisible();
  });

  test('should submit form with Enter key when input has valid value', async ({ page }) => {
    const folderName = `enter-test-${Date.now()}`;

    // Open modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    const modal = page.locator('#create-folder-modal');

    // Type valid folder name and press Enter
    const folderInput = page.locator('#folder-name');
    await folderInput.fill(folderName);
    await folderInput.press('Enter');

    // Wait for success and verify notification (within animation time)
    const notification = page.getByText(/created successfully/i);
    await expect(notification).toBeVisible({ timeout: 1500 });
  });

  test('should clear input when reopening modal after successful creation', async ({ page }) => {
    const folderName = `clear-test-${Date.now()}`;

    // Create first folder
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    let modal = page.locator('#create-folder-modal');
    await page.locator('#folder-name').fill(folderName);
    await modal.locator('button[type="submit"]').click();

    // Wait for modal to close
    await expect(modal).not.toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(500);

    // Reopen modal
    await page.locator('button[onclick="openCreateFolderModal()"]').click();
    await expect(modal).toBeVisible({ timeout: 2000 });

    // Verify input is empty
    const folderInput = page.locator('#folder-name');
    await expect(folderInput).toHaveValue('');
  });
});
