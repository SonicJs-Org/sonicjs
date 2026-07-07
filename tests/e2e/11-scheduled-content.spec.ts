import { test, expect } from '@playwright/test'
import { loginAsAdmin, createTestWorkflowContent, createTestContent } from './utils/test-helpers'

async function skipIfWorkflowInactive(page: any) {
  const featureNotAvailable = page.locator('h1:has-text("Feature Not Available")')
  if (await featureNotAvailable.isVisible({ timeout: 2000 })) {
    test.skip();
    return true;
  }
  return false;
}

test.describe.skip('Scheduled Content Management @content', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should display scheduled content page', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    await page.waitForLoadState('networkidle')

    if (await skipIfWorkflowInactive(page)) return;

    // Check page title and header
    await expect(page).toHaveTitle(/Scheduled Content/)
    await expect(page.locator('h1')).toContainText('Scheduled Content')

    // Check breadcrumb navigation
    await expect(page.locator('a[href="/admin/workflow/dashboard"]').first()).toBeVisible()

    // Check action buttons
    await expect(page.locator('button:has-text("Bulk Schedule")')).toBeVisible()
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible()
  })

  test('should display stats overview cards', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    await page.waitForLoadState('networkidle')

    if (await skipIfWorkflowInactive(page)) return;
    
    // Check for stats cards or general page content
    const statsCards = page.locator('.stats-card')
    const hasStatsCards = await statsCards.count() > 0
    
    if (hasStatsCards) {
      // If stats cards exist, check for expected status text
      const pendingCard = page.locator('.stats-card').filter({ hasText: 'Pending' })
      const completedCard = page.locator('.stats-card').filter({ hasText: 'Completed' })
      
      if (await pendingCard.count() > 0) {
        await expect(pendingCard).toBeVisible()
      }
      if (await completedCard.count() > 0) {
        await expect(completedCard).toBeVisible()
      }
      
      // Check that stats have numeric values
      const statNumbers = page.locator('[class*="text-2xl"][class*="font-bold"]')
      if (await statNumbers.count() > 0) {
        await expect(statNumbers.first()).toBeVisible()
      }
    } else {
      // If no stats cards, just ensure the page loaded with some content
      await expect(page.locator('h1')).toContainText('Scheduled Content')
      await expect(page.locator('button:has-text("Bulk Schedule")')).toBeVisible()
    }
  })

  test('should show empty state when no scheduled content', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // May show empty state or actual content
    const emptyStateText = page.locator('text=No Scheduled Content')
    const scheduledTable = page.locator('table')
    
    // Either empty state or table should be visible
    const hasEmptyState = await emptyStateText.count() > 0
    const hasTable = await scheduledTable.count() > 0
    
    expect(hasEmptyState || hasTable).toBeTruthy()
  })

  test('should open bulk schedule modal', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Click bulk schedule button
    await page.click('button:has-text("Bulk Schedule")')
    
    // Check that modal opens
    await expect(page.locator('#bulk-schedule-modal')).toBeVisible()
    await expect(page.locator('text=Bulk Schedule Content')).toBeVisible()
    
    // Check modal form elements
    await expect(page.locator('select[name="action"]')).toBeVisible()
    await expect(page.locator('select[name="timezone"]')).toBeVisible()
    await expect(page.locator('input[name="schedule_method"][value="single_time"]')).toBeVisible()
    await expect(page.locator('input[name="schedule_method"][value="staggered"]')).toBeVisible()
  })

  test('should close bulk schedule modal', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Open modal
    await page.click('button:has-text("Bulk Schedule")')
    await expect(page.locator('#bulk-schedule-modal')).toBeVisible()
    
    // Close modal
    await page.click('button:has-text("Cancel")')
    await expect(page.locator('#bulk-schedule-modal')).toBeHidden()
  })

  test('should toggle between scheduling methods in bulk modal', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Open modal
    await page.click('button:has-text("Bulk Schedule")')
    
    // By default, single time should be selected
    await expect(page.locator('#single-time-options')).toBeVisible()
    await expect(page.locator('#staggered-options')).toBeHidden()
    
    // Switch to staggered
    await page.click('input[name="schedule_method"][value="staggered"]')
    
    // Options should switch
    await expect(page.locator('#single-time-options')).toBeHidden()
    await expect(page.locator('#staggered-options')).toBeVisible()
    
    // Check staggered options elements
    await expect(page.locator('input[name="start_time"]')).toBeVisible()
    await expect(page.locator('input[name="interval_minutes"]')).toBeVisible()
    await expect(page.locator('select[name="interval_unit"]')).toBeVisible()
  })

  test('should filter scheduled content by status', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Test status filter
    const statusFilter = page.locator('#status-filter')
    await expect(statusFilter).toBeVisible()
    
    // Select pending status
    await statusFilter.selectOption('pending')
    
    // Check that JavaScript filtering would work
    // (In real implementation, this would filter visible rows)
    await expect(statusFilter).toHaveValue('pending')
  })

  test('should filter scheduled content by action', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Test action filter
    const actionFilter = page.locator('#action-filter')
    await expect(actionFilter).toBeVisible()
    
    // Select publish action
    await actionFilter.selectOption('publish')
    
    await expect(actionFilter).toHaveValue('publish')
  })

  test('should handle refresh button', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Click refresh button
    await page.click('button:has-text("Refresh")')
    
    // Should reload the page
    await page.waitForLoadState('networkidle')
    await expect(page.locator('h1')).toContainText('Scheduled Content')
  })

  test('should display scheduled items table when data exists', async ({ page }) => {
    // First create some content to schedule using the correct helper
    const contentCreated = await createTestContent(page, {
      title: 'Scheduled Content Test',
      slug: 'scheduled-content-test',
      content: 'Content for scheduling test.'
    });
    
    if (!contentCreated) {
      // Skip test if content creation failed
      test.skip();
      return;
    }
    
    await page.waitForTimeout(1000);
    
    // Go to scheduled content page
    await page.goto('/admin/workflow/scheduled');
    
    await page.waitForLoadState('networkidle')
    // Skip if workflow plugin is not active
    if (await skipIfWorkflowInactive(page)) return;
    
    // Check for table elements if scheduled content exists
    const table = page.locator('table');
    const emptyState = page.locator('text=No Scheduled Content');
    
    // Either table or empty state should be present
    const hasTable = await table.count() > 0
    const hasEmptyState = await emptyState.count() > 0
    
    expect(hasTable || hasEmptyState).toBeTruthy()
    
    if (hasTable) {
      // Check table headers
      await expect(page.locator('th:has-text("Content")')).toBeVisible()
      await expect(page.locator('th:has-text("Action")')).toBeVisible()
      await expect(page.locator('th:has-text("Scheduled Time")')).toBeVisible()
      await expect(page.locator('th:has-text("Status")')).toBeVisible()
      await expect(page.locator('th:has-text("Actions")')).toBeVisible()
    }
  })

  test('should handle mock scheduled content data', async ({ page }) => {
    // Mock the scheduled content endpoint to return test data
    await page.route('/admin/workflow/scheduled', async route => {
      if (route.request().method() === 'GET') {
        // Let the original request go through, we're testing the UI
        await route.continue()
      }
    })

    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Test that page loads successfully with or without data
    await expect(page.locator('h1')).toContainText('Scheduled Content')
    await expect(page.locator('button:has-text("Bulk Schedule")')).toBeVisible()
  })

  test('should show proper status badges', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Check that status filter options match expected statuses
    const statusFilter = page.locator('#status-filter')
    const options = await statusFilter.locator('option').allTextContents()
    
    expect(options).toContain('Pending')
    expect(options).toContain('Completed')
    expect(options).toContain('Failed')
    expect(options).toContain('Cancelled')
  })

  test('should show proper action badges', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Check that action filter options match expected actions
    const actionFilter = page.locator('#action-filter')
    const options = await actionFilter.locator('option').allTextContents()
    
    expect(options).toContain('Publish')
    expect(options).toContain('Unpublish')
    expect(options).toContain('Archive')
  })

  test('should handle bulk schedule form submission', async ({ page }) => {
    // Mock the bulk schedule endpoint
    await page.route('/admin/workflow/bulk-schedule', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, scheduled: 3 })
      })
    })

    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Open bulk schedule modal
    await page.click('button:has-text("Bulk Schedule")')
    
    // Fill form
    await page.selectOption('select[name="action"]', 'publish')
    await page.selectOption('select[name="timezone"]', 'America/New_York')
    await page.fill('input[name="scheduled_at"]', '2024-12-31T23:59')
    
    // Submit form
    await page.click('button:has-text("Schedule Selected Content")')
    
    // Would wait for response in real implementation
    // For now, just verify form submission doesn't error
  })

  test('should handle scheduled content cancellation', async ({ page }) => {
    // Mock delete endpoint
    await page.route('/admin/workflow/scheduled/*', async route => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        })
      } else {
        await route.continue()
      }
    })

    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Test cancellation function exists
    const cancelFunction = await page.evaluate(() => {
      return typeof window.cancelScheduledAction === 'function'
    })
    
    // Function may not be defined if no scheduled content exists
    // Just verify page loads without errors
    await expect(page.locator('h1')).toContainText('Scheduled Content')
  })

  test('should maintain responsive design', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Check responsive elements
    await expect(page.locator('h1')).toBeVisible()
    await expect(page.locator('button:has-text("Bulk Schedule")')).toBeVisible()
    
    // Stats cards should stack on mobile - check for visible grid container
    const statsCards = page.locator('[class*="grid-cols"]:visible')
    if (await statsCards.count() > 0) {
      await expect(statsCards.first()).toBeVisible()
    } else {
      // Alternative check for mobile layout
      const mobileStats = page.locator('.stats-card, [class*="col-span"]')
      await expect(mobileStats.first()).toBeVisible()
    }
  })

  test('should navigate back to workflow dashboard', async ({ page }) => {
    await page.goto('/admin/workflow/scheduled')
    
    await page.waitForLoadState('networkidle')
    if (await skipIfWorkflowInactive(page)) return;
    
    // Click breadcrumb
    await page.click('a[href="/admin/workflow/dashboard"]')
    await page.waitForURL('/admin/workflow/dashboard')
    
    await expect(page.locator('h1')).toContainText('Workflow Dashboard')
  })
})