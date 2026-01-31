import { Page, expect } from '@playwright/test';

// Default admin credentials for testing
export const ADMIN_CREDENTIALS = {
  email: 'admin@sonicjs.com',
  password: 'sonicjs!'
};

// Test data
export const TEST_DATA = {
  collection: {
    name: 'test_collection',
    displayName: 'Test Collection',
    description: 'Test collection for E2E testing'
  },
  content: {
    title: 'Test Blog Post',
    content: '<h1>Test Content</h1><p>This is test content for E2E testing.</p>',
    excerpt: 'Test excerpt for blog post',
    tags: ['test', 'e2e', 'playwright']
  },
  user: {
    email: 'testuser@example.com',
    username: 'testuser',
    firstName: 'Test',
    lastName: 'User',
    password: 'testpass123'
  }
};

/**
 * Ensure admin user exists (for testing)
 */
export async function ensureAdminUserExists(page: Page) {
  try {
    await page.request.post('/auth/seed-admin');
  } catch (error) {
    // Admin might already exist, ignore errors
  }
}

/**
 * Ensure workflow tables exist (for testing)
 * NOTE: This function should be called AFTER login, as it requires authentication
 */
export async function ensureWorkflowTablesExist(page: Page) {
  try {
    // Make an authenticated request using the page's cookies
    const response = await page.request.post('/admin/api/migrations/run', {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Only log non-404/401 errors (404/401 means endpoint doesn't exist or auth failed, which is expected in some cases)
    if (response.status() !== 404 && response.status() !== 401) {
      console.log('Migration response status:', response.status());
    }
  } catch (error) {
    // Migration might already be applied or endpoint not available, ignore errors
    // Don't log to reduce test output noise
  }
}

/**
 * Ensure workflow plugin is active (for testing workflow features)
 */
export async function ensureWorkflowPluginActive(page: Page) {
  // SKIP: Workflow plugin not currently installed - this function just adds overhead
  // Re-enable when workflow plugin is available
  return;
  
  /* Disabled for now - workflow plugin not installed
  try {
    const currentUrl = page.url();
    
    // Navigate to plugins page with longer timeout for CI
    await page.goto('/admin/plugins', { timeout: 20000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 });
    
    // Look for workflow plugin row
    const workflowRow = page.locator('tr').filter({ hasText: 'Workflow Management' });
    const hasWorkflowPlugin = await workflowRow.count() > 0;
    
    if (hasWorkflowPlugin) {
      // Check if it's already active
      const isActive = await workflowRow.locator('.bg-green-100').count() > 0;
      
      if (!isActive) {
        // Activate the plugin
        const activateButton = workflowRow.locator('button').filter({ hasText: 'Activate' });
        if (await activateButton.count() > 0) {
          await activateButton.click();
          await page.waitForTimeout(2000); // Wait for activation
          console.log('Workflow plugin activated');
        }
      } else {
        console.log('Workflow plugin already active');
      }
    } else {
      console.log('Workflow plugin not found - may need to be installed first');
    }
    
    // Return to the original URL if it was an admin page
    if (currentUrl.includes('/admin') && !currentUrl.includes('/admin/plugins')) {
      await page.goto(currentUrl, { timeout: 20000 });
      await page.waitForLoadState('networkidle', { timeout: 15000 });
    }
  } catch (error) {
    console.log('Could not ensure workflow plugin is active:', error);
  }
  */
}

/**
 * Create test workflow content (assumes user is already logged in)
 */
export async function createTestWorkflowContent(page: Page) {
  try {
    // Ensure we have a collection first
    await ensureTestCollectionExists(page);
    
    // Navigate to content creation
    await page.goto('/admin/content/new');
    
    // Wait for the page to load and check if modelName select exists
    try {
      await page.waitForSelector('select[name="modelName"]', { timeout: 5000 });
      const models = await page.locator('select[name="modelName"] option').count();
      
      if (models > 1) { // Skip the first placeholder option
        await page.selectOption('select[name="modelName"]', { index: 1 });
        
        // Wait for dynamic fields to load
        await page.waitForTimeout(1000);
        
        await page.fill('input[name="title"]', 'Workflow Transition Test');
        await page.fill('input[name="slug"]', 'workflow-transition-test');
        await page.fill('textarea[name="content"]', 'Test content for workflow transitions.');
        
        // Submit the form
        await page.click('button[type="submit"]');
        
        // Wait for success response
        await page.waitForTimeout(2000);
      } else {
        console.log('No models available for content creation');
      }
    } catch (selectorError) {
      console.log('Model selector not found or content creation not available');
    }
  } catch (error) {
    // Content might already exist, ignore errors
    console.log('Test content creation failed:', error);
  }
}

/**
 * Ensure test content exists for content management tests
 */
export async function ensureTestContentExists(page: Page) {
  try {
    // Navigate to content list to check if content exists
    await page.goto('/admin/content/');
    await page.waitForTimeout(1000);
    
    // Check if there's already content
    const table = page.locator('table');
    const hasTable = await table.count() > 0;
    
    if (hasTable) {
      const contentRows = page.locator('tbody tr');
      const rowCount = await contentRows.count();
      
      if (rowCount > 0) {
        // Content already exists
        console.log('Test content already exists');
        return;
      }
    }
    
    // No content exists, try to create individual test content using existing collections
    console.log('Creating test content...');
    const created = await createTestContent(page, {
      title: 'Test Article for E2E Testing',
      slug: 'test-article-e2e-testing',
      content: 'This is a test article created for E2E testing purposes. It contains sample content to verify that the content management system is working correctly.'
    });
    
    if (created) {
      console.log('Successfully created test content');
    } else {
      console.log('Could not create test content - this is expected if no collections exist');
    }
    
  } catch (error) {
    console.log('Could not ensure test content exists:', error);
  }
}

/**
 * Create test content (assumes user is already logged in)
 */
export async function createTestContent(page: Page, contentData?: {
  title: string;
  slug: string;
  content: string;
}) {
  const data = contentData || {
    title: 'Test Content',
    slug: 'test-content',
    content: 'This is test content for E2E testing.'
  };

  try {
    // Ensure we have a collection first
    await ensureTestCollectionExists(page);
    
    // Navigate to content creation
    await page.goto('/admin/content/new');
    
    // Check if we get the collection selection page
    try {
      // Look for collection cards (new UI)
      await page.waitForSelector('.collection-card, .grid', { timeout: 5000 });
      
      // Click on the first available collection
      const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]');
      const collectionCount = await collectionLinks.count();
      
      if (collectionCount > 0) {
        await collectionLinks.first().click();
        
        // Wait for the form to load
        await page.waitForTimeout(2000);
        
        // Fill in the form fields - try different possible field names
        const titleField = page.locator('input[name="title"], input[name="name"], input[id="title"]').first();
        if (await titleField.count() > 0) {
          await titleField.fill(data.title);
        }
        
        const slugField = page.locator('input[name="slug"], input[id="slug"]').first();
        if (await slugField.count() > 0) {
          await slugField.fill(data.slug);
        }
        
        const contentField = page.locator('textarea[name="content"], textarea[name="body"], textarea[id="content"]').first();
        if (await contentField.count() > 0) {
          await contentField.fill(data.content);
        }
        
        // Submit the form
        const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
        if (await submitButton.count() > 0) {
          await submitButton.click();
          
          // Wait for form submission
          await page.waitForTimeout(2000);
          return true;
        }
      }
    } catch (selectionError) {
      // Fall back to old model-based approach
      await page.waitForSelector('select[name="modelName"]', { timeout: 5000 });
      const models = await page.locator('select[name="modelName"] option').count();
      
      if (models > 1) {
        await page.selectOption('select[name="modelName"]', { index: 1 });
        
        // Wait for dynamic fields to load
        await page.waitForTimeout(1500);
        
        // Fill in the form fields
        await page.fill('input[name="title"]', data.title);
        await page.fill('input[name="slug"]', data.slug);
        await page.fill('textarea[name="content"]', data.content);
        
        // Submit the form
        await page.click('button[type="submit"]');
        await page.waitForTimeout(2000);
        return true;
      }
    }
    
    console.log('No collections or models available for content creation');
    return false;
  } catch (error) {
    console.log('Test content creation failed:', error);
    return false;
  }
}

/**
 * Ensure test collection exists
 */
export async function ensureTestCollectionExists(page: Page) {
  try {
    // First check if collection already exists
    await page.goto('/admin/collections');
    
    const collectionExists = await page.locator('td').filter({ hasText: TEST_DATA.collection.name }).first().isVisible({ timeout: 2000 });
    
    if (!collectionExists) {
      await createTestCollection(page);
    }
  } catch (error) {
    // Try to create collection anyway
    try {
      await createTestCollection(page);
    } catch (createError) {
      console.log('Failed to create test collection:', createError);
    }
  }
}

/**
 * Login as admin user (form submits to Better Auth /auth/sign-in/email, then redirects to /admin)
 */
export async function loginAsAdmin(page: Page) {
  await ensureAdminUserExists(page);

  await page.goto('/auth/login');
  await page.fill('[name="email"]', ADMIN_CREDENTIALS.email);
  await page.fill('[name="password"]', ADMIN_CREDENTIALS.password);
  await page.click('button[type="submit"]');

  // Login form uses fetch to /auth/sign-in/email; on success it does window.location = '/admin/dashboard'
  try {
    await page.waitForURL(/\/admin/, { timeout: 20000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 });
  } catch {
    console.log('Auto-redirect failed, navigating manually to /admin');
    await page.goto('/admin');
    await page.waitForLoadState('networkidle', { timeout: 15000 });
  }

  await expect(page).toHaveURL(/\/admin/);

  await ensureWorkflowTablesExist(page);
  await ensureWorkflowPluginActive(page);

  await page.goto('/admin');
  await page.waitForLoadState('networkidle', { timeout: 15000 });
}

/**
 * Navigate to a specific admin section
 */
export async function navigateToAdminSection(page: Page, section: 'collections' | 'content' | 'media' | 'users' | 'forms' | 'plugins') {
  // Navigate directly instead of clicking navigation links
  // This is more reliable as admin navigation may vary
  await page.goto(`/admin/${section}`);
  await page.waitForLoadState('networkidle');
}

/**
 * Create a test collection
 */
export async function createTestCollection(page: Page, collectionData = TEST_DATA.collection) {
  await navigateToAdminSection(page, 'collections');
  await page.click('a[href="/admin/collections/new"]');

  await page.fill('[name="name"]', collectionData.name);
  await page.fill('[name="displayName"]', collectionData.displayName);
  await page.fill('[name="description"]', collectionData.description);

  await page.click('button[type="submit"]');

  // Wait for form submission - either redirect or manually navigate
  try {
    await page.waitForURL('/admin/collections', { timeout: 10000 });
  } catch {
    // If no automatic redirect, navigate manually
    await page.goto('/admin/collections');
  }

  // Wait for database write and any caching to settle
  await page.waitForTimeout(2000);
}

/**
 * Delete a test collection
 */
export async function deleteTestCollection(page: Page, collectionName: string) {
  try {
    await navigateToAdminSection(page, 'collections');

    // Check if collection exists
    const collectionRow = page.locator('tr').filter({ hasText: collectionName });
    const isVisible = await collectionRow.isVisible({ timeout: 2000 });

    if (!isVisible) {
      // Collection doesn't exist, nothing to delete
      return;
    }

    // Click the row itself (rows are clickable for editing)
    await collectionRow.click();

    // Wait for edit page to load
    await page.waitForTimeout(1000);

    // Set up dialog handler before clicking delete (use once to avoid handler accumulation)
    page.once('dialog', dialog => dialog.accept());

    // Click delete button
    await page.locator('button').filter({ hasText: 'Delete Collection' }).click();

    // Wait for redirect back to collections list (shorter timeout for cleanup)
    try {
      await page.waitForURL('/admin/collections', { timeout: 5000 });
    } catch {
      // If didn't redirect, navigate manually
      await page.goto('/admin/collections');
    }
  } catch (error) {
    // If deletion fails, just continue - this is cleanup, don't log noise
    // Silent failure for cleanup operations
  }
}

/**
 * Upload a test file
 */
export async function uploadTestFile(page: Page, fileName: string = 'test-image.jpg') {
  await navigateToAdminSection(page, 'media');
  await page.locator('button').filter({ hasText: 'Upload Files' }).click();
  
  // Create a test file buffer (1x1 pixel JPEG)
  const testImageBuffer = Buffer.from([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
    0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
    0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
    0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
    0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
    0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
    0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
  ]);
  
  // Set the file to upload
  await page.setInputFiles('#file-input', {
    name: fileName,
    mimeType: 'image/jpeg',
    buffer: testImageBuffer
  });
  
  await page.click('button[type="submit"]');
  
  // Wait for upload completion
  await expect(page.locator('#upload-results')).toContainText('successful');
}

/**
 * Wait for HTMX request to complete
 */
export async function waitForHTMX(page: Page) {
  try {
    // Wait for any ongoing network requests to complete
    await page.waitForLoadState('networkidle', { timeout: 5000 });
  } catch {
    // If network idle times out, just wait a bit for HTMX
    await page.waitForTimeout(1000);
  }
}

/** Better Auth default session cookie name */
const BETTER_AUTH_SESSION_COOKIE = 'better-auth.session_token';

/**
 * Check if user is authenticated by checking for Better Auth session cookie
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
  try {
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === BETTER_AUTH_SESSION_COOKIE);
    return !!sessionCookie;
  } catch {
    return false;
  }
}

/**
 * Logout current user
 */
export async function logout(page: Page) {
  await page.goto('/auth/logout');
  await page.waitForURL(/\/auth\/login/);
  // Wait a moment for cookies to be cleared
  await page.waitForTimeout(500);
}

/**
 * Clear test data - comprehensive database cleanup
 */
export async function clearTestData(page: Page) {
  try {
    // Use public API to clean up test data (no auth required)
    const response = await page.request.post('/test-cleanup', {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (response.ok()) {
      console.log('Test data cleanup successful');
    } else {
      console.log('Test data cleanup failed:', response.status());
    }
  } catch (error) {
    // If API endpoint doesn't exist or fails, try UI-based cleanup
    console.log('API cleanup failed, attempting UI cleanup:', error);
    try {
      await loginAsAdmin(page);

      // Delete test collections
      try {
        await deleteTestCollection(page, TEST_DATA.collection.name);
        await deleteTestCollection(page, 'test_collection_e2e');
        await deleteTestCollection(page, 'test_articles');
      } catch {
        // Collections might not exist
      }

      await logout(page);
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Clean up test users (but preserve admin)
 */
export async function cleanupTestUsers(page: Page) {
  try {
    await page.request.post('/admin/api/test-cleanup/users');
  } catch (error) {
    console.log('User cleanup failed:', error);
  }
}

/**
 * Check API health
 */
export async function checkAPIHealth(page: Page) {
  const response = await page.request.get('/health');
  expect(response.ok()).toBeTruthy();
  const health = await response.json();
  expect(health.status).toBe('running');
  return health;
} 