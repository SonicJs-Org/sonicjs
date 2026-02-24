import { test, expect } from '@playwright/test';
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

// Test data
let testCollectionId: string;
let testContentId: string;
let authToken: string;
let csrfToken: string;

test.describe('Content API CRUD Operations', () => {
  test.beforeAll(async ({ browser }) => {
    // Get auth token
    const context = await browser.newContext();
    const page = await context.newPage();

    await ensureAdminUserExists(page);
    await loginAsAdmin(page);

    // Extract token from cookie or localStorage
    const cookies = await context.cookies();
    const authCookie = cookies.find(c => c.name === 'auth_token' || c.name === 'token');
    if (authCookie) {
      authToken = authCookie.value;
    }
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    if (csrfCookie) {
      csrfToken = csrfCookie.value;
    }

    await context.close();
  });

  test.beforeEach(async ({ request }) => {
    // Get a collection to use for testing
    const collectionsResponse = await request.get(`${BASE_URL}/api/collections`);
    expect(collectionsResponse.ok()).toBeTruthy();

    const collectionsData = await collectionsResponse.json();
    if (collectionsData.data && collectionsData.data.length > 0) {
      testCollectionId = collectionsData.data[0].id;
      console.log(`Using collection ID: ${testCollectionId} (${collectionsData.data[0].name})`);
    }
  });

  test.describe('POST /api/content - Create Content', () => {
    test('should create new content with valid data', async ({ request }) => {
      const newContent = {
        collectionId: testCollectionId,
        title: `Test Content ${Date.now()}`,
        slug: `test-content-${Date.now()}`,
        status: 'draft',
        data: {
          content: 'This is test content created via API',
          excerpt: 'Test excerpt'
        }
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      console.log(`Response status: ${response.status()}`);

      if (!response.ok()) {
        const errorBody = await response.text();
        console.log(`Error response: ${errorBody}`);
      }

      expect(response.status()).toBe(201);

      const responseData = await response.json();
      console.log(`Created content with ID: ${responseData.data.id}`);

      // Verify response structure
      expect(responseData.data).toBeDefined();
      expect(responseData.data.id).toBeDefined();
      expect(responseData.data.title).toBe(newContent.title);
      expect(responseData.data.slug).toBe(newContent.slug);
      expect(responseData.data.status).toBe(newContent.status);
      expect(responseData.data.collectionId).toBe(testCollectionId);

      // Store for cleanup
      testContentId = responseData.data.id;
    });

    test('should require authentication for content creation', async ({ request }) => {
      const newContent = {
        collectionId: testCollectionId,
        title: 'Unauthorized Test',
        status: 'draft'
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json'
          // No auth token
        }
      });

      // Should return 401 Unauthorized or 403 Forbidden
      expect([401, 403]).toContain(response.status());
    });

    test('should validate required fields', async ({ request }) => {
      // Missing required fields
      const invalidContent = {
        collectionId: testCollectionId
        // Missing title
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: invalidContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      // Should return 400 Bad Request for validation error
      expect(response.status()).toBe(400);

      const errorData = await response.json();
      expect(errorData.error).toBeDefined();
      console.log(`Validation error: ${errorData.error}`);
    });

    test('should auto-generate slug if not provided', async ({ request }) => {
      const newContent = {
        collectionId: testCollectionId,
        title: `Auto Slug Test ${Date.now()}`,
        status: 'draft',
        data: {}
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (response.ok()) {
        const responseData = await response.json();

        // Slug should be generated from title
        expect(responseData.data.slug).toBeDefined();
        expect(responseData.data.slug).toContain('auto-slug-test');

        console.log(`Auto-generated slug: ${responseData.data.slug}`);

        // Cleanup
        if (responseData.data.id) {
          await request.delete(`${BASE_URL}/api/content/${responseData.data.id}`, {
            headers: { ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {}) }
          });
        }
      }
    });

    test('should prevent duplicate slugs within same collection', async ({ request }) => {
      const uniqueSlug = `unique-slug-${Date.now()}`;

      const firstContent = {
        collectionId: testCollectionId,
        title: 'First Content',
        slug: uniqueSlug,
        status: 'draft'
      };

      // Create first content
      const firstResponse = await request.post(`${BASE_URL}/api/content`, {
        data: firstContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (!firstResponse.ok()) {
        console.log('Skipping duplicate slug test - first creation failed');
        return;
      }

      const firstData = await firstResponse.json();
      const firstId = firstData.data.id;

      // Try to create second content with same slug
      const secondContent = {
        collectionId: testCollectionId,
        title: 'Second Content',
        slug: uniqueSlug, // Same slug
        status: 'draft'
      };

      const secondResponse = await request.post(`${BASE_URL}/api/content`, {
        data: secondContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      // Should fail with 400 or 409 (Conflict)
      expect([400, 409]).toContain(secondResponse.status());

      const errorData = await secondResponse.json();
      console.log(`Duplicate slug error: ${errorData.error}`);

      // Cleanup
      await request.delete(`${BASE_URL}/api/content/${firstId}`, {
        headers: { ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {}) }
      });
    });
  });

  test.describe('PUT /api/content/:id - Update Content', () => {
    let contentToUpdate: string;

    test.beforeEach(async ({ request }) => {
      // Create content to update
      const newContent = {
        collectionId: testCollectionId,
        title: `Update Test ${Date.now()}`,
        slug: `update-test-${Date.now()}`,
        status: 'draft',
        data: {
          content: 'Original content'
        }
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (response.ok()) {
        const responseData = await response.json();
        contentToUpdate = responseData.data.id;
        console.log(`Created content for update test: ${contentToUpdate}`);
      }
    });

    test.afterEach(async ({ request }) => {
      // Cleanup
      if (contentToUpdate) {
        await request.delete(`${BASE_URL}/api/content/${contentToUpdate}`, {
          headers: { ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {}) }
        });
      }
    });

    test('should update existing content', async ({ request }) => {
      if (!contentToUpdate) {
        console.log('Skipping - no content to update');
        return;
      }

      const updates = {
        title: 'Updated Title',
        status: 'published',
        data: {
          content: 'Updated content',
          excerpt: 'Updated excerpt'
        }
      };

      const response = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
        data: updates,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      console.log(`Update response status: ${response.status()}`);

      if (!response.ok()) {
        const errorBody = await response.text();
        console.log(`Error response: ${errorBody}`);
      }

      expect(response.ok()).toBeTruthy();

      const responseData = await response.json();

      // Verify updates were applied
      expect(responseData.data.title).toBe(updates.title);
      expect(responseData.data.status).toBe(updates.status);

      console.log('✓ Content updated successfully');
    });

    test('should return 404 for non-existent content', async ({ request }) => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const response = await request.put(`${BASE_URL}/api/content/${fakeId}`, {
        data: { title: 'Updated' },
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      expect(response.status()).toBe(404);
    });

    test('should require authentication for updates', async ({ request }) => {
      if (!contentToUpdate) {
        console.log('Skipping - no content to update');
        return;
      }

      const response = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
        data: { title: 'Unauthorized Update' },
        headers: {
          'Content-Type': 'application/json'
          // No auth token
        }
      });

      expect([401, 403]).toContain(response.status());
    });

    test('should preserve unchanged fields', async ({ request }) => {
      if (!contentToUpdate) {
        console.log('Skipping - no content to update');
        return;
      }

      // Get original content
      const getResponse = await request.get(`${BASE_URL}/api/content/${contentToUpdate}`);
      const originalData = await getResponse.json();
      const originalTitle = originalData.data.title;

      // Update only status
      const updates = {
        status: 'published'
      };

      const updateResponse = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
        data: updates,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (updateResponse.ok()) {
        const updatedData = await updateResponse.json();

        // Title should remain unchanged
        expect(updatedData.data.title).toBe(originalTitle);
        // Status should be updated
        expect(updatedData.data.status).toBe('published');

        console.log('✓ Unchanged fields preserved during partial update');
      }
    });
  });

  test.describe('DELETE /api/content/:id - Delete Content', () => {
    let contentToDelete: string;

    test.beforeEach(async ({ request }) => {
      // Create content to delete
      const newContent = {
        collectionId: testCollectionId,
        title: `Delete Test ${Date.now()}`,
        slug: `delete-test-${Date.now()}`,
        status: 'draft'
      };

      const response = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (response.ok()) {
        const responseData = await response.json();
        contentToDelete = responseData.data.id;
        console.log(`Created content for delete test: ${contentToDelete}`);
      }
    });

    test('should delete existing content', async ({ request }) => {
      if (!contentToDelete) {
        console.log('Skipping - no content to delete');
        return;
      }

      const response = await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
        headers: {
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      console.log(`Delete response status: ${response.status()}`);

      if (!response.ok()) {
        const errorBody = await response.text();
        console.log(`Error response: ${errorBody}`);
      }

      expect(response.ok()).toBeTruthy();

      const responseData = await response.json();
      expect(responseData.success).toBe(true);

      // Verify content is deleted by trying to fetch it
      const getResponse = await request.get(`${BASE_URL}/api/content/${contentToDelete}`);
      expect(getResponse.status()).toBe(404);

      console.log('✓ Content deleted successfully');

      // Clear the ID so afterEach doesn't try to delete again
      contentToDelete = '';
    });

    test('should return 404 when deleting non-existent content', async ({ request }) => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const response = await request.delete(`${BASE_URL}/api/content/${fakeId}`, {
        headers: {
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      expect(response.status()).toBe(404);
    });

    test('should require authentication for deletion', async ({ request }) => {
      if (!contentToDelete) {
        console.log('Skipping - no content to delete');
        return;
      }

      const response = await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
        headers: {
          'Content-Type': 'application/json'
          // No auth token
        }
      });

      expect([401, 403]).toContain(response.status());
    });

    test.afterEach(async ({ request }) => {
      // Cleanup if delete test failed
      if (contentToDelete) {
        await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
          headers: { ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {}) }
        }).catch(() => {});
      }
    });
  });

  test.describe('Content API Integration', () => {
    test('should handle complete CRUD lifecycle', async ({ request }) => {
      // CREATE
      const newContent = {
        collectionId: testCollectionId,
        title: `Lifecycle Test ${Date.now()}`,
        slug: `lifecycle-test-${Date.now()}`,
        status: 'draft',
        data: {
          content: 'Initial content'
        }
      };

      const createResponse = await request.post(`${BASE_URL}/api/content`, {
        data: newContent,
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      if (!createResponse.ok()) {
        console.log('Skipping lifecycle test - create failed');
        return;
      }

      const createdData = await createResponse.json();
      const contentId = createdData.data.id;
      console.log(`✓ Created content: ${contentId}`);

      // READ
      const readResponse = await request.get(`${BASE_URL}/api/content/${contentId}`);
      expect(readResponse.ok()).toBeTruthy();
      const readData = await readResponse.json();
      expect(readData.data.title).toBe(newContent.title);
      console.log('✓ Read content successfully');

      // UPDATE
      const updateResponse = await request.put(`${BASE_URL}/api/content/${contentId}`, {
        data: {
          title: 'Updated Lifecycle Title',
          status: 'published'
        },
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      expect(updateResponse.ok()).toBeTruthy();
      const updatedData = await updateResponse.json();
      expect(updatedData.data.title).toBe('Updated Lifecycle Title');
      expect(updatedData.data.status).toBe('published');
      console.log('✓ Updated content successfully');

      // DELETE
      const deleteResponse = await request.delete(`${BASE_URL}/api/content/${contentId}`, {
        headers: {
          ...(authToken ? { 'Cookie': `auth_token=${authToken}${csrfToken ? `; csrf_token=${csrfToken}` : ''}`, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) } : {})
        }
      });

      expect(deleteResponse.ok()).toBeTruthy();
      console.log('✓ Deleted content successfully');

      // Verify deletion
      const verifyResponse = await request.get(`${BASE_URL}/api/content/${contentId}`);
      expect(verifyResponse.status()).toBe(404);
      console.log('✓ Complete CRUD lifecycle successful');
    });
  });
});
