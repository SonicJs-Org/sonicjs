import { test, expect } from './fixtures';
import { ADMIN_CREDENTIALS, requestLoginToken } from './utils/test-helpers';

test.describe('User Management - Hard Delete @auth @lock-auth-login @lock-auth-registration', () => {
  let authToken: string;

  test.beforeAll(async ({ request }) => {
    // `requestLoginToken`, not a bare POST: /auth/login is rate limited to 30/min per IP and the
    // whole suite shares one IP. The `@lock-auth-login` tag serialises the *tests* that drain that
    // bucket, but this is a beforeAll hook — it runs before any test's fixtures are set up, so the
    // lock does not cover it. A 429 here used to leave `authToken` undefined and every test below
    // failed on its DELETE with a bare `expect(deleteResponse.ok()).toBeTruthy()` → false, which
    // pointed at the wrong endpoint entirely.
    authToken = await requestLoginToken(request, ADMIN_CREDENTIALS);
  });

  test('should soft delete a user via API (deactivate)', async ({ request }) => {
    // Create a test user
    const timestamp = Date.now();
    const testEmail = `softdelete${timestamp}@example.com`;
    const testUsername = `softdelete${timestamp}`;

    const registerResponse = await request.post('/auth/register', {
      data: {
        email: testEmail,
        username: testUsername,
        password: 'TestPassword123!',
        firstName: 'Soft',
        lastName: 'Delete'
      }
    });

    expect(registerResponse.ok()).toBeTruthy();
    const userData = await registerResponse.json();
    const userId = userData.user?.id;
    expect(userId).toBeDefined();

    // Soft delete the user (hardDelete: false)
    const deleteResponse = await request.delete(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      data: {
        hardDelete: false
      }
    });

    expect(deleteResponse.ok()).toBeTruthy();
    const deleteData = await deleteResponse.json();
    expect(deleteData.success).toBe(true);
    expect(deleteData.message).toContain('deactivated');

    // Verify user still exists but is inactive
    const checkResponse = await request.get(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    // Debug: log the response if it's not OK
    if (!checkResponse.ok()) {
      console.error('GET user request details:');
      console.error('  URL:', `/admin/users/${userId}`);
      console.error('  Status:', checkResponse.status());
      console.error('  Status Text:', checkResponse.statusText());
      try {
        const errorData = await checkResponse.json();
        console.error('  Response:', JSON.stringify(errorData));
      } catch (e) {
        const responseText = await checkResponse.text();
        console.error('  Response (text):', responseText.substring(0, 500));
      }
    }

    expect(checkResponse.ok()).toBeTruthy();

    const checkData = await checkResponse.json();
    expect(checkData.user).toBeDefined();
    expect(checkData.user.is_active).toBe(0);
  });

  test('should hard delete a user via API (permanent deletion)', async ({ request }) => {
    // Create a test user
    const timestamp = Date.now();
    const testEmail = `harddelete${timestamp}@example.com`;
    const testUsername = `harddelete${timestamp}`;

    const registerResponse = await request.post('/auth/register', {
      data: {
        email: testEmail,
        username: testUsername,
        password: 'TestPassword123!',
        firstName: 'Hard',
        lastName: 'Delete'
      }
    });

    expect(registerResponse.ok()).toBeTruthy();
    const userData = await registerResponse.json();
    const userId = userData.user?.id;
    expect(userId).toBeDefined();

    // Hard delete the user (hardDelete: true)
    const deleteResponse = await request.delete(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      data: {
        hardDelete: true
      }
    });

    expect(deleteResponse.ok()).toBeTruthy();
    const deleteData = await deleteResponse.json();
    expect(deleteData.success).toBe(true);
    expect(deleteData.message).toContain('permanently');

    // Verify user no longer exists
    const checkResponse = await request.get(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    expect(checkResponse.status()).toBe(404);
  });

  test('should default to soft delete when hardDelete is not specified', async ({ request }) => {
    // Create a test user
    const timestamp = Date.now();
    const testEmail = `defaultdelete${timestamp}@example.com`;
    const testUsername = `defaultdelete${timestamp}`;

    const registerResponse = await request.post('/auth/register', {
      data: {
        email: testEmail,
        username: testUsername,
        password: 'TestPassword123!',
        firstName: 'Default',
        lastName: 'Delete'
      }
    });

    expect(registerResponse.ok()).toBeTruthy();
    const userData = await registerResponse.json();
    const userId = userData.user?.id;
    expect(userId).toBeDefined();

    // Delete without specifying hardDelete (should default to soft delete)
    const deleteResponse = await request.delete(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    expect(deleteResponse.ok()).toBeTruthy();
    const deleteData = await deleteResponse.json();
    expect(deleteData.success).toBe(true);

    // Verify user still exists but is inactive
    const checkResponse = await request.get(`/admin/users/${userId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    // Debug: log the response if it's not OK
    if (!checkResponse.ok()) {
      const errorData = await checkResponse.json();
      console.error('GET user failed (default delete):', checkResponse.status(), errorData);
    }

    expect(checkResponse.ok()).toBeTruthy();

    const checkData = await checkResponse.json();
    expect(checkData.user).toBeDefined();
    expect(checkData.user.is_active).toBe(0);
  });
});
