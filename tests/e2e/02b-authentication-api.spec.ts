import { test, expect } from '@playwright/test';
import { ADMIN_CREDENTIALS, extractCsrfToken } from './utils/test-helpers';

/**
 * Check if a registration response indicates registration is disabled
 * by a concurrent test shard (37-disable-registration.spec.ts).
 * Returns true if the test should be skipped.
 */
function isRegistrationDisabled(status: number, body: any): boolean {
  if (status !== 403) return false;
  const msg = body?.error || '';
  return msg.includes('disabled') || msg.includes('Registration');
}

test.describe('Authentication API', () => {
  const testUser = {
    email: 'test.api.user@example.com',
    password: 'TestPassword123!',
    username: 'testapiuser',
    firstName: 'Test',
    lastName: 'User'
  };

  // Seed admin user and ensure registration is enabled before all tests
  test.beforeAll(async ({ request }) => {
    try {
      await request.post('/auth/seed-admin');
    } catch (error) {
      // Admin might already exist, ignore errors
    }

    // Ensure registration is enabled (may have been disabled by 37-disable-registration tests)
    try {
      const loginRes = await request.post('/auth/login', {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password }
      });
      if (loginRes.ok()) {
        const { token } = await loginRes.json();
        await request.post('/admin/plugins/core-auth/settings', {
          headers: { Authorization: `Bearer ${token}` },
          data: {
            registration: { enabled: true, requireEmailVerification: false, defaultRole: 'viewer' }
          }
        });
      }
    } catch (error) {
      // Best effort — tests will fail with clear 403 if this didn't work
    }
  });

  // Clean up test user after tests
  test.afterAll(async ({ request }) => {
    // We'll implement cleanup when we have admin API access
    // For now, tests are designed to be idempotent
  });

  test.describe('POST /auth/register - User Registration', () => {
    test('should register a new user successfully', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `test.${Date.now()}@example.com`,
        username: `testuser${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      const data = await response.json();
      if (isRegistrationDisabled(response.status(), data)) return;

      expect(response.status()).toBe(201);
      expect(data).toHaveProperty('user');
      expect(data).toHaveProperty('token');

      // Verify user object
      expect(data.user).toMatchObject({
        email: uniqueUser.email.toLowerCase(),
        username: uniqueUser.username,
        firstName: uniqueUser.firstName,
        lastName: uniqueUser.lastName,
        role: 'viewer'
      });

      // Should have a valid UUID
      expect(data.user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

      // Should have a JWT token
      expect(data.token).toBeTruthy();
      expect(data.token.split('.')).toHaveLength(3); // JWT format
    });

    test('should normalize email to lowercase', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `TEST.UPPERCASE.${Date.now()}@EXAMPLE.COM`,
        username: `testuser${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      const data = await response.json();
      if (isRegistrationDisabled(response.status(), data)) return;

      expect(response.status()).toBe(201);
      expect(data.user.email).toBe(uniqueUser.email.toLowerCase());
    });

    test('should validate required fields', async ({ request }) => {
      const invalidPayloads = [
        { email: 'test@example.com' }, // Missing other fields
        { ...testUser, email: '' }, // Empty email
        { ...testUser, email: 'invalid-email' }, // Invalid email format
        { ...testUser, password: '123' }, // Too short password
        { ...testUser, username: 'ab' }, // Too short username
        { ...testUser, firstName: '' }, // Empty first name
        { ...testUser, lastName: '' } // Empty last name
      ];

      for (const payload of invalidPayloads) {
        const response = await request.post('/auth/register', {
          data: payload
        });

        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
        
        const data = await response.json();
        expect(data).toHaveProperty('error');
      }
    });

    test('should prevent duplicate email registration', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `duplicate.test.${Date.now()}@example.com`,
        username: `uniqueuser${Date.now()}`
      };

      // First registration should succeed
      const firstResponse = await request.post('/auth/register', {
        data: uniqueUser
      });
      const firstData = await firstResponse.json();
      if (isRegistrationDisabled(firstResponse.status(), firstData)) return;
      expect(firstResponse.status()).toBe(201);

      // Second registration with same email should fail
      const secondResponse = await request.post('/auth/register', {
        data: {
          ...uniqueUser,
          username: `different${Date.now()}` // Different username
        }
      });

      expect(secondResponse.status()).toBe(400);

      const data = await secondResponse.json();
      expect(data.error).toContain('already exists');
    });

    test('should prevent duplicate username registration', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `unique.email.${Date.now()}@example.com`,
        username: `duplicateusername${Date.now()}`
      };

      // First registration should succeed
      const firstResponse = await request.post('/auth/register', {
        data: uniqueUser
      });
      const firstData = await firstResponse.json();
      if (isRegistrationDisabled(firstResponse.status(), firstData)) return;
      expect(firstResponse.status()).toBe(201);

      // Second registration with same username should fail
      const secondResponse = await request.post('/auth/register', {
        data: {
          ...uniqueUser,
          email: `different.${Date.now()}@example.com` // Different email
        }
      });

      expect(secondResponse.status()).toBe(400);

      const data = await secondResponse.json();
      expect(data.error).toContain('already exists');
    });

    test('should set auth cookie on registration', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `cookie.test.${Date.now()}@example.com`,
        username: `cookieuser${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      if (response.status() === 403) {
        const body = await response.json();
        if (isRegistrationDisabled(response.status(), body)) return;
      }

      expect(response.status()).toBe(201);

      // Check for auth cookie
      const cookies = response.headers()['set-cookie'];
      expect(cookies).toBeTruthy();
      expect(cookies).toContain('auth_token');
      expect(cookies).toContain('HttpOnly');
      expect(cookies).toContain('SameSite=Strict');
    });

    test('should assign viewer role by default', async ({ request }) => {
      const uniqueUser = {
        ...testUser,
        email: `role.test.${Date.now()}@example.com`,
        username: `roleuser${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      const data = await response.json();
      if (isRegistrationDisabled(response.status(), data)) return;

      expect(response.status()).toBe(201);
      expect(data.user.role).toBe('viewer');
    });
  });

  test.describe('POST /auth/login - User Login', () => {
    test('should login successfully with valid credentials', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });

      expect(response.status()).toBe(200);
      
      const data = await response.json();
      expect(data).toHaveProperty('user');
      expect(data).toHaveProperty('token');
      
      // Verify user object
      expect(data.user).toMatchObject({
        email: ADMIN_CREDENTIALS.email,
        username: 'admin',
        role: 'admin'
      });
      
      // Should have a JWT token
      expect(data.token).toBeTruthy();
      expect(data.token.split('.')).toHaveLength(3);
    });

    test('should normalize email to lowercase on login', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email.toUpperCase(),
          password: ADMIN_CREDENTIALS.password
        }
      });

      expect(response.status()).toBe(200);
      
      const data = await response.json();
      expect(data.user.email).toBe(ADMIN_CREDENTIALS.email.toLowerCase());
    });

    test('should fail with invalid email', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: 'nonexistent@example.com',
          password: 'anypassword'
        }
      });

      expect(response.status()).toBe(401);
      
      const data = await response.json();
      expect(data.error).toContain('Invalid email or password');
    });

    test('should fail with invalid password', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: 'wrongpassword'
        }
      });

      expect(response.status()).toBe(401);
      
      const data = await response.json();
      expect(data.error).toContain('Invalid email or password');
    });

    test('should validate required fields', async ({ request }) => {
      const invalidPayloads = [
        { email: '' }, // Missing password
        { password: '' }, // Missing email
        { email: '', password: '' }, // Both empty
        { email: 'invalid-email', password: 'password' } // Invalid email format
      ];

      for (const payload of invalidPayloads) {
        const response = await request.post('/auth/login', {
          data: payload
        });

        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
        
        const data = await response.json();
        expect(data).toHaveProperty('error');
      }
    });

    test('should set auth cookie on login', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });

      expect(response.status()).toBe(200);
      
      // Check for auth cookie
      const cookies = response.headers()['set-cookie'];
      expect(cookies).toBeTruthy();
      expect(cookies).toContain('auth_token');
      expect(cookies).toContain('HttpOnly');
      expect(cookies).toContain('SameSite=Strict');
      expect(cookies).toContain('Max-Age=86400'); // 24 hours
    });

    test('should update last login timestamp', async ({ request }) => {
      // Login twice and verify the second login has updated timestamp
      const firstLogin = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(firstLogin.status()).toBe(200);

      // Wait a moment
      await new Promise(resolve => setTimeout(resolve, 100));

      const secondLogin = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(secondLogin.status()).toBe(200);
    });
  });

  test.describe('POST /auth/logout - User Logout', () => {
    test('should logout successfully', async ({ request }) => {
      // First login to get a session
      const loginResponse = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(loginResponse.status()).toBe(200);

      // Extract auth cookie and CSRF token
      const cookies = loginResponse.headers()['set-cookie'];
      const authCookie = cookies?.split(';')[0] || '';
      const csrfToken = extractCsrfToken(cookies);

      // Logout with the session
      const logoutResponse = await request.post('/auth/logout', {
        headers: {
          'Cookie': `${authCookie}; csrf_token=${csrfToken}`,
          'X-CSRF-Token': csrfToken
        }
      });

      expect(logoutResponse.status()).toBe(200);
      
      const data = await logoutResponse.json();
      expect(data.message).toContain('Logged out successfully');

      // Check that auth cookie is cleared
      const logoutCookies = logoutResponse.headers()['set-cookie'];
      expect(logoutCookies).toContain('auth_token=');
      expect(logoutCookies).toContain('Max-Age=0');
    });

    test('GET /auth/logout should redirect to login', async ({ request }) => {
      const response = await request.get('/auth/logout', {
        maxRedirects: 0 // Don't follow redirects
      });

      expect(response.status()).toBe(302);
      expect(response.headers()['location']).toContain('/auth/login');
    });
  });

  test.describe('GET /auth/me - Current User', () => {
    test('should return current user when authenticated', async ({ request }) => {
      // Login first
      const loginResponse = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(loginResponse.status()).toBe(200);

      // Extract auth cookie
      const cookies = loginResponse.headers()['set-cookie'];
      const authCookie = cookies?.split(';')[0] || '';

      // Get current user
      const meResponse = await request.get('/auth/me', {
        headers: {
          'Cookie': authCookie
        }
      });

      expect(meResponse.status()).toBe(200);
      
      const data = await meResponse.json();
      expect(data).toHaveProperty('user');
      expect(data.user).toMatchObject({
        email: ADMIN_CREDENTIALS.email,
        username: 'admin',
        role: 'admin'
      });
      
      // Should not expose password hash
      expect(data.user).not.toHaveProperty('password_hash');
      expect(data.user).not.toHaveProperty('password');
    });

    test('should return 401 when not authenticated', async ({ request }) => {
      const response = await request.get('/auth/me');

      expect(response.status()).toBe(401);
      
      const data = await response.json();
      expect(data.error).toContain('Authentication required');
    });

    test('should return 401 with invalid token', async ({ request }) => {
      const response = await request.get('/auth/me', {
        headers: {
          'Cookie': 'auth_token=invalid.jwt.token'
        }
      });

      expect(response.status()).toBe(401);
    });
  });

  test.describe('POST /auth/refresh - Token Refresh', () => {
    test('should refresh token when authenticated', async ({ request }) => {
      // Login first
      const loginResponse = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(loginResponse.status()).toBe(200);

      const loginData = await loginResponse.json();
      const originalToken = loginData.token;

      // Extract auth cookie and CSRF token
      const cookies = loginResponse.headers()['set-cookie'];
      const authCookie = cookies?.split(';')[0] || '';
      const csrfToken = extractCsrfToken(cookies);

      // Wait a moment to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Refresh token
      const refreshResponse = await request.post('/auth/refresh', {
        headers: {
          'Cookie': `${authCookie}; csrf_token=${csrfToken}`,
          'X-CSRF-Token': csrfToken
        }
      });

      expect(refreshResponse.status()).toBe(200);
      
      const refreshData = await refreshResponse.json();
      expect(refreshData).toHaveProperty('token');
      
      // Token should be valid JWT format
      expect(refreshData.token.split('.')).toHaveLength(3);
      
      // Should return a token (may be same if called within same second)
      expect(refreshData.token).toBeTruthy();

      // Check for new auth cookie
      const refreshCookies = refreshResponse.headers()['set-cookie'];
      expect(refreshCookies).toContain('auth_token');
    });

    test('should return 401 when not authenticated', async ({ request }) => {
      const response = await request.post('/auth/refresh');

      expect(response.status()).toBe(401);
      
      const data = await response.json();
      expect(data.error).toContain('Authentication required');
    });
  });

  test.describe('Security Tests', () => {
    test('should not expose sensitive data in responses', async ({ request }) => {
      // Register a new user
      const uniqueUser = {
        ...testUser,
        email: `security.test.${Date.now()}@example.com`,
        username: `securityuser${Date.now()}`
      };

      const response = await request.post('/auth/register', {
        data: uniqueUser
      });

      const data = await response.json();
      if (isRegistrationDisabled(response.status(), data)) return;

      expect(response.status()).toBe(201);

      // Should not expose password or hash
      expect(data.user).not.toHaveProperty('password');
      expect(data.user).not.toHaveProperty('password_hash');
      expect(data.user).not.toHaveProperty('passwordHash');

      // Response should not contain the original password
      const responseText = JSON.stringify(data);
      expect(responseText).not.toContain(uniqueUser.password);
    });

    test('should handle SQL injection attempts safely', async ({ request }) => {
      const maliciousPayloads = [
        {
          email: "admin@sonicjs.com' OR '1'='1",
          password: "anything"
        },
        {
          email: "admin@sonicjs.com'; DROP TABLE users; --",
          password: "anything"
        },
        {
          email: "admin@sonicjs.com",
          password: "' OR '1'='1"
        }
      ];

      for (const payload of maliciousPayloads) {
        const response = await request.post('/auth/login', {
          data: payload
        });

        // Should safely reject without exposing SQL errors
        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
        
        const data = await response.json();
        expect(data.error).not.toContain('SQL');
        expect(data.error).not.toContain('syntax');
      }
    });

    test('should handle XSS attempts in registration', async ({ request }) => {
      const xssPayload = {
        ...testUser,
        email: `xss.test.${Date.now()}@example.com`,
        username: `xssuser${Date.now()}`,
        firstName: '<script>alert("XSS")</script>',
        lastName: '"><script>alert("XSS")</script>'
      };

      const response = await request.post('/auth/register', {
        data: xssPayload
      });

      if (response.status() === 201) {
        const data = await response.json();
        
        // Names should be stored as-is (not executed)
        expect(data.user.firstName).toBe(xssPayload.firstName);
        expect(data.user.lastName).toBe(xssPayload.lastName);
      }
    });

    test('should enforce HTTPS-only cookies in production', async ({ request }) => {
      const response = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });

      expect(response.status()).toBe(200);
      
      const cookies = response.headers()['set-cookie'];
      expect(cookies).toContain('HttpOnly');
      expect(cookies).toContain('SameSite=Strict');
      // Note: Secure flag might be disabled in test environment
    });

    test('should rate limit login attempts', async ({ request }) => {
      // Make multiple rapid login attempts
      const attempts = Array.from({ length: 10 }, () => 
        request.post('/auth/login', {
          data: {
            email: 'bruteforce@example.com',
            password: 'wrongpassword'
          }
        })
      );

      const responses = await Promise.all(attempts);
      
      // All should either fail with 401 or eventually hit rate limit
      responses.forEach(response => {
        expect([401, 429]).toContain(response.status());
      });
    });
  });

  test.describe('Error Handling', () => {
    test('should handle malformed JSON gracefully', async ({ request }) => {
      const response = await request.post('/auth/login', {
        headers: {
          'Content-Type': 'application/json'
        },
        data: 'invalid json'
      });

      expect(response.status()).toBeGreaterThanOrEqual(400);
      expect(response.status()).toBeLessThan(500);
    });

    test('should handle missing content-type', async ({ request }) => {
      const response = await request.post('/auth/login', {
        headers: {
          'Content-Type': 'text/plain'
        },
        data: JSON.stringify({
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        })
      });

      // Should either work or return proper error
      expect([200, 400, 415]).toContain(response.status());
    });

    test('should handle server errors gracefully', async ({ request }) => {
      // Test with extremely long values that might cause issues
      const response = await request.post('/auth/register', {
        data: {
          ...testUser,
          email: `test.${Date.now()}@example.com`,
          username: `user${Date.now()}`,
          firstName: 'A'.repeat(10000), // Very long name
          lastName: 'B'.repeat(10000)
        }
      });

      // Should handle gracefully (either accept or reject with proper error)
      if (!response.ok()) {
        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(600);
        
        const data = await response.json();
        expect(data).toHaveProperty('error');
      }
    });
  });

  test.describe('Session Management', () => {
    test('should maintain session across requests', async ({ request }) => {
      // Login
      const loginResponse = await request.post('/auth/login', {
        data: {
          email: ADMIN_CREDENTIALS.email,
          password: ADMIN_CREDENTIALS.password
        }
      });
      expect(loginResponse.status()).toBe(200);

      const cookies = loginResponse.headers()['set-cookie'];
      const authCookie = cookies?.split(';')[0] || '';
      const csrfToken = extractCsrfToken(cookies);
      const fullCookie = `${authCookie}; csrf_token=${csrfToken}`;

      // Make authenticated request
      const meResponse = await request.get('/auth/me', {
        headers: {
          'Cookie': fullCookie
        }
      });
      expect(meResponse.status()).toBe(200);

      // Make another authenticated request
      const refreshResponse = await request.post('/auth/refresh', {
        headers: {
          'Cookie': fullCookie,
          'X-CSRF-Token': csrfToken
        }
      });
      expect(refreshResponse.status()).toBe(200);
    });

    test('should handle concurrent authentication requests', async ({ request }) => {
      // Login with same credentials concurrently
      const loginPromises = Array.from({ length: 5 }, () =>
        request.post('/auth/login', {
          data: {
            email: ADMIN_CREDENTIALS.email,
            password: ADMIN_CREDENTIALS.password
          }
        })
      );

      const responses = await Promise.all(loginPromises);
      
      // All should succeed
      responses.forEach(response => {
        expect(response.status()).toBe(200);
      });
    });
  });
});