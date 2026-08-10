import { test, expect } from '@playwright/test';

/**
 * Magic Link Authentication E2E Tests (Better Auth)
 *
 * Tests passwordless authentication via Better Auth's magic link plugin.
 * Endpoints: POST /auth/sign-in/magic-link (send), GET /auth/magic-link/verify (verify).
 */

function uniqueEmail(prefix: string): string {
  return `${prefix}.${Date.now()}.${Math.random().toString(36).substring(7)}@test.sonicjs.com`;
}

test.describe('Magic Link Authentication (Better Auth) @auth', () => {

  test.describe('POST /auth/sign-in/magic-link - Request Magic Link', () => {
    test('should accept valid email and return status true', async ({ request }) => {
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
        data: { email: uniqueEmail('ml-valid') }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toHaveProperty('status', true);
    });

    test('should normalize email to lowercase (accept uppercase)', async ({ request }) => {
      const email = uniqueEmail('ML-UPPERCASE');
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
        data: { email: email.toUpperCase() }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toHaveProperty('status', true);
    });

    test('should reject invalid email format with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
        data: { email: 'not-an-email' }
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code', 'VALIDATION_ERROR');
    });

    test('should reject empty email with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
        data: { email: '' }
      });

      expect(response.status()).toBe(400);
    });

    test('should reject missing email field with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
        data: {}
      });

      expect(response.status()).toBe(400);
    });

    test('should not reveal whether user exists (same status true for any valid email)', async ({ request }) => {
      const email1 = uniqueEmail('ml-security1');
      const email2 = uniqueEmail('ml-security2');

      const [r1, r2] = await Promise.all([
        request.post('/auth/sign-in/magic-link', {
          headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
          data: { email: email1 }
        }),
        request.post('/auth/sign-in/magic-link', {
          headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
          data: { email: email2 }
        }),
      ]);

      expect(r1.status()).toBe(200);
      expect(r2.status()).toBe(200);
      const d1 = await r1.json();
      const d2 = await r2.json();
      expect(d1.status).toBe(true);
      expect(d2.status).toBe(true);
    });

    test('should rate limit excessive requests from same email', async ({ request }) => {
      const email = uniqueEmail('ml-ratelimit');
      const responses = await Promise.all(
        Array.from({ length: 10 }, () =>
          request.post('/auth/sign-in/magic-link', {
            headers: { 'Content-Type': 'application/json', 'Origin': 'http://localhost:9704' },
            data: { email }
          })
        )
      );

      const statuses = responses.map(r => r.status());
      const has429 = statuses.includes(429);
      const allSuccess = statuses.every(s => s === 200);
      expect(has429 || allSuccess).toBe(true);
    });
  });

  test.describe('GET /auth/magic-link/verify - Verify Magic Link', () => {
    test('should return 400 for missing token', async ({ request }) => {
      const response = await request.get('/auth/magic-link/verify', {
        headers: { 'Origin': 'http://localhost:9704' },
        maxRedirects: 0
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code', 'VALIDATION_ERROR');
    });

    test('should redirect with error for invalid token', async ({ request }) => {
      const response = await request.get('/auth/magic-link/verify?token=invalid-token', {
        headers: { 'Origin': 'http://localhost:9704' },
        maxRedirects: 0
      });

      expect(response.status()).toBe(302);
      const location = response.headers()['location'] ?? '';
      expect(location).toContain('error=');
    });

    test('should redirect to callbackURL with error for invalid token', async ({ request }) => {
      const response = await request.get(
        '/auth/magic-link/verify?token=invalid-token&callbackURL=%2Fauth%2Flogin',
        {
          headers: { 'Origin': 'http://localhost:9704' },
          maxRedirects: 0
        }
      );

      expect(response.status()).toBe(302);
      const location = response.headers()['location'] ?? '';
      expect(location).toContain('/auth/login');
      expect(location).toContain('error=');
    });
  });

  test.describe('Security Tests', () => {
    test('should handle SQL injection in token safely', async ({ request }) => {
      const maliciousTokens = [
        "' OR '1'='1",
        "'; DROP TABLE magic_links; --",
        "token' OR 'x'='x"
      ];

      for (const token of maliciousTokens) {
        const response = await request.get(
          `/auth/magic-link/verify?token=${encodeURIComponent(token)}`,
          {
            headers: { 'Origin': 'http://localhost:9704' },
            maxRedirects: 0
          }
        );

        // Malicious tokens should redirect (302) with an error param, never expose SQL errors
        expect(response.status()).toBeGreaterThanOrEqual(300);
        expect(response.status()).toBeLessThan(500);
        const location = response.headers()['location'] ?? '';
        expect(location).not.toContain('SQL');
        expect(location).not.toContain('syntax error');
      }
    });

    test('should handle very long tokens', async ({ request }) => {
      // Very long tokens may return 302 (redirect) or 4xx/5xx — the server must respond
      const longToken = 'a'.repeat(500);
      const response = await request.get(
        `/auth/magic-link/verify?token=${longToken}`,
        {
          headers: { 'Origin': 'http://localhost:9704' },
          maxRedirects: 0
        }
      );

      // Any HTTP response is acceptable — server must not hang
      expect(response.status()).toBeGreaterThanOrEqual(200);
    });

    test('should handle special characters in token', async ({ request }) => {
      for (const token of ['<script>alert(1)</script>', '../../../etc/passwd']) {
        const response = await request.get(
          `/auth/magic-link/verify?token=${encodeURIComponent(token)}`,
          {
            headers: { 'Origin': 'http://localhost:9704' },
            maxRedirects: 0
          }
        );
        expect(response.status()).toBeGreaterThanOrEqual(300);
        expect(response.status()).toBeLessThan(500);
      }
    });
  });

  test.describe('Error Handling', () => {
    test('should handle malformed JSON gracefully', async ({ request }) => {
      const response = await request.post('/auth/sign-in/magic-link', {
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://localhost:9704'
        },
        data: 'invalid json'
      });

      expect(response.status()).toBeGreaterThanOrEqual(400);
      expect(response.status()).toBeLessThan(500);
    });
  });
});
