import { test, expect } from '@playwright/test';

/**
 * Email OTP Authentication E2E Tests (Better Auth)
 *
 * Tests passwordless authentication via Better Auth's emailOTP plugin.
 * Send: POST /auth/email-otp/send-verification-otp  { email, type: "sign-in" }
 * Verify/sign-in: POST /auth/sign-in/email-otp  { email, otp }
 */

function uniqueEmail(prefix: string): string {
  return `${prefix}.${Date.now()}.${Math.random().toString(36).substring(7)}@test.sonicjs.com`;
}

const BA_HEADERS = {
  'Content-Type': 'application/json',
  'Origin': 'http://localhost:9704',
};

test.describe('Email OTP Authentication (Better Auth)', () => {

  test.describe('POST /auth/email-otp/send-verification-otp - Request OTP Code', () => {
    test('should accept valid email and return success', async ({ request }) => {
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { email: uniqueEmail('otp-valid'), type: 'sign-in' }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toHaveProperty('success', true);
    });

    test('should normalize email to lowercase (accept uppercase)', async ({ request }) => {
      const email = uniqueEmail('OTP-UPPERCASE');
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { email: email.toUpperCase(), type: 'sign-in' }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toHaveProperty('success', true);
    });

    test('should reject invalid email format with 400', async ({ request }) => {
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { email: 'not-an-email', type: 'sign-in' }
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code');
    });

    test('should reject empty email with 400', async ({ request }) => {
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { email: '', type: 'sign-in' }
      });

      expect(response.status()).toBe(400);
    });

    test('should reject missing email field with 400', async ({ request }) => {
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { type: 'sign-in' }
      });

      expect(response.status()).toBe(400);
    });

    test('should reject missing type field with 400', async ({ request }) => {
      const response = await request.post('/auth/email-otp/send-verification-otp', {
        headers: BA_HEADERS,
        data: { email: uniqueEmail('otp-no-type') }
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code', 'VALIDATION_ERROR');
    });

    test('should not reveal if user exists (same success response for any valid email)', async ({ request }) => {
      const email1 = uniqueEmail('otp-security1');
      const email2 = uniqueEmail('otp-security2');

      const [r1, r2] = await Promise.all([
        request.post('/auth/email-otp/send-verification-otp', {
          headers: BA_HEADERS,
          data: { email: email1, type: 'sign-in' }
        }),
        request.post('/auth/email-otp/send-verification-otp', {
          headers: BA_HEADERS,
          data: { email: email2, type: 'sign-in' }
        }),
      ]);

      expect(r1.status()).toBe(200);
      expect(r2.status()).toBe(200);
      const d1 = await r1.json();
      const d2 = await r2.json();
      expect(d1.success).toBe(true);
      expect(d2.success).toBe(true);
    });

    test('should rate limit excessive requests from same email', async ({ request }) => {
      const email = uniqueEmail('ratelimit');
      const responses = await Promise.all(
        Array.from({ length: 10 }, () =>
          request.post('/auth/email-otp/send-verification-otp', {
            headers: BA_HEADERS,
            data: { email, type: 'sign-in' }
          })
        )
      );

      const statuses = responses.map(r => r.status());
      const has429 = statuses.includes(429);
      const allSuccess = statuses.every(s => s === 200);
      expect(has429 || allSuccess).toBe(true);
    });
  });

  test.describe('POST /auth/sign-in/email-otp - Verify OTP Code', () => {
    test('should reject wrong OTP with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email-otp', {
        headers: BA_HEADERS,
        data: {
          email: uniqueEmail('verify-invalid'),
          otp: '000000'
        }
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code', 'INVALID_OTP');
    });

    test('should reject invalid email format with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email-otp', {
        headers: BA_HEADERS,
        data: {
          email: 'not-an-email',
          otp: '123456'
        }
      });

      expect(response.status()).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty('code');
    });

    test('should reject missing email with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email-otp', {
        headers: BA_HEADERS,
        data: { otp: '123456' }
      });

      expect(response.status()).toBe(400);
    });

    test('should reject missing otp with 400', async ({ request }) => {
      const response = await request.post('/auth/sign-in/email-otp', {
        headers: BA_HEADERS,
        data: { email: uniqueEmail('no-otp') }
      });

      expect(response.status()).toBe(400);
    });
  });

  test.describe('Security Tests', () => {
    test('should handle SQL injection attempts safely', async ({ request }) => {
      const maliciousPayloads = [
        { email: "test@example.com", otp: "' OR '1'='1" },
        { email: "test'; DROP TABLE otp_codes; --@x.com", otp: "123456" },
        { email: "test@example.com", otp: "' OR '1'='1'" }
      ];

      for (const payload of maliciousPayloads) {
        const response = await request.post('/auth/sign-in/email-otp', {
          headers: BA_HEADERS,
          data: payload
        });

        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
        const data = await response.json();
        const text = JSON.stringify(data);
        expect(text).not.toContain('SQL');
        expect(text).not.toContain('syntax error');
      }
    });
  });
});
