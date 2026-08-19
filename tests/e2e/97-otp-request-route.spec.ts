import { test, expect } from '@playwright/test';

/**
 * Legacy `/auth/otp/*` routes regression tests.
 *
 * The otp-login plugin reads its settings from the `plugins` table and writes
 * codes to `otp_codes`. On a fresh DB these tables only exist once migration
 * 0005/0006 have been applied — before the fix the unguarded settings read
 * 500'd with `no such table: plugins`. These specs guard against regressing to
 * that state: the request must fall back to defaults (200), not throw.
 */

function uniqueEmail(prefix: string): string {
  return `${prefix}.${Date.now()}.${Math.random().toString(36).substring(7)}@test.sonicjs.com`;
}

const JSON_HEADERS = {
  'Content-Type': 'application/json',
};

test.describe('Legacy OTP Routes (plugins/otp_codes tables) @auth', () => {
  test.describe('POST /auth/otp/request', () => {
    test('returns 200 (not 500) for an unknown email', async ({ request }) => {
      const response = await request.post('/auth/otp/request', {
        headers: JSON_HEADERS,
        data: { email: uniqueEmail('otp-unknown') }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      // Success message, not an error 500
      expect(data.error).toBeUndefined();
      expect(data.message).toBeTruthy();
    });

    test('returns 200 for a known admin email', async ({ request }) => {
      const response = await request.post('/auth/otp/request', {
        headers: JSON_HEADERS,
        data: { email: 'admin@sonicjs.com' }
      });

      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data.error).toBeUndefined();
      expect(data.message).toBeTruthy();
    });

    test('rejects invalid email with 400', async ({ request }) => {
      const response = await request.post('/auth/otp/request', {
        headers: JSON_HEADERS,
        data: { email: 'not-an-email' }
      });

      expect(response.status()).toBe(400);
    });
  });

  test.describe('POST /auth/otp/verify', () => {
    test('returns a controlled 4xx for a wrong code (not a 500)', async ({ request }) => {
      const response = await request.post('/auth/otp/verify', {
        headers: JSON_HEADERS,
        data: { email: uniqueEmail('otp-verify-bad'), code: '000000' }
      });

      expect(response.status()).toBeGreaterThanOrEqual(400);
      expect(response.status()).toBeLessThan(500);
    });

    test('rejects invalid email with 400', async ({ request }) => {
      const response = await request.post('/auth/otp/verify', {
        headers: JSON_HEADERS,
        data: { email: 'not-an-email', code: '123456' }
      });

      expect(response.status()).toBe(400);
    });
  });
});
