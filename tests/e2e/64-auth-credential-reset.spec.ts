import { test, expect } from '@playwright/test';

/**
 * Regression coverage for the Better Auth credential path (convergence plan
 * Phase 1). Better Auth verifies against `account.password`, NOT
 * `users.password_hash`, so:
 *
 *  - A user created outside the BA sign-up flow (legacy /auth/register) has no
 *    credential account until first login; the login self-heal must create it.
 *  - A password reset must write through to `account.password` (via
 *    ensureCredentialAccount). Before the fix, a reset only updated
 *    users.password_hash, so the new password never validated and the user was
 *    HARD-LOCKED-OUT (the self-heal only fires when no account row exists).
 *
 * This test exercises register -> self-heal login -> reset -> new-password login,
 * and asserts the new password works and the old one is rejected.
 */
test.describe('Auth — Better Auth credential & password reset', () => {
  test('reset updates the BA credential so the new password works (no lockout)', async ({ request }) => {
    const email = `reset-${Date.now()}@e2e.test`;
    const oldPassword = 'OldPass123!';
    const newPassword = 'NewPass456!';

    // 1) Register — creates a legacy users row (password_hash) with NO BA account.
    const reg = await request.post('/auth/register', {
      data: { email, password: oldPassword, firstName: 'Reset', lastName: 'Test' },
    });
    expect(reg.ok(), `register failed: ${reg.status()}`).toBeTruthy();

    // 2) First login with the OLD password — the self-heal must create the BA
    //    credential account from the legacy hash, so this succeeds.
    const login1 = await request.post('/auth/login/form', { form: { email, password: oldPassword } });
    expect(await login1.text()).toContain('Login successful');

    // 3) Request a password reset (dev/test returns the reset link inline).
    const reqReset = await request.post('/auth/request-password-reset', { form: { email } });
    expect(reqReset.ok(), `request-reset failed: ${reqReset.status()}`).toBeTruthy();
    const resetBody = await reqReset.json();
    expect(resetBody.reset_link, 'no reset_link returned').toBeTruthy();
    const token = new URL(resetBody.reset_link).searchParams.get('token');
    expect(token, 'no reset token').toBeTruthy();

    // 4) Reset to the NEW password.
    const reset = await request.post('/auth/reset-password', {
      form: { token: token!, password: newPassword, confirm_password: newPassword },
    });
    expect(reset.ok(), `reset failed: ${reset.status()}`).toBeTruthy();

    // 5) The NEW password MUST log in — this is the regression. Before the fix
    //    this returned "Invalid email or password" (the lockout).
    const login2 = await request.post('/auth/login/form', { form: { email, password: newPassword } });
    expect(await login2.text(), 'new password did not work — reset lockout regressed').toContain(
      'Login successful'
    );

    // 6) The OLD password must now be rejected (credential fully replaced).
    const login3 = await request.post('/auth/login/form', { form: { email, password: oldPassword } });
    expect(await login3.text()).toContain('Invalid email or password');
  });
});
