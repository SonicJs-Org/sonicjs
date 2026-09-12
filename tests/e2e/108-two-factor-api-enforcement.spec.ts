import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'
import { totpFromOtpauthUri } from '../../packages/core/src/__tests__/utils/totp'

/**
 * Forced re-enrolment, enforced on the JSON API — and the path normalization that keeps the
 * disable guard from being stepped around.
 *
 * ── Why /api/* matters ──
 * `two_factor_required` is enforced by a middleware mounted in `app.ts`. Mounted on `/admin/*`
 * alone it only gates the HTML portal, and the very same session cookie drives `/api/*` — so a
 * user told to enrol could keep reading and writing content through the API indefinitely while the
 * admin who set the requirement believes the account is blocked.
 *
 * This is the one forced-enrolment behaviour reachable from an E2E spec. The `/admin/*` half is
 * not: a self-registered account gets the `viewer` role, which has no `portal:access` grant, so it
 * is bounced before the enforcement middleware is consulted. That half — the redirect, the
 * exemptions, the htmx branch, the API-key exemption and the fail-open behaviour — is covered
 * against a real SQLite D1 in
 * `packages/core/src/plugins/core-plugins/two-factor-auth/__tests__/recovery.sqlite.test.ts`.
 *
 * Every test brings its own throwaway `…@example.com` account, for the reason spelled out in
 * `107-two-factor-admin-reset.spec.ts`: `fullyParallel: true` means enrolling the shared admin
 * would break every concurrent spec. The shared admin only ever acts as the reset ACTOR.
 */

function json(data: unknown) {
  return { headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN }, data }
}

/** Create a throwaway account and take it to a VERIFIED enrolment. Leaves the session signed in. */
async function createEnrolledUser(page: Page, slot: string) {
  const user = {
    email: `tf-api-${slot}-${Date.now().toString(36)}@example.com`,
    password: 'TwoFactorApi!123',
    name: 'Two Factor API Target',
  }
  await page.context().clearCookies()

  const signUp = await page.request.post(`${TEST_ORIGIN}/auth/sign-up/email`, json(user))
  expect(signUp.ok(), `sign-up failed: ${signUp.status()} ${await signUp.text()}`).toBeTruthy()
  const { user: created } = (await signUp.json()) as { user: { id: string } }

  await enrol(page, user.password)
  return { ...user, id: created.id }
}

/** Enrol whoever currently holds the session, all the way to `verified = 1`. */
async function enrol(page: Page, password: string) {
  const enable = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/enable`,
    json({ password }),
  )
  expect(enable.ok(), `enable failed: ${enable.status()} ${await enable.text()}`).toBeTruthy()
  const { totpURI } = (await enable.json()) as { totpURI: string }

  const confirm = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/verify-totp`,
    json({ code: await totpFromOtpauthUri(totpURI) }),
  )
  expect(confirm.ok(), `verify-totp failed: ${confirm.status()} ${await confirm.text()}`).toBeTruthy()
}

/** Reset a user as the signed-in admin, leaving the requirement in place. */
async function resetAsAdmin(page: Page, userId: string, confirmEmail: string) {
  await loginAsAdmin(page)
  const csrf = await getCsrfTokenFromPage(page)
  const res = await page.request.post(`${TEST_ORIGIN}/admin/two-factor-reset`, {
    headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN, 'X-CSRF-Token': csrf },
    data: { userId, confirmEmail, requireReenrolment: true },
  })
  expect(res.status(), await res.text()).toBe(200)
  await page.context().clearCookies()
}

/** Sign in with password alone. Valid only after a reset has removed the second factor. */
async function signInWithPassword(page: Page, email: string, password: string) {
  await page.context().clearCookies()
  const res = await page.request.post(
    `${TEST_ORIGIN}/auth/sign-in/email`,
    json({ email, password }),
  )
  expect(res.ok(), `sign-in failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  const body = (await res.json()) as { twoFactorRedirect?: boolean }
  // A reset with requireReenrolment leaves no second factor, so nothing should be demanded here.
  expect(body.twoFactorRedirect ?? false).toBe(false)
}

test.describe('Two-Factor API Enforcement @auth', () => {
  test('a user who owes an enrolment is refused by the JSON API @smoke', async ({ page }) => {
    const target = await createEnrolledUser(page, 'apigate')
    await resetAsAdmin(page, target.id, target.email)
    await signInWithPassword(page, target.email, target.password)

    const res = await page.request.get(`${TEST_ORIGIN}/api/documents`, {
      headers: { Accept: 'application/json' },
    })
    expect(res.status()).toBe(403)
    // The body, not just the status: a 403 for some unrelated permission reason would be
    // indistinguishable otherwise, and this test would pass with the gate removed.
    await expect(res.json()).resolves.toMatchObject({ enrolmentPath: '/admin/two-factor' })
  })

  test('the same user is let back onto the API once they enrol', async ({ page }) => {
    // The requirement must be satisfiable. A gate that never lifts is a lockout, which is the
    // exact failure this whole feature exists to prevent.
    const target = await createEnrolledUser(page, 'apiclear')
    await resetAsAdmin(page, target.id, target.email)
    await signInWithPassword(page, target.email, target.password)

    const before = await page.request.get(`${TEST_ORIGIN}/api/documents`, {
      headers: { Accept: 'application/json' },
    })
    expect(before.status()).toBe(403)

    await enrol(page, target.password)

    // Asserted on the body rather than the status: a `viewer` may well be refused `/api/documents`
    // on ordinary ACL grounds, and that is not what this test is about. What must be gone is the
    // enrolment refusal.
    const after = await page.request.get(`${TEST_ORIGIN}/api/documents`, {
      headers: { Accept: 'application/json' },
    })
    expect(await after.text()).not.toContain('enrolmentPath')
  })

  test('an enrolled user under no requirement is untouched by the gate', async ({ page }) => {
    // Keying the gate off "is enrolled" rather than "owes an enrolment" would break the API for
    // every 2FA user in the install.
    await createEnrolledUser(page, 'apinormal')

    const res = await page.request.get(`${TEST_ORIGIN}/api/documents`, {
      headers: { Accept: 'application/json' },
    })
    expect(await res.text()).not.toContain('enrolmentPath')
  })

  test('the disable guard is not stepped around with a trailing slash', async ({ page }) => {
    // `/auth/two-factor/disable/` reaches the same Better Auth endpoint. The guard compares the
    // pathname, so without normalization one extra character deletes the enrolment an admin
    // mandated.
    const target = await createEnrolledUser(page, 'slash')
    await resetAsAdmin(page, target.id, target.email)
    await signInWithPassword(page, target.email, target.password)
    await enrol(page, target.password)

    const disable = await page.request.post(
      `${TEST_ORIGIN}/auth/two-factor/disable/`,
      json({ password: target.password }),
    )
    expect(disable.status()).toBe(403)
    await expect(disable.json()).resolves.toMatchObject({ code: 'TWO_FACTOR_REQUIRED' })

    // Still challenged — a 403 that failed to prevent the delete would look the same from here.
    await page.context().clearCookies()
    const signIn = await page.request.post(
      `${TEST_ORIGIN}/auth/sign-in/email`,
      json({ email: target.email, password: target.password }),
    )
    await expect(signIn.json()).resolves.toMatchObject({ twoFactorRedirect: true })
  })
})
