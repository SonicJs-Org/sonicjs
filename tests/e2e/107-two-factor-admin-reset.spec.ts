import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'
import { totpFromOtpauthUri } from '../../packages/core/src/__tests__/utils/totp'

/**
 * Administrative two-factor reset — the break-glass path for a user who lost their authenticator
 * AND their backup codes.
 *
 * Without it the only routes back into such an account are an unused backup code or
 * `wrangler d1 execute --remote`, which means a sole admin who loses their phone locks the whole
 * organisation out of the portal until someone with Cloudflare credentials intervenes.
 *
 * ── Every test brings its own throwaway account ──
 * Same rule as `106-two-factor-auth.spec.ts`, for the same reason: `playwright.config.ts` sets
 * `fullyParallel: true`, so enrolling the shared `admin@sonicjs.com` would make every other spec
 * running concurrently take a `{twoFactorRedirect:true}` on `loginAsAdmin` and fail. The accounts
 * are `…@example.com`, which the `/test-cleanup` sweep in global-setup/teardown already deletes.
 *
 * The shared admin is used only as the ACTOR — it performs resets, and never enrols.
 *
 * ── What is not covered here, and where it is ──
 * The forced re-enrolment redirect (`two_factor_required && !enrolled` → /admin/two-factor) cannot
 * be driven from this file: a self-registered account gets the `viewer` role, which has no
 * `portal:access` grant, so it is bounced from `/admin/*` before the enforcement middleware is
 * ever consulted. That middleware — including its exemptions, its JSON branch and its fail-open
 * behavior — is covered against a real SQLite D1 in
 * `packages/core/src/plugins/core-plugins/two-factor-auth/__tests__/recovery.sqlite.test.ts`.
 */

/** JSON request options for `page.request` calls to Better Auth. */
function json(data: unknown) {
  return { headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN }, data }
}

/**
 * Create a throwaway account, take it to a VERIFIED enrolment, and return its id.
 *
 * The id comes from the sign-up response rather than by scraping the admin users list — the list
 * is paginated and this account is one of many `…@example.com` rows left by concurrent specs.
 */
async function createEnrolledUser(page: Page, slot: string, opts: { keepSession?: boolean } = {}) {
  const user = {
    email: `tf-reset-${slot}-${Date.now().toString(36)}@example.com`,
    password: 'TwoFactorReset!123',
    name: 'Two Factor Reset Target',
  }
  await page.context().clearCookies()

  const signUp = await page.request.post(`${TEST_ORIGIN}/auth/sign-up/email`, json(user))
  expect(signUp.ok(), `sign-up failed: ${signUp.status()} ${await signUp.text()}`).toBeTruthy()
  const { user: created } = (await signUp.json()) as { user: { id: string } }

  // autoSignIn is on (auth/config.ts), so a session cookie is already held here.
  const enable = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/enable`,
    json({ password: user.password }),
  )
  expect(enable.ok(), `enable failed: ${enable.status()} ${await enable.text()}`).toBeTruthy()
  const { totpURI } = (await enable.json()) as { totpURI: string }

  // Not enrolled until a live code proves it — `verified = 1` is what actually challenges.
  const confirm = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/verify-totp`,
    json({ code: await totpFromOtpauthUri(totpURI) }),
  )
  expect(confirm.ok(), `verify-totp failed: ${confirm.status()} ${await confirm.text()}`).toBeTruthy()

  // `verify-totp` left this context holding a fully-verified session. Callers that go on to act
  // as the ADMIN need it gone; the one that exercises self-service disable needs it kept.
  if (!opts.keepSession) await page.context().clearCookies()
  return { ...user, id: created.id }
}

/**
 * Ask Better Auth to sign this account in, and report whether it demanded a second factor.
 *
 * This is the assertion that matters: it reads the same signal the login form acts on, so it
 * cannot pass while the user is still really challenged.
 */
async function signInDemandsSecondFactor(page: Page, email: string, password: string) {
  await page.context().clearCookies()
  const res = await page.request.post(
    `${TEST_ORIGIN}/auth/sign-in/email`,
    json({ email, password }),
  )
  expect(res.ok(), `sign-in failed outright: ${res.status()} ${await res.text()}`).toBeTruthy()
  const body = (await res.json()) as { twoFactorRedirect?: boolean }
  return body.twoFactorRedirect === true
}

/** POST the reset as the signed-in admin, carrying the CSRF header every admin POST sends. */
async function postReset(
  page: Page,
  body: { userId: string; confirmEmail: string; requireReenrolment?: boolean },
) {
  const csrf = await getCsrfTokenFromPage(page)
  return page.request.post(`${TEST_ORIGIN}/admin/two-factor-reset`, {
    headers: {
      'Content-Type': 'application/json',
      Origin: TEST_ORIGIN,
      'X-CSRF-Token': csrf,
    },
    data: body,
  })
}

test.describe('Two-Factor Admin Reset @auth', () => {
  test('an admin can reset a locked-out user, who can then sign in with their password @smoke', async ({
    page,
  }) => {
    const target = await createEnrolledUser(page, 'happy')

    // Precondition: this account really is challenged. Without it, a reset that did nothing at
    // all would still pass the assertion below.
    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(true)

    await loginAsAdmin(page)
    const res = await postReset(page, { userId: target.id, confirmEmail: target.email })
    expect(res.status(), await res.text()).toBe(200)
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      email: target.email,
      wasEnrolled: true,
      requireReenrolment: true,
    })

    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(false)
  })

  test('the recovery panel on the user edit page shows enrolment state and the confirm field', async ({
    page,
  }) => {
    const target = await createEnrolledUser(page, 'panel')

    await loginAsAdmin(page)
    await page.goto(`/admin/users/${target.id}/edit`)

    const panel = page.locator('div', { hasText: 'Two-Factor Recovery' }).last()
    await expect(page.getByRole('heading', { name: 'Two-Factor Recovery' })).toBeVisible()
    await expect(panel).toContainText('Enrolled')
    // The typed-email confirmation is the control that stops the wrong row being reset, so its
    // absence is a real defect rather than a cosmetic one.
    await expect(page.locator('#tf-confirm-email')).toBeVisible()
    await expect(page.locator('#tf-require-reenrol')).toBeChecked()
    await expect(page.locator('#tf-reset-button')).toBeVisible()
  })

  test('a mistyped confirmation email changes nothing', async ({ page }) => {
    const target = await createEnrolledUser(page, 'mistype')

    await loginAsAdmin(page)
    const res = await postReset(page, {
      userId: target.id,
      confirmEmail: 'someone.else@example.com',
    })
    expect(res.status()).toBe(400)

    // The status code alone would pass even if the reset had already been applied.
    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(true)
  })

  test('resetting without demanding re-enrolment leaves the account password-only', async ({
    page,
  }) => {
    const target = await createEnrolledUser(page, 'nodemand')

    await loginAsAdmin(page)
    const res = await postReset(page, {
      userId: target.id,
      confirmEmail: target.email,
      requireReenrolment: false,
    })
    expect(res.status(), await res.text()).toBe(200)
    await expect(res.json()).resolves.toMatchObject({ requireReenrolment: false })

    await loginAsAdmin(page)
    await page.goto(`/admin/users/${target.id}/edit`)
    await expect(page.getByRole('heading', { name: 'Two-Factor Recovery' })).toBeVisible()
    await expect(page.getByText('Not enrolled')).toBeVisible()
  })

  test('an unauthenticated caller cannot reset anyone', async ({ page }) => {
    const target = await createEnrolledUser(page, 'anon')

    await page.context().clearCookies()
    const res = await page.request.post(`${TEST_ORIGIN}/admin/two-factor-reset`, {
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      data: { userId: target.id, confirmEmail: target.email },
      maxRedirects: 0,
    })
    expect(res.status()).not.toBe(200)

    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(true)
  })

  test('a user under a requirement cannot turn their second factor back off', async ({ page }) => {
    // The requirement is an access gate, not a write-block: /admin/* enforcement never sees
    // POST /auth/two-factor/disable (wrong prefix), and the page hosting the disable form has to
    // stay exempt so enrolment is possible at all. Without the /auth/* guard, a user told to
    // enrol could enrol and immediately switch it off, leaving the account password-only while
    // the admin who set the requirement gets no signal.
    const target = await createEnrolledUser(page, 'nodisable')

    await loginAsAdmin(page)
    const reset = await postReset(page, { userId: target.id, confirmEmail: target.email })
    expect(reset.status(), await reset.text()).toBe(200)

    // Re-enrol, satisfying the requirement. The flag stays set — that is what "may not turn it
    // off" means — so this account is now `required && verified`.
    await page.context().clearCookies()
    const signIn = await page.request.post(`${TEST_ORIGIN}/auth/sign-in/email`, json(target))
    expect(signIn.ok()).toBeTruthy()
    const enable = await page.request.post(
      `${TEST_ORIGIN}/auth/two-factor/enable`,
      json({ password: target.password }),
    )
    expect(enable.ok(), `re-enable failed: ${enable.status()} ${await enable.text()}`).toBeTruthy()
    const { totpURI } = (await enable.json()) as { totpURI: string }
    const confirm = await page.request.post(
      `${TEST_ORIGIN}/auth/two-factor/verify-totp`,
      json({ code: await totpFromOtpauthUri(totpURI) }),
    )
    expect(confirm.ok()).toBeTruthy()

    const disable = await page.request.post(
      `${TEST_ORIGIN}/auth/two-factor/disable`,
      json({ password: target.password }),
    )
    expect(disable.status()).toBe(403)
    await expect(disable.json()).resolves.toMatchObject({ code: 'TWO_FACTOR_REQUIRED' })

    // The assertion that matters: still challenged. A 403 that did not actually prevent the
    // delete would look identical from here.
    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(true)
  })

  test('an ordinary enrolled user can still turn their own second factor off', async ({ page }) => {
    // The guard must key off the REQUIREMENT, not off being enrolled — otherwise it silently
    // takes self-service 2FA management away from every user in the install.
    const target = await createEnrolledUser(page, 'candisable', { keepSession: true })

    const disable = await page.request.post(
      `${TEST_ORIGIN}/auth/two-factor/disable`,
      json({ password: target.password }),
    )
    expect(disable.status(), await disable.text()).toBe(200)
    expect(await signInDemandsSecondFactor(page, target.email, target.password)).toBe(false)
  })

  test('an unknown user id is refused', async ({ page }) => {
    await loginAsAdmin(page)
    const res = await postReset(page, {
      userId: 'no-such-user-id',
      confirmEmail: 'nobody@example.com',
    })
    expect(res.status()).toBe(404)
  })
})
