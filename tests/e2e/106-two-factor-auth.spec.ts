import { test, expect } from './fixtures'
import type { Page } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, submitLoginForm, TEST_ORIGIN } from './utils/test-helpers'
// The SAME helper `__tests__/services/two-factor-roundtrip.test.ts` verifies against a real Better
// Auth instance. Importing it rather than keeping a second copy is deliberate: the cheap tier proves
// the codes it produces are accepted, so this spec cannot fail in CI over a drifted TOTP
// implementation — a failure mode that looks exactly like a product bug.
import { totpFromOtpauthUri } from '../../packages/core/src/__tests__/utils/totp'

/**
 * two-factor-auth plugin — enrolment surface, challenge surface, and the second-factor
 * enforcement on the passwordless sign-in paths.
 *
 * ── Nothing here enrols the shared admin account, and that is the whole design ──
 * An earlier version of this spec enrolled `admin@sonicjs.com` and relied on
 * `test.describe.configure({ mode: 'serial' })` plus an `afterEach` cleanup to put it back.
 * That does not work: `playwright.config.ts` sets `fullyParallel: true` with 4 CI workers, and
 * serial mode only orders tests WITHIN one describe block — it does not stop the other ~124 specs
 * that call `loginAsAdmin` from running on the other three workers. For the whole window in which
 * 2FA was on, every one of them would take a `{twoFactorRedirect:true}` response and fail. The
 * blast radius of this file was the entire suite.
 *
 * So the enrolling tests each create their OWN throwaway account via Better Auth sign-up. Worst
 * case they now fail alone. The accounts are `…@example.com`, which the existing sweep already
 * deletes: `global-setup.ts` and `global-teardown.ts` POST `/test-cleanup`, whose user predicate is
 * `email LIKE '%test%' OR email LIKE '%example.com%'` (routes/test-cleanup.ts). Note the sweep is
 * mounted at the ROOT (`app.route('/', testCleanupRoutes)` in app.ts) — there is no
 * `/admin/api/test-cleanup/*` path, despite what some helpers still call.
 *
 * The trade-off: a self-registered user gets the `viewer` role, which has no `portal:access`
 * grant, so it cannot load `/admin/two-factor`. The enrolment PAGE is therefore exercised against
 * the shared admin in its non-enrolling states only (disabled, warning copy, wrong password), and
 * the enrol/confirm/disable page transitions are driven through the Better Auth endpoints the page
 * calls rather than through its buttons. The full page-driven flow is covered without a browser in
 * `packages/core/src/__tests__/services/two-factor-roundtrip.test.ts`.
 */

/** JSON request options for `page.request` calls to Better Auth. */
function json(data: unknown) {
  return { headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN }, data }
}

const TWO_FACTOR_PLUGIN_ID = 'two-factor-auth'

/**
 * Put the plugin into the state every test below assumes: installed and ACTIVE.
 *
 * The enrolment surface sits behind a deactivate→404 gate — `twoFactorAdminRoutes` calls
 * `isPluginActive()` and answers `c.notFound()` when it is false (plugins/core-plugins/
 * two-factor-auth/routes.ts). That lookup is memoised per server isolate with no TTL and is only
 * busted by the isolate that toggled the plugin, so an isolate that resolved it once before the
 * plugin row was seeded keeps 404ing `/admin/two-factor` and `/admin/two-factor/qr` for the rest
 * of its life even though the row now reads `active`. The same memo is consulted by
 * `enforceTwoFactorEnrolment()`, so a stale `false` silently un-gates the API too.
 *
 * `POST /admin/plugins/:id/activate` is idempotent and calls `invalidatePluginStatusCache()`, so
 * this pins the real precondition instead of inheriting whatever the isolate happened to cache.
 *
 * Requires an admin session on `page` — every caller runs after `loginAsAdmin`.
 */
async function ensureTwoFactorPluginActive(page: Page) {
  const csrf = await getCsrfTokenFromPage(page)
  const headers = {
    'Content-Type': 'application/json',
    Origin: TEST_ORIGIN,
    ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
  }
  const activate = () =>
    page.request.post(`${TEST_ORIGIN}/admin/plugins/${TWO_FACTOR_PLUGIN_ID}/activate`, {
      headers,
      data: {},
    })

  let res = await activate()
  if (!res.ok()) {
    // Nothing to activate yet (greenfield DB whose bootstrap has not registered the row).
    // Install first — the generic installer resolves the id straight out of the plugin registry.
    await page.request.post(`${TEST_ORIGIN}/admin/plugins/install`, {
      headers,
      data: { id: TWO_FACTOR_PLUGIN_ID, name: TWO_FACTOR_PLUGIN_ID },
    })
    res = await activate()
  }
  expect(
    res.ok(),
    `could not activate the ${TWO_FACTOR_PLUGIN_ID} plugin: ${res.status()} ${await res.text()}`,
  ).toBeTruthy()
}

/**
 * Create a throwaway account and take it all the way to a VERIFIED enrolment, using the same
 * Better Auth endpoints the enrolment page's JS calls.
 *
 * No CSRF header needed: these requests carry no `auth_token` cookie, and `csrfProtection`
 * exempts cookie-less requests (middleware/csrf.ts).
 */
async function createEnrolledUser(page: Page, slot: string) {
  const user = {
    email: `two-factor-${slot}-${Date.now().toString(36)}@example.com`,
    password: 'TwoFactorTest!123',
    name: 'Two Factor Test',
  }
  await page.context().clearCookies()

  const signUp = await page.request.post(`${TEST_ORIGIN}/auth/sign-up/email`, json(user))
  expect(signUp.ok(), `sign-up failed: ${signUp.status()} ${await signUp.text()}`).toBeTruthy()

  // `emailAndPassword.autoSignIn` is true (auth/config.ts), so a session cookie is already held.
  const enable = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/enable`,
    json({ password: user.password }),
  )
  expect(enable.ok(), `enable failed: ${enable.status()} ${await enable.text()}`).toBeTruthy()
  const { totpURI, backupCodes } = (await enable.json()) as {
    totpURI: string
    backupCodes: string[]
  }
  expect(totpURI).toMatch(/^otpauth:\/\/totp\//)
  // Backup codes are issued once, here. Policy floor is 5.
  expect(backupCodes.length).toBeGreaterThanOrEqual(5)

  // Enrolment is not active until a live code proves it.
  const confirm = await page.request.post(
    `${TEST_ORIGIN}/auth/two-factor/verify-totp`,
    json({ code: await totpFromOtpauthUri(totpURI) }),
  )
  expect(confirm.ok(), `verify-totp failed: ${confirm.status()} ${await confirm.text()}`).toBeTruthy()

  return { user, totpURI, backupCodes }
}

/** Sign in through the real login form and expect to land on the challenge page. */
async function loginAndExpectChallenge(page: Page, email: string, password: string) {
  await page.context().clearCookies()
  await page.goto('/auth/login')
  // `submitLoginForm`, not a bare click: the form POST is rate limited per IP and the suite is one
  // IP, so under four workers this submit comes back 429. htmx does not swap a non-2xx response,
  // so the page stays put and the only symptom is this URL never becoming /auth/two-factor.
  await submitLoginForm(page, email, password, /\/auth\/two-factor/)
}

/**
 * The session upgrade is what makes a 2FA session as strong as a password one: without the
 * `auth_token` cookie, `csrfProtection` treats every later admin POST as token-authenticated and
 * skips validation. Poll rather than assert once — the challenge page fires `/complete` and then
 * navigates, so the cookie lands slightly after the click.
 */
async function expectSessionUpgraded(page: Page) {
  await expect
    .poll(
      async () => (await page.context().cookies()).some((c) => c.name === 'auth_token'),
      { timeout: 15_000, message: 'auth_token was never minted — POST /auth/two-factor/complete did not run' },
    )
    .toBe(true)
}

/**
 * Click a two-factor form's submit button and wait for the POST it fires.
 *
 * Both of these pages render `#tf-msg` from their own `fetch` handler, so the banner cannot
 * appear until the request answers — and answering it means a password-hash comparison on a
 * possibly-cold isolate. `expect(...).toBeVisible()` budgets 5s, which is an assertion budget,
 * not a server-round-trip budget: in CI the wrong-password test failed with the locator still
 * resolving to `<div id="tf-msg" class="hidden ...">` on its 14th poll. Wait for the response
 * and let the assertion check what the handler did with it.
 */
async function submitTwoFactorForm(page: Page, click: () => Promise<void>): Promise<void> {
  await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === 'POST' && r.url().includes('/auth/two-factor/')
    ),
    click(),
  ])
}

test.describe('Two-Factor Authentication @auth @lock-auth-login @lock-auth-registration', () => {
  test.describe('enrolment page', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await ensureTwoFactorPluginActive(page)
    })

    test('is reachable from the sidebar and renders the disabled state @smoke', async ({ page }) => {
      await page.goto('/admin/two-factor')
      await expect(page.locator('h1')).toContainText('Two-Factor Authentication')
      await expect(page.locator('#tf-status')).toHaveText('Disabled')
      await expect(page.locator('#enrolForm')).toBeVisible()
      // The "on" panel exists but must be hidden until an enrolment is confirmed.
      await expect(page.locator('#state-on')).toBeHidden()
    })

    test('warns that enrolling disables emailed sign-in for the account', async ({ page }) => {
      // Not decoration — the passwordless guard really does refuse magic links for enrolled
      // accounts, so the consequence has to be stated before the user opts in.
      await page.goto('/admin/two-factor')
      // \s+ rather than a literal space: the sentence wraps across source lines in the template,
      // so the rendered text carries a newline between "are" and "disabled".
      await expect(page.getByText(/magic links and emailed sign-in codes are\s+disabled/i)).toBeVisible()
    })

    test('is linked from the profile page security panel', async ({ page }) => {
      await page.goto('/admin/profile')
      // The sidebar also links to /admin/two-factor (desktop + mobile copies), so target the
      // security panel's own anchor by id rather than by href alone.
      const link = page.locator('#profile-two-factor-link')
      await expect(link).toBeVisible()
      await expect(link).toHaveAttribute('href', '/admin/two-factor')
      await expect(link).toContainText(/Enable|Manage/)
    })

    test('rejects setup with the wrong password and stays in the off state', async ({ page }) => {
      await page.goto('/admin/two-factor')
      await page.fill('#tf-pw', 'definitely-not-the-password')
      await submitTwoFactorForm(page, () => page.click('#enrolBtn'))
      await expect(page.locator('#tf-msg')).toBeVisible()
      await expect(page.locator('#state-enrolling')).toBeHidden()
      await expect(page.locator('#tf-status')).toHaveText('Disabled')
    })

    test('redirects an unauthenticated visitor to login', async ({ page }) => {
      await page.context().clearCookies()
      await page.goto('/admin/two-factor')
      await expect(page).toHaveURL(/\/auth\/login/)
    })

    test('renders a scannable QR code for an enrolment URI', async ({ page }) => {
      // Without this the page is unusable in its primary setting: admin panel on a desktop,
      // authenticator on a phone, no handler for an otpauth:// link and no shared clipboard.
      await page.goto('/admin/two-factor')
      const csrf = await getCsrfTokenFromPage(page)
      const res = await page.request.post(`${TEST_ORIGIN}/admin/two-factor/qr`, {
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN, 'X-CSRF-Token': csrf },
        data: { uri: 'otpauth://totp/SonicJS:admin@sonicjs.com?secret=JBSWY3DPEHPK3PXP&issuer=SonicJS' },
      })
      expect(res.status()).toBe(200)
      const { svg } = (await res.json()) as { svg: string }
      expect(svg.startsWith('<svg')).toBe(true)
      expect(svg.length).toBeGreaterThan(1000)
    })

    test('refuses to render a QR for anything but a TOTP URI', async ({ page }) => {
      await page.goto('/admin/two-factor')
      const csrf = await getCsrfTokenFromPage(page)
      const res = await page.request.post(`${TEST_ORIGIN}/admin/two-factor/qr`, {
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN, 'X-CSRF-Token': csrf },
        data: { uri: 'https://evil.test/steal' },
      })
      expect(res.status()).toBe(400)
    })
  })

  test.describe('login challenge page', () => {
    test('is served without a session — an enrolled user has none at challenge time @smoke', async ({
      page,
    }) => {
      await page.context().clearCookies()
      await page.goto('/auth/two-factor')
      await expect(page.locator('h1')).toContainText('Two-step verification')
      await expect(page.locator('#totpForm')).toBeVisible()
    })

    test('always offers backup-code entry', async ({ page }) => {
      // BA's twoFactorMethods never contains 'backup_code'; keying the UI off it would hide this
      // exactly when the authenticator device is lost.
      await page.context().clearCookies()
      await page.goto('/auth/two-factor')
      await page.click('#backupToggle')
      await expect(page.locator('#backupForm')).toBeVisible()
      await expect(page.locator('#tf-backup')).toBeVisible()
    })

    test('rejects a bogus code without signing anyone in', async ({ page }) => {
      await page.context().clearCookies()
      await page.goto('/auth/two-factor')
      await page.fill('#tf-code', '000000')
      await submitTwoFactorForm(page, () => page.click('#totpBtn'))
      await expect(page.locator('#tf-msg')).toBeVisible()
      await expect(page).toHaveURL(/\/auth\/two-factor/)
    })
  })

  /**
   * Each of these creates and enrols its OWN account, so they are safe to run in parallel with
   * each other and with every other spec. Nothing shared is mutated — see the file header.
   */
  test.describe('full enrolment round trip (throwaway account)', () => {
    test('challenges the password login, then a live TOTP code resolves it @smoke', async ({
      page,
    }) => {
      const { user, totpURI } = await createEnrolledUser(page, 'totp')

      // The password alone must no longer be enough.
      await loginAndExpectChallenge(page, user.email, user.password)

      await page.fill('#tf-code', await totpFromOtpauthUri(totpURI))
      await page.click('#totpBtn')
      await expectSessionUpgraded(page)
    })

    test('accepts a backup code at the challenge', async ({ page }) => {
      const { user, backupCodes } = await createEnrolledUser(page, 'backup')

      await loginAndExpectChallenge(page, user.email, user.password)

      await page.click('#backupToggle')
      await page.fill('#tf-backup', backupCodes[0]!.trim())
      await page.click('#backupBtn')
      await expectSessionUpgraded(page)
    })

    test('refuses a magic link while enrolled, without revealing that it refused', async ({
      page,
    }) => {
      const { user } = await createEnrolledUser(page, 'guard')

      // Both assertions below are indistinguishable-by-design: BA answers the same shapes for an
      // unguarded request, which is exactly the anti-oracle property. So this test pins the
      // RESPONSE CONTRACT, not the guard's activity — deleting the guard would not turn it red.
      // That the guard actually blocks is proved in
      // `packages/core/src/__tests__/services/passwordless-second-factor-guard.test.ts`, which
      // asserts the request never reaches Better Auth.
      const magic = await page.request.post(
        `${TEST_ORIGIN}/auth/sign-in/magic-link`,
        json({ email: user.email, callbackURL: '/admin' }),
      )
      expect(magic.status()).toBe(200)
      expect(await magic.json()).toEqual({ status: true })

      const otp = await page.request.post(
        `${TEST_ORIGIN}/auth/sign-in/email-otp`,
        json({ email: user.email, otp: '000000' }),
      )
      expect(otp.status()).toBe(400)
      expect(await otp.json()).toEqual({ message: 'Invalid OTP', code: 'INVALID_OTP' })
    })
  })

  /**
   * The QR renderer, driven as the enrolment page drives it.
   *
   * Worth having at this tier even though `qr.test.ts` covers the route: the defect this feature
   * shipped with was a QR that was well-formed and unscannable, and the property that decides
   * scannability — CSS pixels per module — only exists once something renders it. These cases need
   * NO enrolment, so they carry none of the shared-admin hazard the rest of this file avoids.
   */
  test.describe('QR rendering @auth', () => {
    /** Below ~4 CSS px/module a phone camera stops reliably decoding a screen. */
    const MIN_CSS_PX_PER_MODULE = 4

    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
      await ensureTwoFactorPluginActive(page)
    })

    test('renders a QR big enough to scan, for any issuer length', async ({ page }) => {
      // A synthetic URI — no enrolment needed, and the long-issuer case is the one that regressed:
      // `issuer` is operator-configurable to 64 chars and Better Auth writes it into the URI twice,
      // which pushed the symbol from 49 to 69 modules while the box stayed a fixed width.
      for (const issuer of ['SonicJS', 'A'.repeat(64)]) {
        const uri =
          `otpauth://totp/${encodeURIComponent(`${issuer}:admin@sonicjs.com`)}` +
          `?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=${encodeURIComponent(issuer)}` +
          `&algorithm=SHA1&digits=6&period=30`

        const res = await page.request.post(`${TEST_ORIGIN}/admin/two-factor/qr`, json({ uri }))
        expect(res.ok(), `QR failed for a ${issuer.length}-char issuer`).toBeTruthy()

        const { svg, renderPx, modulesAcross } = (await res.json()) as {
          svg: string
          renderPx: number
          modulesAcross: number
        }
        expect(renderPx / modulesAcross).toBeGreaterThanOrEqual(MIN_CSS_PX_PER_MODULE)
        // The size must be on the element: a viewBox-only <svg> is sized by its container, which
        // is what let the density regress silently.
        expect(svg).toContain(`width="${renderPx}"`)
        expect(svg).not.toContain('<script')
      }
    })

    test('refuses to render arbitrary content as a QR', async ({ page }) => {
      // Otherwise this is a phishing primitive: a QR is unreadable to the human deciding whether
      // to trust it, and this one would carry our own origin.
      const res = await page.request.post(
        `${TEST_ORIGIN}/admin/two-factor/qr`,
        json({ uri: 'https://evil.test/steal' }),
      )
      expect(res.status()).toBe(400)
    })
  })
})
