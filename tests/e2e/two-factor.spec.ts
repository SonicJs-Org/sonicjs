import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "@playwright/test"
import { loginAsAdmin } from "./utils/test-helpers"
import { getCsrfTokenFromPage } from "./utils/test-helpers"
import { submitLoginForm } from "./utils/test-helpers"
import { TEST_ORIGIN } from "./utils/test-helpers"
import { totpFromOtpauthUri } from "../../packages/core/src/__tests__/utils/totp"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 106-two-factor-auth.spec.ts", () => {
  // The SAME helper `__tests__/services/two-factor-roundtrip.test.ts` verifies against a real Better
  // Auth instance. Importing it rather than keeping a second copy is deliberate: the cheap tier proves
  // the codes it produces are accepted, so this spec cannot fail in CI over a drifted TOTP
  // implementation — a failure mode that looks exactly like a product bug.
  
  
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 107-two-factor-admin-reset.spec.ts", () => {
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
  
  test.describe('Two-Factor Admin Reset @auth @lock-auth-registration', () => {
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
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 108-two-factor-api-enforcement.spec.ts", () => {
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
  
  const TWO_FACTOR_PLUGIN_ID = 'two-factor-auth'
  
  /**
   * Put the plugin into the state the gate assumes: installed and ACTIVE.
   *
   * `enforceTwoFactorEnrolment()` opens with `if (!(await isPluginActive(...))) return next()`
   * (two-factor-auth/recovery.ts), and that lookup is memoised per server isolate with no TTL,
   * busted only by the isolate that toggled the plugin. An isolate that resolved it once before
   * the plugin row was seeded therefore waves every request through for the rest of its life —
   * `/api/documents` answers its own `400 type query parameter is required` instead of the `403`
   * this file is about, which reads exactly like a deleted gate.
   *
   * `POST /admin/plugins/:id/activate` is idempotent and calls `invalidatePluginStatusCache()`.
   */
  async function ensureTwoFactorPluginActive(page: Page) {
    await loginAsAdmin(page)
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
    await page.context().clearCookies()
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
  
  test.describe('Two-Factor API Enforcement @auth @lock-auth-registration', () => {
    // Once per worker rather than per test: the memo being busted lives in the SERVER isolate, so
    // one activation covers every test that follows, and each repeat would cost another admin
    // sign-in against the 10/min rate limit on /auth/seed-admin.
    test.beforeAll(async ({ browser }) => {
      const context = await browser.newContext({ baseURL: TEST_ORIGIN })
      try {
        await ensureTwoFactorPluginActive(await context.newPage())
      } finally {
        await context.close()
      }
    })
  
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
})
