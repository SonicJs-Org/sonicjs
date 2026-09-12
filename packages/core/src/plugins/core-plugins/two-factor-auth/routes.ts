/**
 * two-factor-auth route handlers.
 *
 * Two mounts with deliberately different gating — see the plugin entrypoint for why:
 *
 *   - `twoFactorAdminRoutes`     → /admin/two-factor  (session required, deactivate→404)
 *   - `twoFactorChallengeRoutes` → /auth/two-factor   (NO session — that is the point)
 *
 * Neither mount proxies Better Auth. Enrolment and verification are browser-direct calls to
 * `/auth/two-factor/*`, which the `/auth/*` catch-all in app.ts already serves. Wrapping them
 * here would add a second place that has to know BA's request/response shapes, and BA sets
 * signed cookies that a server-side hop would have to forward by hand.
 */
import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { requireAuth, AuthManager } from '../../../middleware'
import { getJwtExpirySecondsFromDb } from '../../../middleware/auth'
// Sourced from its defining module rather than the middleware barrel, matching api-docs:
// the barrel does not re-export invalidatePluginStatusCache, and keeping the status cache and
// its invalidator resolved through one module keeps them coherent under the test runner.
import { isPluginActive } from '../../../middleware/plugin-middleware'
import { getEnrolmentState, hasVerifiedSecondFactor } from '../../../auth/second-factor-guard'
import { isTwoFactorRequired } from './recovery'
import { TWO_FACTOR_PLUGIN_ID } from '../../../auth/two-factor-settings'
import { renderTwoFactorEnrolmentPage } from './components/enrolment-page'
import { renderTwoFactorChallengePage } from './components/challenge-page'
import type { Bindings, Variables } from '../../../app'

const twoFactorAdminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()
const twoFactorChallengeRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

/** Quiet zone the QR spec requires, in modules, on all four sides. */
const QUIET_ZONE_MODULES = 4

/**
 * CSS pixels per QR module — the number that decides whether a phone can actually read the code
 * off a desktop screen.
 *
 * Below roughly 4 px/module, decoding a screen becomes unreliable on ordinary phone cameras at a
 * natural distance. 6 leaves headroom for the things we cannot measure from here: a
 * standard-density monitor, browser zoom under 100%, and a camera held at arm's length.
 *
 * Raise this before touching `ecl` or the quiet zone if a scan ever fails — it is the variable
 * with the most direct effect and it costs only layout width.
 */
const CSS_PX_PER_MODULE = 6

// Defense-in-depth: `/admin/*` is already globally gated by requireAuth +
// requireRbac('portal','access'), but assert auth locally so the sub-app is safe if remounted
// and the intent is explicit at the plugin boundary.
twoFactorAdminRoutes.use('*', requireAuth())

// Deactivate→404 gate. SonicJS mounts plugin routes unconditionally and only hides the sidebar
// entry when a plugin is deactivated, so routes stay reachable by direct URL. Uses the BOOLEAN
// isPluginActive (not requireActivePlugin, which throws and becomes a 500 via onError).
//
// Best-effort across warm isolates: isPluginActive caches per isolate with no TTL and
// invalidation only clears the isolate that toggled. Acceptable here — this gate covers the
// enrolment SURFACE only. Verification is never gated on plugin status (auth/config.ts).
twoFactorAdminRoutes.use('*', async (c, next) => {
  if (!(await isPluginActive(c.env.DB, TWO_FACTOR_PLUGIN_ID))) {
    return c.notFound()
  }
  return next()
})

/**
 * Enrolment page.
 *
 * NOT permission-gated beyond authentication: every authenticated user manages their OWN second
 * factor, and the BA endpoints this page calls resolve the user from the session — there is no
 * arbitrary user id to pass.
 *
 * The policy SETTINGS surface is separate and administrative: it lives on the generic
 * schema-driven form at `/admin/plugins/two-factor-auth/configure`, which gates on
 * `user?.role !== 'admin'` (routes/admin-plugins.ts). The `two-factor:manage` permission the
 * manifest declares is registered for the plugins UI and is NOT currently enforced by any
 * handler — the role check is what actually gates it.
 */
twoFactorAdminRoutes.get('/', async (c) => {
  // requireAuth() above guarantees this.
  const user = c.get('user')!
  const [state, required] = await Promise.all([
    getEnrolmentState(c.env.DB, user.userId),
    // The RAW policy flag, not "owes an enrolment". The page needs both meanings and derives them
    // from this plus `verified`: the amber banner is `required && !verified`, while hiding the
    // disable form is `required` alone — a user who has satisfied the requirement still may not
    // turn it back off.
    isTwoFactorRequired(c.env.DB, user.userId),
  ])

  return c.html(
    renderTwoFactorEnrolmentPage({
      verified: state.verified,
      pending: state.enrolled && !state.verified,
      required,
      user: { name: user.email, email: user.email, role: user.role },
      version: c.get('appVersion'),
      dynamicMenuItems: c.get('pluginMenuItems'),
    }),
  )
})

/**
 * POST /admin/two-factor/qr — render an `otpauth://` URI as a scannable QR code.
 *
 * The enrolment page originally shipped the URI as a link plus the secret as selectable text and
 * no QR, on the reasoning that every authenticator supports manual entry. That reasoning does not
 * survive contact with the actual flow: the admin panel is used on a DESKTOP and the authenticator
 * lives on a PHONE, so an `otpauth://` link has no handler to open and the only path left is
 * hand-typing a 32-character base32 secret across devices. A QR is the only practical way to get
 * the account into the app.
 *
 * Server-side because these pages have no client bundler — the alternative was a CDN script tag on
 * the page that handles TOTP secrets. `qrcode-svg` is already a core dependency, pure JS, and safe
 * on Workers (no canvas, no Node built-ins).
 *
 * The URI is posted back rather than derived here because only the browser holds it: Better Auth
 * returns it once, from `/auth/two-factor/enable`, and never stores it in plaintext.
 *
 * Behind the same `requireAuth()` + deactivate→404 gates as the page (the `use('*')` pair above).
 * The caller sends `X-CSRF-Token` like every other admin POST, but note that CSRF validation is
 * currently inert app-wide — csrfProtection exempts requests without an `auth_token` cookie and
 * sign-in mints a Better Auth session cookie instead. `requireAuth()` is what actually protects
 * this route today. Rendering a QR is a read, so the exposure is bounded; the fix belongs in
 * csrf.ts, not here.
 */
twoFactorAdminRoutes.post('/qr', async (c) => {
  const body = await c.req.json().catch(() => null)
  const uri = (body as { uri?: unknown } | null)?.uri

  // Pin the input to a TOTP enrolment URI. Without this the endpoint is a generic
  // "render any text I give you as a QR code, from your origin" service — which is a phishing
  // primitive, since a QR is unreadable to the human deciding whether to trust it.
  if (typeof uri !== 'string' || uri.length > 512 || !/^otpauth:\/\/totp\//.test(uri)) {
    return c.json({ error: 'Expected an otpauth://totp/ URI' }, 400)
  }

  const { default: QRCode } = await import('qrcode-svg')
  const qr = new QRCode({
    content: uri,
    // 4 modules is the quiet zone the QR spec requires. The surrounding element's white padding
    // is NOT a substitute — a scanner sees the screen, not our box model, and anything less than
    // 4 is where "the code just won't scan on some phones" comes from.
    padding: QUIET_ZONE_MODULES,
    // Coordinate space only. `container: 'svg-viewbox'` emits a viewBox and NO width/height on the
    // <svg>, so this number sets the units the path is drawn in and has no effect on the size the
    // browser paints — that comes from the width/height attributes added below.
    width: 256,
    height: 256,
    // Medium recovery: enough redundancy for a phone camera on a screen, without inflating
    // the module count for a URI this long.
    ecl: 'M',
    // `join` merges the per-module rects into one path — ~190KB down to ~56KB on a long URI.
    join: true,
    container: 'svg-viewbox',
  })

  // ── Why the rendered size is computed, not a constant ──
  // Scannability is governed by CSS pixels PER MODULE, not by the overall size, and the module
  // count grows with the URI. `issuer` is operator-configurable up to 64 chars
  // (auth/two-factor-settings.ts) and Better Auth puts it in the URI TWICE — once in the label,
  // once as a parameter — so a long issuer plus a long email reaches ~285 chars and a 69-module
  // symbol, versus 49 modules for the shipped 'SonicJS' default.
  //
  // A fixed size therefore silently degrades: at the 236 CSS px this shipped with, a default
  // install got 4.1 px/module and a 64-char issuer got 3.1 — under the ~4 px/module floor where
  // phone cameras stop decoding screens reliably. The failure is invisible to every assertion in
  // qr.test.ts, because the SVG is perfectly well-formed either way.
  //
  // Deriving the size from the symbol keeps the density fixed instead, so no issuer or email
  // length can push it under the floor.
  const modulesAcross = qr.qrcode.moduleCount + QUIET_ZONE_MODULES * 2
  const renderPx = modulesAcross * CSS_PX_PER_MODULE

  const svg = qr
    .svg()
    // Strip the XML prolog: valid in a standalone .svg file, meaningless inline in HTML.
    .replace(/^<\?xml[^>]*\?>\s*/, '')
    // Pin the painted size on the element itself. Without width/height a viewBox-only <svg> is
    // sized entirely by its container, which is what made the density a CSS detail that no test
    // could see. The viewBox is retained, so this is a uniform scale.
    .replace('<svg ', `<svg width="${renderPx}" height="${renderPx}" `)

  return c.json({ svg, renderPx, modulesAcross })
})

/**
 * The login challenge.
 *
 * Unauthenticated by construction: the caller has proven a password and holds only Better
 * Auth's signed `better-auth.two_factor` cookie. Requiring a session here would make the page
 * unreachable for exactly the users it exists for.
 *
 * Safe to serve to anyone — it renders a form and nothing else. Possession of the challenge
 * cookie, which BA checks on the verify call, is what actually gates the factor. Serving it
 * unconditionally also avoids leaking whether a challenge is outstanding.
 */
twoFactorChallengeRoutes.get('/', (c) => {
  return c.html(renderTwoFactorChallengePage())
})

/**
 * POST /auth/two-factor/complete — bring a just-challenged session up to the full SonicJS shape.
 *
 * Better Auth's `verify-totp` / `verify-backup-code` set only `better-auth.session_token`. That is
 * enough for `requireAuth()` (app.ts resolves `c.get('user')` from the BA session), but it leaves
 * a 2FA user's session strictly WEAKER than a password-login session in two ways:
 *
 *   1. `csrfProtection` treats a request with no `auth_token` cookie as token-authenticated and
 *      skips validation entirely (middleware/csrf.ts). So every admin POST for the rest of that
 *      session would go unvalidated — the users who opted into the strongest authentication would
 *      get the weakest CSRF posture. BA's session cookie is `SameSite=Lax`, which stops a pure
 *      cross-site POST but not a same-site attacker, which is the case CSRF tokens exist for.
 *   2. No JWT, so API/Bearer callers behave differently after a 2FA login than after a password
 *      login.
 *
 * Rather than loosening the global CSRF rule (that would start requiring tokens from every
 * BA-session-only client, including the E2E helper), this mints exactly what `POST /auth/login`
 * mints, so the two sign-in paths converge.
 *
 * Restricted to callers who actually hold a verified second factor — the population this exists
 * for. It grants nothing a password login would not: the JWT is derived from the session's own
 * user, never from request input.
 */
twoFactorChallengeRoutes.post('/complete', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user) return c.json({ error: 'Authentication required' }, 401)

  if (!(await hasVerifiedSecondFactor(c.env.DB, user.userId))) {
    // No enrolment => nothing was challenged => nothing to upgrade.
    return c.json({ error: 'No second factor on this account' }, 400)
  }

  const tokenTtl = await getJwtExpirySecondsFromDb(c.env.DB, c.env)
  const token = await AuthManager.generateToken(
    user.userId,
    user.email,
    user.role ?? 'viewer',
    c.env.JWT_SECRET,
    tokenTtl,
  )
  const isDev = c.env.ENVIRONMENT === 'development' || !c.env.ENVIRONMENT
  // Same attributes as POST /auth/login's auth_token.
  setCookie(c, 'auth_token', token, {
    httpOnly: true,
    secure: !isDev,
    sameSite: 'Strict',
    path: '/',
    maxAge: tokenTtl,
  })
  return c.json({ ok: true })
})

export { twoFactorAdminRoutes, twoFactorChallengeRoutes }
