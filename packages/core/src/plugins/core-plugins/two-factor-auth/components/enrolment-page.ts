/**
 * Enrolment page — `/admin/two-factor`.
 *
 * ── QR code ──
 * Authenticator apps take an `otpauth://` URI. This page renders it three ways, in descending
 * order of how people actually enrol: a scannable QR, the `otpauth://` link (which opens the app
 * directly when the admin panel IS on the phone), and the raw secret for manual entry.
 *
 * An earlier version shipped only the link and the secret, arguing that every authenticator
 * supports manual entry so a QR dependency "would buy one paste". That was wrong about the
 * primary flow: the admin panel is used on a desktop and the authenticator lives on a phone, so
 * there is no handler for the link and no shared clipboard — the user is left hand-typing a
 * 32-character base32 secret across devices, or unable to enrol at all. The QR is rendered
 * server-side by `POST /admin/two-factor/qr` (see routes.ts) because these pages have no client
 * bundler and a CDN script tag on the page that handles TOTP secrets is not a trade worth making.
 *
 * ── Backup codes ──
 * Shown exactly once, at enrolment, and the page says so plainly rather than burying it. With
 * no external identity provider they are the ONLY route back in if the device is lost.
 *
 * ── Passwordless notice ──
 * The page states that enrolling disables magic-link / email-code sign-in for the account.
 * That is a real consequence of `auth/passwordless-second-factor-guard.ts`, and a user who
 * discovers it by having a link silently stop arriving would reasonably call it a bug.
 *
 * ── CSRF ──
 * Every mutation is a cookie-authenticated POST to `/auth/two-factor/*`, which is NOT on
 * `csrfProtection`'s exempt list, so each one carries `X-CSRF-Token` read from the `csrf_token`
 * cookie the GET of this page just set. Without the header they all 403.
 */
import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'

export interface EnrolmentPageData {
  /** A verified enrolment exists — render the "on" state. */
  verified: boolean
  /** A row exists but was never confirmed against a live code. */
  pending: boolean
  /**
   * The RAW `auth_user.two_factor_required` flag — an admin mandates a second factor here.
   *
   * Two different things are derived from it, and they are not the same condition:
   *   - `required && !verified` → the amber "set up to continue" banner. The portal is closed.
   *   - `required` alone        → the disable form is replaced by an explanation. A user who has
   *                               satisfied the requirement still may not turn it back off.
   *
   * Read from the database, never from the request: this tells the user their administrator acted
   * on their account, and a query parameter would let anyone put those words on their screen.
   */
  required?: boolean
  user?: { name: string; email: string; role: string }
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
}

const INPUT_CLASS =
  'w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10'
const PRIMARY_BUTTON_CLASS =
  'rounded-lg bg-zinc-900 dark:bg-white px-3 py-2 text-sm font-medium text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200'

export function renderTwoFactorEnrolmentPage(data: EnrolmentPageData): string {
  const { verified, pending } = data

  const statusLabel = verified ? 'Enabled' : pending ? 'Started, not confirmed' : 'Disabled'
  const statusClass = verified
    ? 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-green-600/20 dark:ring-green-500/20'
    : 'bg-zinc-50 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 ring-zinc-500/10 dark:ring-zinc-400/20'

  const content = `
    <div class="space-y-6 max-w-2xl">
      <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Two-Factor Authentication</h1>
${data.required && !verified ? `
      <div class="rounded-xl bg-amber-50 dark:bg-amber-500/10 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20 px-4 py-3">
        <p class="text-sm font-medium text-amber-900 dark:text-amber-200">Set up two-factor to continue</p>
        <p class="mt-1 text-sm text-amber-800 dark:text-amber-300">
          An administrator reset the two-factor authentication on your account. The rest of the
          admin portal stays closed until you finish setting it up again.
        </p>
      </div>
` : ''}
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
        <p class="text-sm text-zinc-500 dark:text-zinc-400">
          Add a time-based one-time password (TOTP) from an authenticator app as a second factor
          on your account. You will be asked for a code after your password on every sign-in.
        </p>

        <p class="mt-4 text-sm text-zinc-500 dark:text-zinc-400">
          Status
          <span id="tf-status" class="ml-1 inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${statusClass}">${escapeHtml(statusLabel)}</span>
        </p>

        <div class="mt-4 rounded-lg bg-blue-50 dark:bg-blue-500/10 px-4 py-3">
          <p class="text-sm text-blue-800 dark:text-blue-300">
            While two-factor authentication is on, magic links and emailed sign-in codes are
            disabled for this account &mdash; anyone who reads your inbox would otherwise be able
            to skip the second factor entirely. Sign in with your password and your authenticator.
          </p>
        </div>

        ${pending ? `
        <div class="mt-4 rounded-lg bg-amber-50 dark:bg-amber-900/20 px-4 py-3">
          <p class="text-sm text-amber-800 dark:text-amber-300">
            A previous setup was started but never confirmed with a live code, so two-factor is
            <strong>not</strong> active. Start again below &mdash; that issues a fresh secret and a
            fresh set of backup codes, and discards the unconfirmed one.
          </p>
        </div>` : ''}

        <div id="state-off" class="${verified ? 'hidden' : ''} mt-6">
          <form id="enrolForm" class="max-w-sm space-y-3">
            <label for="tf-pw" class="block text-sm font-medium text-zinc-950 dark:text-white">Confirm your password</label>
            <input id="tf-pw" type="password" autocomplete="current-password" required class="${INPUT_CLASS}">
            <button type="submit" id="enrolBtn" class="${PRIMARY_BUTTON_CLASS}">Begin setup</button>
          </form>
        </div>

        <div id="state-enrolling" class="hidden mt-6 space-y-4">
          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            1. Scan this QR code with your authenticator app (Google Authenticator, 1Password, Authy&hellip;).
          </p>
          <!-- Always white, never themed: a dark-mode-inverted QR is unreadable to most scanners.
               NOT a fixed width. This box shrink-wraps whatever size the server sized the SVG to
               (see CSS_PX_PER_MODULE in routes.ts), because the module count — and so the width
               needed to stay scannable — grows with the issuer and email in the URI. It shipped as
               w-[260px], which silently squeezed a 69-module symbol into 236 px and produced a
               well-formed image no phone could read. max-w-full keeps it inside a narrow viewport,
               where the otpauth:// link below is the better path anyway. -->
          <div id="tf-qr" class="w-fit max-w-full rounded-lg bg-white p-3 ring-1 ring-inset ring-zinc-950/10">
            <p class="text-xs text-zinc-500">Generating QR code&hellip;</p>
          </div>

          <details class="text-sm text-zinc-500 dark:text-zinc-400">
            <summary class="cursor-pointer select-none">Can't scan it?</summary>
            <div class="mt-2 space-y-2">
              <p>
                If the admin panel is open on the same device as your authenticator, use this link:
              </p>
              <p><a id="otpauth" href="#" rel="noreferrer" class="break-all text-blue-600 dark:text-blue-400 underline"></a></p>
              <p>Otherwise add the account by hand. Secret:
                <code id="tf-secret" class="select-all text-zinc-950 dark:text-white"></code></p>
            </div>
          </details>

          <p class="text-sm text-zinc-500 dark:text-zinc-400">2. Save your backup codes.</p>
          <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 px-4 py-3">
            <p class="text-sm text-amber-800 dark:text-amber-300">
              These codes are shown once and never again. Each one works a single time. If you lose
              your authenticator device they are the only way back into this account &mdash; store them
              somewhere other than the device itself.
            </p>
          </div>
          <pre id="tf-codes" class="select-all rounded-lg bg-zinc-50 dark:bg-zinc-800 p-3 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"></pre>

          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            3. Enter the current 6-digit code to confirm. Two-factor is not active until you do.
          </p>
          <form id="verifyForm" class="max-w-[14rem] space-y-3">
            <input id="tf-code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" required
              placeholder="000000"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-center text-lg tracking-[0.15em] text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">
            <button type="submit" id="verifyBtn" class="w-full ${PRIMARY_BUTTON_CLASS}">Confirm</button>
          </form>
        </div>

        <div id="state-on" class="${verified ? '' : 'hidden'} mt-6 space-y-4">
          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            Two-factor authentication is active on this account. You will be asked for a code after
            your password on every sign-in.
          </p>
          ${data.required ? `
          <div id="tf-locked-on" class="rounded-lg bg-zinc-50 dark:bg-zinc-800/60 ring-1 ring-inset ring-zinc-950/5 dark:ring-white/10 px-4 py-3">
            <p class="text-sm font-medium text-zinc-950 dark:text-white">Required by an administrator</p>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
              Two-factor authentication is mandatory on this account and cannot be turned off here.
              Ask an administrator if this needs to change.
            </p>
          </div>
          ` : `
          <form id="disableForm" class="max-w-sm space-y-3">
            <label for="tf-pw-off" class="block text-sm font-medium text-zinc-950 dark:text-white">Confirm your password</label>
            <input id="tf-pw-off" type="password" autocomplete="current-password" required class="${INPUT_CLASS}">
            <button type="submit" id="disableBtn"
              class="rounded-lg bg-white dark:bg-zinc-900 px-3 py-2 text-sm font-medium text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20 hover:bg-red-50 dark:hover:bg-red-900/20">Turn off two-factor</button>
          </form>
          `}
        </div>

        <div id="tf-msg" class="hidden mt-4 rounded-lg px-4 py-3 text-sm"></div>
      </div>
    </div>

    <script>
    (function () {
      var $ = function (id) { return document.getElementById(id); };
      // These POSTs are not on csrfProtection's exempt list, so the double-submit header is sent.
      //
      // Be aware it is currently INERT, verified against a running server: csrfProtection exempts
      // any request with no auth_token cookie, and sign-in mints better-auth.session_token
      // instead — so a valid session with a missing or bogus token is accepted. Sending it is
      // still correct: it costs nothing and it is what makes these calls work unchanged once
      // csrf.ts learns to treat a BA session cookie as cookie-authenticated ("OD2 Option B").
      // Do NOT read the presence of this header as evidence that CSRF is enforced here.
      function csrf() {
        var m = document.cookie.match(/(?:^|;\\s*)csrf_token=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : '';
      }
      function post(path, body) {
        return fetch('/auth/two-factor/' + path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
          body: JSON.stringify(body),
          credentials: 'include',
        });
      }
      // The QR renderer is OUR route, not a Better Auth one — different prefix.
      function renderQr(uri) {
        var box = $('tf-qr');
        return fetch('/admin/two-factor/qr', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
          body: JSON.stringify({ uri: uri }),
          credentials: 'include',
        }).then(function (res) {
          if (!res.ok) throw new Error('qr');
          return res.json();
        }).then(function (data) {
          // Server-generated from a URI validated against ^otpauth://totp/ — the only markup in
          // it is the SVG scaffold qrcode-svg emits.
          box.innerHTML = data.svg;
        }).catch(function () {
          // Never block enrolment on the QR: the link and the secret below still work.
          box.innerHTML = '<p class="text-xs text-zinc-500">QR code unavailable &mdash; use the link or secret below.</p>';
        });
      }
      function msg(kind, text) {
        var m = $('tf-msg');
        m.classList.remove('hidden');
        m.className = 'mt-4 rounded-lg px-4 py-3 text-sm ' + (kind === 'err'
          ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300'
          : 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-800 dark:text-emerald-300');
        m.textContent = text;
      }

      $('enrolForm').addEventListener('submit', function (e) {
        e.preventDefault();
        $('enrolBtn').disabled = true;
        post('enable', { password: $('tf-pw').value }).then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            if (!res.ok) { msg('err', data.message || 'Could not start setup. Check your password and try again.'); return; }
            var uri = data.totpURI || data.totpUri || '';
            $('otpauth').href = uri;
            $('otpauth').textContent = uri;
            try { $('tf-secret').textContent = new URL(uri).searchParams.get('secret') || ''; }
            catch (_) { $('tf-secret').textContent = ''; }
            $('tf-codes').textContent = (data.backupCodes || []).join('\\n');
            $('tf-pw').value = '';
            $('state-off').classList.add('hidden');
            $('state-enrolling').classList.remove('hidden');
            renderQr(uri);
            $('tf-code').focus();
          });
        }).catch(function () { msg('err', 'Network error. Please try again.'); })
          .then(function () { $('enrolBtn').disabled = false; });
      });

      $('verifyForm').addEventListener('submit', function (e) {
        e.preventDefault();
        $('verifyBtn').disabled = true;
        post('verify-totp', { code: $('tf-code').value.trim() }).then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            if (!res.ok) { msg('err', data.message || 'That code was not accepted. Try the current one.'); return; }
            $('state-enrolling').classList.add('hidden');
            $('state-on').classList.remove('hidden');
            $('tf-status').textContent = 'Enabled';
            msg('ok', 'Two-factor authentication is now active on your account.');
          });
        }).catch(function () { msg('err', 'Network error. Please try again.'); })
          .then(function () { $('verifyBtn').disabled = false; });
      });

      // Absent when an administrator requires 2FA on this account — the form is replaced by an
      // explanation. Binding unconditionally would throw on null and take the enrol and verify
      // handlers down with it, since this is all one IIFE.
      if ($('disableForm')) $('disableForm').addEventListener('submit', function (e) {
        e.preventDefault();
        if (!window.confirm('Turn off two-factor authentication? Your account will be protected by its password alone.')) return;
        $('disableBtn').disabled = true;
        post('disable', { password: $('tf-pw-off').value }).then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            if (!res.ok) { msg('err', data.message || 'Could not turn two-factor off. Check your password and try again.'); return; }
            $('tf-pw-off').value = '';
            $('state-on').classList.add('hidden');
            $('state-off').classList.remove('hidden');
            $('tf-status').textContent = 'Disabled';
            msg('ok', 'Two-factor authentication has been turned off.');
          });
        }).catch(function () { msg('err', 'Network error. Please try again.'); })
          .then(function () { $('disableBtn').disabled = false; });
      });
    })();
    </script>`

  return renderAdminLayoutCatalyst({
    title: 'Two-Factor Authentication',
    pageTitle: 'Two-Factor Authentication',
    currentPath: '/admin/two-factor',
    user: data.user,
    version: data.version,
    dynamicMenuItems: data.dynamicMenuItems,
    content,
  })
}
