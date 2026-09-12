/**
 * Login challenge page — `/auth/two-factor`.
 *
 * Reached after a password has been accepted but before a session exists. Renders standalone
 * (mirroring the login page rather than the admin layout) for the same reason it is mounted
 * outside `/admin/*`: there is no session yet, so there is no admin chrome, no user menu, and no
 * permissions to render.
 *
 * ── Backup codes are always offered ──
 * NOT keyed off Better Auth's `twoFactorMethods`, which only ever contains `'totp'` and `'otp'`
 * — never `'backup_code'` (see the after-hook in better-auth/plugins/two-factor). Keying the UI
 * off that list would hide backup-code entry exactly when it matters most: the user has lost the
 * device that generates the codes the list is telling them to use.
 *
 * ── CSRF ──
 * These POSTs normally carry no `auth_token` cookie (BA deleted the session cookie when it issued
 * the challenge), and `csrfProtection` exempts cookie-less requests. But a browser that still
 * holds a stale `auth_token` from a previous session WOULD be validated, so the header is sent
 * unconditionally — the GET of this page sets `csrf_token`, so it is always available. Sending it
 * when it is not required is inert; omitting it when it is required is a 403 nobody can debug.
 */

const INPUT_CLASS =
  'w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10'

export function renderTwoFactorChallengePage(): string {
  return `<!DOCTYPE html>
<html lang="en" class="h-full dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Two-Factor Verification - SonicJS AI</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = { darkMode: 'class' }
  </script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
  </style>
</head>
<body class="h-full bg-zinc-50 dark:bg-zinc-950">
  <div class="flex min-h-full items-center justify-center px-4 py-12">
    <div class="w-full max-w-sm space-y-6">
      <h1 class="text-center text-2xl font-semibold text-zinc-950 dark:text-white">Two-step verification</h1>
      <p class="text-center text-sm text-zinc-500 dark:text-zinc-400">
        Enter the 6-digit code from your authenticator app to finish signing in.
      </p>

      <div class="rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 space-y-4">
        <form id="totpForm" class="space-y-3">
          <label for="tf-code" class="block text-sm font-medium text-zinc-950 dark:text-white">Authentication code</label>
          <input id="tf-code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" required autofocus
            placeholder="000000"
            class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-center text-lg tracking-[0.15em] text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">
          <button type="submit" id="totpBtn"
            class="w-full rounded-lg bg-zinc-900 dark:bg-white px-3 py-2 text-sm font-medium text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200">Verify</button>
        </form>

        <button type="button" id="backupToggle"
          class="w-full text-center text-sm text-zinc-500 dark:text-zinc-400 underline hover:text-zinc-900 dark:hover:text-white">Use a backup code instead</button>

        <form id="backupForm" class="hidden space-y-3 border-t border-zinc-950/5 dark:border-white/10 pt-4">
          <label for="tf-backup" class="block text-sm font-medium text-zinc-950 dark:text-white">Backup code</label>
          <input id="tf-backup" autocomplete="one-time-code" required placeholder="xxxxx-xxxxx" class="${INPUT_CLASS}">
          <button type="submit" id="backupBtn"
            class="w-full rounded-lg bg-white dark:bg-zinc-900 px-3 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800">Verify backup code</button>
        </form>

        <div id="tf-msg" class="hidden rounded-lg px-4 py-3 text-sm"></div>
      </div>

      <p class="text-center"><a href="/auth/login" class="text-sm text-zinc-500 dark:text-zinc-400 underline hover:text-zinc-900 dark:hover:text-white">Back to sign in</a></p>
    </div>
  </div>

  <script>
  (function () {
    var $ = function (id) { return document.getElementById(id); };
    function csrf() {
      var m = document.cookie.match(/(?:^|;\\s*)csrf_token=([^;]+)/);
      return m ? decodeURIComponent(m[1]) : '';
    }
    function msg(text) {
      var m = $('tf-msg');
      m.classList.remove('hidden');
      m.className = 'rounded-lg px-4 py-3 text-sm bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300';
      m.textContent = text;
    }
    function post(path, body) {
      return fetch('/auth/two-factor/' + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
        body: JSON.stringify(body),
        credentials: 'include',
      });
    }
    function submit(path, body, btn, fallback) {
      btn.disabled = true;
      post(path, body).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) { msg(data.message || fallback); return; }
          // Better Auth has set its session cookie. Bring the session up to the same shape a
          // password login produces (auth_token JWT) before navigating — without it,
          // csrfProtection would skip validation for the whole session, because it treats a
          // request with no auth_token cookie as token-authenticated. Non-fatal if it fails: the
          // BA session alone still authenticates, so land the user rather than trapping them here.
          return post('complete', {})
            .catch(function () { /* ignore — see above */ })
            .then(function () {
              // Same landing page the password-only login flow uses.
              window.location.href = '/admin/content';
            });
        });
      }).catch(function () { msg('Network error. Please try again.'); })
        .then(function () { btn.disabled = false; });
    }

    $('totpForm').addEventListener('submit', function (e) {
      e.preventDefault();
      submit('verify-totp', { code: $('tf-code').value.trim() }, $('totpBtn'), 'That code was not accepted.');
    });
    $('backupToggle').addEventListener('click', function () {
      $('backupForm').classList.toggle('hidden');
      $('tf-backup').focus();
    });
    $('backupForm').addEventListener('submit', function (e) {
      e.preventDefault();
      submit('verify-backup-code', { code: $('tf-backup').value.trim() }, $('backupBtn'), 'That backup code was not accepted.');
    });
  })();
  </script>
</body>
</html>`
}
