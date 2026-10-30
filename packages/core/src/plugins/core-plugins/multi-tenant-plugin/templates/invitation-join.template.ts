import { escapeHtml } from '../../../../utils/sanitize'

export interface InvitationJoinPageData {
  tenantName: string
  tenantSlug: string
  role: string
  email: string
  token: string
  mode: 'register' | 'sign-in'
  error?: string
  version?: string
}

export function renderInvitationJoinPage(data: InvitationJoinPageData): string {
  const e = escapeHtml
  const isRegister = data.mode === 'register'
  const title = isRegister ? 'Create account to accept invitation' : 'Sign in to accept invitation'
  const action = isRegister ? '/join/invite/register' : '/join/invite/sign-in'

  const fields = isRegister ? `
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-sm font-medium text-zinc-200 mb-1">First name</label>
        <input type="text" name="firstName" required autocomplete="given-name"
          class="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-white/30">
      </div>
      <div>
        <label class="block text-sm font-medium text-zinc-200 mb-1">Last name</label>
        <input type="text" name="lastName" required autocomplete="family-name"
          class="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-white/30">
      </div>
    </div>
    <div>
      <label class="block text-sm font-medium text-zinc-200 mb-1">Password</label>
      <input type="password" name="password" required minlength="8" autocomplete="new-password"
        placeholder="Minimum 8 characters"
        class="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-white/30">
    </div>` : `
    <div>
      <label class="block text-sm font-medium text-zinc-200 mb-1">Password</label>
      <input type="password" name="password" required autocomplete="current-password"
        class="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-white/30">
    </div>`

  const errorHtml = data.error
    ? `<div class="rounded-lg bg-red-500/20 border border-red-500/30 px-4 py-3 text-sm text-red-300">${e(data.error)}</div>`
    : ''

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${e(title)} - SonicJS</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <!-- Logo -->
    <div class="text-center mb-8">
      <a href="/" class="inline-flex items-center gap-2 text-white font-bold text-xl">
        <svg class="h-8 w-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
        </svg>
        SonicJS
      </a>
    </div>

    <!-- Invitation context -->
    <div class="rounded-xl bg-white/5 border border-white/10 px-6 py-4 mb-6 text-center">
      <p class="text-sm text-zinc-400 mb-1">You've been invited to join</p>
      <p class="text-lg font-semibold text-white">${e(data.tenantName)}</p>
      <p class="text-sm text-zinc-400 mt-1">as <span class="text-white font-medium">${e(data.role)}</span></p>
    </div>

    <!-- Form card -->
    <div class="rounded-xl bg-white/5 border border-white/10 px-6 py-8">
      <h1 class="text-lg font-semibold text-white mb-6">${e(title)}</h1>

      ${errorHtml}

      <form method="POST" action="${e(action)}" class="space-y-4 ${data.error ? 'mt-4' : ''}">
        <input type="hidden" name="token" value="${e(data.token)}">

        <!-- Email (pre-filled, readonly) -->
        <div>
          <label class="block text-sm font-medium text-zinc-200 mb-1">Email</label>
          <input type="email" name="email" value="${e(data.email)}" readonly
            class="w-full rounded-lg bg-white/5 border border-white/10 px-3 py-2 text-sm text-zinc-400 cursor-not-allowed">
        </div>

        ${fields}

        <button type="submit"
          class="w-full rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-zinc-100 transition-colors mt-2">
          ${isRegister ? 'Create account &amp; accept invitation' : 'Sign in &amp; accept invitation'}
        </button>
      </form>
    </div>

    ${data.version ? `<p class="text-center text-xs text-zinc-600 mt-6">SonicJS ${e(data.version)}</p>` : ''}
  </div>
</body>
</html>`
}

export function renderInvitationErrorPage(message: string, version?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Invalid Invitation - SonicJS</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
  <div class="w-full max-w-md text-center">
    <div class="rounded-xl bg-white/5 border border-white/10 px-6 py-10">
      <svg class="h-12 w-12 text-red-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
      </svg>
      <h1 class="text-xl font-semibold text-white mb-2">Invitation invalid</h1>
      <p class="text-sm text-zinc-400 mb-6">${escapeHtml(message)}</p>
      <a href="/auth/login" class="inline-flex items-center rounded-lg bg-white px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-zinc-100">
        Go to sign in
      </a>
    </div>
    ${version ? `<p class="text-xs text-zinc-600 mt-6">SonicJS ${escapeHtml(version)}</p>` : ''}
  </div>
</body>
</html>`
}
