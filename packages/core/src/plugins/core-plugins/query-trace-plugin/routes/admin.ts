import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { wrapAdminPage } from '../../_shared/admin-template'
import { loadAsyncLocalStorage, RAW } from '../../../../utils/request-trace'
import { escapeHtml } from '../../../../utils/sanitize'
import { QUERY_TRACE_COOKIE } from '../constants'
import { getQueryTraceState } from '../state'

export const queryTraceAdminRoutes = new Hono<any>()

const PAGE = '/admin/plugins/query-trace'

// Admin role only: traces expose redacted SQL shapes and timings.
queryTraceAdminRoutes.use('*', async (c, next) => {
  const user = c.get('user') as { role?: string } | undefined
  if (!user) return c.redirect('/auth/login')
  if (user.role !== 'admin') return c.text('Forbidden', 403)
  return next()
})

queryTraceAdminRoutes.get('/', async (c) => {
  // getQueryTraceState must read through the RAW binding so its own query is never traced.
  const db = c.env.DB
  const state = await getQueryTraceState(db?.[RAW] ?? db)
  const als = await loadAsyncLocalStorage()
  const optedIn = getCookie(c, QUERY_TRACE_COOKIE) === '1'
  const s = state.settings
  // "On" only if tracing can actually happen: plugin active, ALS available, and this admin is in scope.
  const visible = state.active && !!als && (s.visibility === 'all-admins' || optedIn)

  const notice = als
    ? ''
    : `<div data-testid="trace-als-warning" class="mb-4 rounded border border-yellow-600 bg-yellow-900/30 p-3 text-yellow-200">Tracing unavailable: enable <code>nodejs_compat</code> in wrangler.toml.</div>`

  const btn = (enabled: '1' | '0', label: string) =>
    `<button type="button" data-testid="trace-me-${enabled === '1' ? 'enable' : 'disable'}" hx-post="${PAGE}/me" hx-vals='{"enabled":"${enabled}"}' class="px-3 py-2 rounded bg-sky-600 hover:bg-sky-500 text-white">${label}</button>`

  const body = `<div class="max-w-3xl mx-auto p-6 text-zinc-200">
<h1 class="text-2xl font-semibold mb-4">Query Trace</h1>
${notice}
<dl class="grid grid-cols-2 gap-2 mb-6">
<dt class="text-zinc-400">Plugin</dt><dd data-testid="trace-state-active">${state.active ? 'Active' : 'Inactive'}</dd>
<dt class="text-zinc-400">Visibility</dt><dd data-testid="trace-state-visibility">${escapeHtml(s.visibility)}</dd>
<dt class="text-zinc-400">Tracing for you</dt><dd data-testid="trace-state-me">${visible ? 'On' : 'Off'}</dd>
<dt class="text-zinc-400">Slow / warn thresholds</dt><dd>${s.slowQueryMs} ms / ${s.warnQueryMs} ms</dd>
</dl>
${s.visibility === 'all-admins' ? '<p class="mb-4 text-zinc-400">Visibility is set to all admins; the personal toggle has no effect.</p>' : `<div class="flex gap-3 mb-6">${optedIn ? btn('0', 'Disable for me') : btn('1', 'Enable for me')}</div>`}
<a data-testid="trace-settings-link" class="underline text-sky-400" href="/admin/plugins/query-trace/configure">Plugin settings</a>
</div>`
  return c.html(wrapAdminPage({ title: 'Query Trace', body }))
})

queryTraceAdminRoutes.post('/me', async (c) => {
  const form = await c.req.parseBody().catch(() => ({}) as Record<string, string>)
  const enabled = form['enabled'] === '1'
  if (enabled) {
    setCookie(c, QUERY_TRACE_COOKIE, '1', {
      path: '/admin',
      httpOnly: true,
      sameSite: 'Lax',
      secure: new URL(c.req.url).protocol === 'https:',
      maxAge: 7 * 24 * 60 * 60,
    })
  } else {
    deleteCookie(c, QUERY_TRACE_COOKIE, { path: '/admin' })
  }
  if (c.req.header('HX-Request')) {
    c.header('HX-Redirect', PAGE)
    return c.body(null, 204)
  }
  return c.redirect(PAGE, 303)
})
