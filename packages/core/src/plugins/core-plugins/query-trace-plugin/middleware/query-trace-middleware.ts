import type { MiddlewareHandler } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { RequestTrace, loadAsyncLocalStorage, runWithTrace, wrapTraceBindings } from '../../../../utils/request-trace'
import { QUERY_TRACE_COOKIE } from '../constants'
import { getQueryTraceState } from '../state'
import { analyze, serverTimingValue } from '../services/analyze'
import { renderTracePanel } from '../components/trace-panel'

/**
 * Core-mounted request tracing. Always installs passthrough binding proxies
 * (so singletons seeded by any request hold proxies), then traces only
 * /admin requests when the plugin is active and the caller opted in.
 */
export const queryTraceMiddleware = (): MiddlewareHandler => async (c, next) => {
  const rawDb = (c.env as any)?.DB
  if (c.env) c.env = wrapTraceBindings(c.env as any) as typeof c.env

  const url = new URL(c.req.url)
  const p = url.pathname
  if (p !== '/admin' && !p.startsWith('/admin/')) return next()
  if (!rawDb) return next()

  const state = await getQueryTraceState(rawDb)
  if (!state.active) return next()

  const toggle = url.searchParams.get('trace')
  if (toggle === '1' || toggle === '0') {
    if (toggle === '1') {
      setCookie(c, QUERY_TRACE_COOKIE, '1', {
        path: '/admin',
        httpOnly: true,
        sameSite: 'Lax',
        secure: url.protocol === 'https:',
        maxAge: 7 * 24 * 60 * 60,
      })
    } else {
      deleteCookie(c, QUERY_TRACE_COOKIE, { path: '/admin' })
    }
    url.searchParams.delete('trace')
    return c.redirect(url.pathname + url.search)
  }

  const optedIn = getCookie(c, QUERY_TRACE_COOKIE) === '1'
  if (state.settings.visibility !== 'all-admins' && !optedIn) return next()
  if (!(await loadAsyncLocalStorage())) return next()

  const trace = new RequestTrace(c.req.method, p, state.settings.maxEntries, state.settings.captureCallers)
  try {
    await runWithTrace(trace, () => next())
  } finally {
    trace.closed = true
  }

  const user = c.get('user') as { role?: string } | undefined
  if (user?.role !== 'admin') return

  const totalMs = trace.now()
  const analysis = analyze(trace, state.settings, totalMs)
  if (state.settings.serverTimingHeader) c.header('Server-Timing', serverTimingValue(analysis))

  const res = c.res
  const ct = res.headers.get('content-type') ?? ''
  const status = res.status
  if (!ct.includes('text/html') || (status >= 300 && status < 400) || c.req.header('HX-Request')) return

  const body = await res.text()
  const i = body.lastIndexOf('</body>')
  const out = i === -1 ? body : body.slice(0, i) + renderTracePanel(trace, analysis, state.settings) + body.slice(i)
  const headers = new Headers(res.headers)
  headers.delete('content-length')
  // Hono's c.res setter re-copies old headers (incl. stale content-length); clear first.
  c.res = undefined as any
  c.res = new Response(out, { status, headers })
}
