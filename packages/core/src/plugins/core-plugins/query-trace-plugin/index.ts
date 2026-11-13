/**
 * Query Trace plugin — per-request D1/KV/cache trace panel for /admin pages.
 *
 * The recording primitives live in core (`utils/request-trace`) and are always
 * passthrough when idle. This plugin supplies the activation state, settings,
 * analysis, the panel UI, and the middleware core mounts first in app.ts.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { DEFAULT_QUERY_TRACE_SETTINGS, QUERY_TRACE_PLUGIN_ID } from './constants'
import { queryTraceAdminRoutes } from './routes/admin'

export const queryTracePlugin = definePlugin({
  id: QUERY_TRACE_PLUGIN_ID,
  version: '1.0.0',
  name: 'Query Trace',
  description: 'Per-request D1/KV/cache tracing panel for admin performance tuning.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team' },

  register(app) {
    app.route('/admin/plugins/query-trace', queryTraceAdminRoutes as any)
  },

  configSchema: {
    visibility: {
      type: 'select',
      label: 'Visibility',
      description: 'opt-in: only admins who enabled it for themselves (cookie). all-admins: every admin on every page.',
      default: DEFAULT_QUERY_TRACE_SETTINGS.visibility,
      options: [
        { value: 'opt-in', label: 'Opt-in (per admin)' },
        { value: 'all-admins', label: 'All admins' },
      ],
    },
    warnQueryMs: {
      type: 'number',
      label: 'Warn threshold (ms)',
      description: 'Queries at or above this are highlighted amber.',
      default: DEFAULT_QUERY_TRACE_SETTINGS.warnQueryMs,
      min: 1,
    },
    slowQueryMs: {
      type: 'number',
      label: 'Slow query threshold (ms)',
      description: 'Queries at or above this are red and reported as slow.',
      default: DEFAULT_QUERY_TRACE_SETTINGS.slowQueryMs,
      min: 1,
    },
    captureCallers: {
      type: 'boolean',
      label: 'Capture callers',
      description: 'Record the stack frame that issued each query.',
      default: DEFAULT_QUERY_TRACE_SETTINGS.captureCallers,
    },
    serverTimingHeader: {
      type: 'boolean',
      label: 'Server-Timing header',
      description: 'Emit a Server-Timing header on traced responses (admins only).',
      default: DEFAULT_QUERY_TRACE_SETTINGS.serverTimingHeader,
    },
    maxEntries: {
      type: 'number',
      label: 'Max entries per request',
      default: DEFAULT_QUERY_TRACE_SETTINGS.maxEntries,
      min: 100,
      max: 5000,
    },
  },

  activate: async () => console.info('[query-trace] activated'),
  deactivate: async () => console.info('[query-trace] deactivated'),
})

export function createQueryTracePlugin() {
  return queryTracePlugin
}

export { queryTraceAdminRoutes } from './routes/admin'
export * from './constants'
export default queryTracePlugin
