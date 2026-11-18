export const QUERY_TRACE_PLUGIN_ID = 'query-trace'
export const QUERY_TRACE_COOKIE = 'sjs_trace'
export const QUERY_TRACE_STATE_TTL_MS = 30_000

export type QueryTraceVisibility = 'opt-in' | 'all-admins'

export interface QueryTraceSettings {
  visibility: QueryTraceVisibility
  warnQueryMs: number
  slowQueryMs: number
  captureCallers: boolean
  serverTimingHeader: boolean
  maxEntries: number
}

export const DEFAULT_QUERY_TRACE_SETTINGS: QueryTraceSettings = {
  visibility: 'opt-in',
  warnQueryMs: 25,
  slowQueryMs: 100,
  captureCallers: true,
  serverTimingHeader: true,
  maxEntries: 1000,
}
