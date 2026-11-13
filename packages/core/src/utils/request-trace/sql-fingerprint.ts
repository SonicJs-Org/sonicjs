/**
 * SQL / KV-key redaction + fingerprinting for request traces.
 *
 * Nothing in here ever returns a raw literal or bound value: labels, fingerprints,
 * masked params and redacted keys are the only things stored on a TraceEntry.
 */

const MAX_LABEL = 2000

// One pass tokenizer so literals inside quoted identifiers / identifiers with digits
// (`q_1`, `t2.col`) are never touched.
const TOKEN_RE = new RegExp(
  [
    "[xX]'[0-9a-fA-F]*'", // blob literal
    "'(?:[^']|'')*'", // string literal ('' escapes)
    '"(?:[^"]|"")*"', // quoted identifier
    '`[^`]*`', // backtick identifier
    '\\[[^\\]]*\\]', // bracket identifier
    '[A-Za-z_][A-Za-z0-9_$]*', // identifier / keyword
    '0[xX][0-9a-fA-F]+', // hex number
    '\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?', // number
  ].join('|'),
  'g'
)

/** Collapse whitespace, replace every string/blob/numeric literal with `?`. Case preserved. */
export function redactSql(sql: string): string {
  const collapsed = sql.replace(/\s+/g, ' ').trim()
  const out = collapsed.replace(TOKEN_RE, (tok) => {
    const c = tok[0]!
    if (c === "'" || ((c === 'x' || c === 'X') && tok[1] === "'")) return '?'
    if (c === '"' || c === '`' || c === '[') return tok
    if (/^[A-Za-z_]/.test(c)) return tok
    return '?'
  })
  return out.length > MAX_LABEL ? out.slice(0, MAX_LABEL) + '…' : out
}

/** Redacted SQL, lowercased, with `IN (?, ?, …)` collapsed. Groups duplicates / N+1 patterns. */
export function fingerprintSql(sql: string): string {
  return redactSql(sql)
    .toLowerCase()
    .replace(/\bin\s*\(\s*\?(?:\s*,\s*\?)*\s*\)/g, 'in (?…)')
}

export type SqlOp = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'PRAGMA' | 'OTHER'

export function sqlOp(sql: string): SqlOp {
  const m = /^\s*(?:(?:--[^\n]*\n|\/\*[\s\S]*?\*\/)\s*)*([A-Za-z]+)/.exec(sql)
  switch (m?.[1]?.toUpperCase()) {
    case 'SELECT':
    case 'WITH':
      return 'SELECT'
    case 'INSERT':
    case 'REPLACE':
      return 'INSERT'
    case 'UPDATE':
      return 'UPDATE'
    case 'DELETE':
      return 'DELETE'
    case 'PRAGMA':
      return 'PRAGMA'
    default:
      return 'OTHER'
  }
}

const TABLE_RE = /\b(?:from|join|into|update)\s+(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][\w$]*))(?![\w$(])/gi
const NOT_TABLES = new Set(['set', 'select', 'where', 'values'])

export function extractTables(sql: string): string[] {
  const seen = new Set<string>()
  for (const m of sql.matchAll(TABLE_RE)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4]
    if (name && !NOT_TABLES.has(name.toLowerCase())) seen.add(name)
  }
  return [...seen]
}

/** Describe bound values by shape only: `string(36)`, `number`, `null`, `bool`, `blob(n)`. */
export function maskParams(values: readonly unknown[]): string[] {
  return values.map((v) => {
    if (v === null || v === undefined) return 'null'
    switch (typeof v) {
      case 'string':
        return `string(${v.length})`
      case 'number':
      case 'bigint':
        return 'number'
      case 'boolean':
        return 'bool'
      default:
        if (v instanceof ArrayBuffer) return `blob(${v.byteLength})`
        if (ArrayBuffer.isView(v)) return `blob(${v.byteLength})`
        return 'object'
    }
  })
}

function fnv1a(str: string, seed: number): number {
  let h = seed >>> 0
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h >>> 0
}

/**
 * Salted hash of fingerprint + RAW bound values. Lets "identical repeat" detection compare
 * actual values without ever storing them. Keep the result private to the trace.
 */
export function identityKey(fingerprint: string, values: readonly unknown[], salt = ''): string {
  const body = JSON.stringify([salt, fingerprint, values], (_k, v) => {
    if (typeof v === 'bigint') return `${v}n`
    if (v instanceof ArrayBuffer) return Array.from(new Uint8Array(v))
    return v
  })
  return fnv1a(body, 0x811c9dc5).toString(16).padStart(8, '0') + fnv1a(body, 0x9747b28c).toString(16).padStart(8, '0')
}

/**
 * Segments of KV / cache keys that are safe to show verbatim: cache namespaces
 * (CACHE_CONFIGS in services/cache.ts + plugins/cache/services/cache-config.ts),
 * cache key "types", and the fixed prefixes core uses. Everything else is redacted.
 * A test asserts each entry still exists as a literal in packages/core/src.
 */
export const KNOWN_KEY_SEGMENTS: ReadonlySet<string> = new Set([
  // cache namespaces
  'api', 'user', 'content', 'collection', 'config', 'media', 'session', 'plugin',
  // generateKey() "types"
  'item', 'list', 'id', 'email', 'all', 'recent',
  // fixed core prefixes
  'rbac', 'perms', 'security', 'bf', 'locked', 'ip', 'ratelimit', '_catalog',
  '_sonicjs_installation_id', '__health_check__',
  // version suffix
  'v1',
])

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function redactSegment(seg: string): string {
  if (seg === '' || KNOWN_KEY_SEGMENTS.has(seg)) return seg
  if (UUID_RE.test(seg)) return '<uuid>'
  if (seg.includes('@')) return '<email>'
  if (/^\d+$/.test(seg)) return '<n>'
  return `<redacted:${seg.length}>`
}

/** Split on `:` `/` `|`; keep a segment only if allowlisted, otherwise replace with a shape tag. */
export function redactKey(key: string): string {
  return key
    .split(/([:/|])/)
    .map((part, i) => (i % 2 === 1 ? part : redactSegment(part)))
    .join('')
}
