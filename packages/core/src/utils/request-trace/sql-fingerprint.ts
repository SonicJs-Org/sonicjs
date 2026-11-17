/**
 * SQL / KV-key redaction + fingerprinting for request traces.
 *
 * Nothing in here ever returns a raw literal or bound value: labels, fingerprints,
 * masked params and redacted keys are the only things stored on a TraceEntry.
 */

const MAX_LABEL = 2000

// One pass tokenizer so literals inside quoted identifiers / identifiers with digits
// (`q_1`, `t2.col`) are never touched. Alternation order matters: a quote that starts earlier
// consumes comment-like text inside it, and comments consume quote-like text inside them.
const TOKEN_RE = new RegExp(
  [
    '--[^\\n]*', // line comment
    '/\\*[\\s\\S]*?(?:\\*/|$)', // block comment (unterminated runs to end)
    "[xX]'[0-9a-fA-F]*(?:'|$)", // blob literal (unterminated runs to end)
    "'(?:[^']|'')*(?:'|$)", // string literal ('' escapes; unterminated runs to end)
    '"(?:[^"]|"")*(?:"|$)', // double-quoted: identifier, or a string literal in SQLite when unresolved
    '`[^`]*`', // backtick identifier
    '\\[[^\\]]*\\]', // bracket identifier
    '[A-Za-z_][A-Za-z0-9_$]*', // identifier / keyword
    '0[xX][0-9a-fA-F]+', // hex number
    '\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?', // number
  ].join('|'),
  'g'
)

// A double-quoted token is only kept verbatim where a table name is expected; anywhere else
// SQLite may treat it as a string literal, so it is redacted like a single-quoted one.
const TABLE_KEYWORD_TAIL_RE = /\b(?:from|join|into|update|table)$/i
const TERMINATED_DQ_RE = /^"(?:[^"]|"")*"$/

/** True when a table keyword, then >=1 whitespace of any length, directly precedes `offset`. */
function inTablePosition(whole: string, offset: number): boolean {
  let j = offset
  while (j > 0 && /\s/.test(whole[j - 1]!)) j--
  if (j === offset) return false
  return TABLE_KEYWORD_TAIL_RE.test(whole.slice(Math.max(0, j - 7), j))
}

function redactSqlFull(sql: string, dqHash = false): string {
  const out = sql.replace(TOKEN_RE, (tok, offset: number, whole: string) => {
    const c = tok[0]!
    if (c === '-' && tok[1] === '-') return ' '
    if (c === '/' && tok[1] === '*') return ' '
    if (c === "'" || ((c === 'x' || c === 'X') && tok[1] === "'")) return '?'
    if (c === '"') {
      if (TERMINATED_DQ_RE.test(tok) && inTablePosition(whole, offset)) return tok
      // Fingerprint only: keep distinct quoted tokens (Drizzle column names) distinct without
      // storing the raw text, which may be a string literal.
      if (dqHash) {
        const h = new Hasher()
        h.str(tok)
        return `?q${h.digest()}`
      }
      return '?'
    }
    if (c === '`' || c === '[') return tok
    if (/^[A-Za-z_]/.test(c)) return tok
    return '?'
  })
  return out.replace(/\s+/g, ' ').trim()
}

/**
 * Strip comments, collapse whitespace, replace every string/blob/numeric literal (and any
 * double-quoted token outside table position) with `?`. Case preserved.
 */
export function redactSql(sql: string): string {
  const out = redactSqlFull(sql)
  return out.length > MAX_LABEL ? out.slice(0, MAX_LABEL) + '…' : out
}

/** Redacted SQL, lowercased, with `IN (?, ?, …)` collapsed. Groups duplicates / N+1 patterns. */
export function fingerprintSql(sql: string): string {
  const out = redactSqlFull(sql, true)
  return (out.length > MAX_LABEL ? out.slice(0, MAX_LABEL) + '…' : out)
    .toLowerCase()
    .replace(/\bin\s*\(\s*\?(?:\s*,\s*\?)*\s*\)/g, 'in (?…)')
}

export type SqlOp = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'PRAGMA' | 'OTHER'

const CTE_VERBS: ReadonlyMap<string, SqlOp> = new Map<string, SqlOp>([
  ['select', 'SELECT'], ['insert', 'INSERT'], ['replace', 'INSERT'], ['update', 'UPDATE'], ['delete', 'DELETE'],
])

/** The verb of a `WITH …` statement is the first keyword at paren depth 0 after the CTE list. */
function cteOp(sql: string): SqlOp {
  const scan = redactSqlFull(sql).replace(/"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\]/g, ' ')
  let depth = 0
  for (const m of scan.matchAll(/[()]|[A-Za-z_]+/g)) {
    const t = m[0]
    if (t === '(') depth++
    else if (t === ')') depth--
    else if (depth === 0) {
      const verb = CTE_VERBS.get(t.toLowerCase())
      if (verb) return verb
    }
  }
  return 'OTHER'
}

export function sqlOp(sql: string): SqlOp {
  const m = /^\s*(?:(?:--[^\n]*\n|\/\*[\s\S]*?\*\/)\s*)*([A-Za-z]+)/.exec(sql)
  switch (m?.[1]?.toUpperCase()) {
    case 'SELECT':
      return 'SELECT'
    case 'WITH':
      return cteOp(sql)
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

/** Scans the REDACTED sql so words inside string literals / comments can never leak via `tables`. */
export function extractTables(sql: string): string[] {
  const seen = new Set<string>()
  for (const m of redactSqlFull(sql).matchAll(TABLE_RE)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4]
    if (name && !NOT_TABLES.has(name.toLowerCase())) seen.add(name)
  }
  return [...seen]
}

const MAX_ERROR = 500

/** Error text from the driver can echo literals from the submitted SQL; run it through the same redaction. */
export function redactErrorMessage(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  const out = redactSqlFull(msg)
  return out.length > MAX_ERROR ? out.slice(0, MAX_ERROR) + '…' : out
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

/** Two independent FNV-1a lanes fed incrementally, so large blobs are never stringified. */
class Hasher {
  private a = 0x811c9dc5
  private b = 0x9747b28c
  str(v: string): void {
    // length-prefix so a 0xff / U+00FF inside content can never be mistaken for the separator
    this.num(v.length)
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i)
      this.a = Math.imul(this.a ^ c, 0x01000193) >>> 0
      this.b = Math.imul(this.b ^ c, 0x01000193) >>> 0
    }
    this.sep()
  }
  bytes(u8: Uint8Array): void {
    for (let i = 0; i < u8.length; i++) {
      this.a = Math.imul(this.a ^ u8[i]!, 0x01000193) >>> 0
      this.b = Math.imul(this.b ^ u8[i]!, 0x01000193) >>> 0
    }
    this.str(`#${u8.length}`)
  }
  private num(n: number): void {
    for (let k = 0; k < 4; k++) {
      const byte = (n >>> (k * 8)) & 0xff
      this.a = Math.imul(this.a ^ byte, 0x01000193) >>> 0
      this.b = Math.imul(this.b ^ byte, 0x01000193) >>> 0
    }
  }
  private sep(): void {
    this.a = Math.imul(this.a ^ 0xff, 0x01000193) >>> 0
    this.b = Math.imul(this.b ^ 0xff, 0x01000193) >>> 0
  }
  digest(): string {
    return this.a.toString(16).padStart(8, '0') + this.b.toString(16).padStart(8, '0')
  }
}

/**
 * Salted hash of fingerprint + RAW sql + RAW bound values. Lets "identical repeat" detection
 * compare actual values (including inline literals the fingerprint stripped) without ever
 * storing them. Keep the result private to the trace.
 */
export function identityKey(fingerprint: string, values: readonly unknown[], salt = '', rawSql = ''): string {
  const h = new Hasher()
  h.str(salt)
  h.str(fingerprint)
  h.str(rawSql)
  for (const v of values) {
    if (v === null || v === undefined) h.str('N')
    else if (v instanceof ArrayBuffer) { h.str('B'); h.bytes(new Uint8Array(v)) }
    else if (ArrayBuffer.isView(v)) { h.str('B'); h.bytes(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)) }
    else if (typeof v === 'bigint') h.str(`n${v}`)
    else if (typeof v === 'string') h.str(`s${v}`)
    else if (typeof v === 'number' || typeof v === 'boolean') h.str(`${typeof v === 'number' ? 'd' : 'b'}${String(v)}`)
    else h.str(`o${safeJson(v)}`)
  }
  return h.digest()
}

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v) ?? ''
  } catch {
    return ''
  }
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
  'item', 'list', 'email', 'all', 'recent',
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
