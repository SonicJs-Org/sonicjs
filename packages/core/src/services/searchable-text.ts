/**
 * Plain-text harvester for full-text indexing (FTS5 `body`).
 *
 * sonicjs-org has no `toPlainText` / field-type text registry (unlike infowall, where richtext
 * fields carry a `toPlainText` hook). So this self-contained function renders an arbitrary field
 * value — plain string, HTML, Quill Delta JSON, or nested object/array — into the readable prose
 * that gets indexed into `documents_fts.body`, rather than indexing JSON punctuation / markup.
 *
 * Ported from infowall's `extractSearchableText` recursion, extended with HTML stripping and
 * Quill Delta flattening (which infowall did separately via field-type hooks).
 */

const MAX_DEPTH = 5

// Keys whose values are structural / identifiers, not searchable prose.
const SKIP_KEYS = new Set([
  'id', '_id', 'slug', 'url', 'href', 'src',
  'image', 'thumbnail', 'avatar', 'icon', 'logo',
  'metadata', 'meta', 'created_at', 'updated_at',
  'author_id', 'collection_id', 'parent_id',
])

const UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i

function stripHtml(s: string): string {
  return s.replace(/<[^>]*>/g, ' ')
}

// Quill Delta shape: { ops: [{ insert: 'text' | {embed}, attributes? }, ...] }
function isQuillDelta(v: unknown): v is { ops: Array<{ insert?: unknown }> } {
  return !!v && typeof v === 'object' && Array.isArray((v as { ops?: unknown }).ops)
}

function deltaToText(delta: { ops: Array<{ insert?: unknown }> }): string {
  return delta.ops.map((op) => (typeof op.insert === 'string' ? op.insert : '')).join('')
}

/**
 * Render any field value to a single plain-text string for indexing.
 * Skips URLs, UUIDs, and structural keys; flattens HTML and Quill Delta; collapses whitespace.
 */
export function extractSearchableText(value: unknown): string {
  const parts: string[] = []

  const walk = (v: unknown, depth: number): void => {
    if (v == null || depth > MAX_DEPTH) return

    if (typeof v === 'string') {
      const s = v.trim()
      if (!s || s.startsWith('http://') || s.startsWith('https://') || UUID_RE.test(s)) return
      parts.push(stripHtml(s))
      return
    }

    if (Array.isArray(v)) {
      for (const item of v) walk(item, depth + 1)
      return
    }

    if (typeof v === 'object') {
      if (isQuillDelta(v)) {
        const t = stripHtml(deltaToText(v)).trim()
        if (t) parts.push(t)
        return
      }
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (!SKIP_KEYS.has(k.toLowerCase())) walk(val, depth + 1)
      }
    }
    // numbers / booleans are intentionally not indexed as full text
  }

  walk(value, 0)
  return parts.join(' ').replace(/\s+/g, ' ').trim()
}
