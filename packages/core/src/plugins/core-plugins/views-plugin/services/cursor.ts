/**
 * cursor.ts — opaque keyset-cursor token codec (Views cursor pagination, PR-3 / PR-3b).
 *
 * A cursor encodes the last row's ordered sort VALUE VECTOR (one value per non-id sort key) + its
 * unique `id` — a POSITION, not an offset. It is opaque + UTF-8-safe base64 (naive
 * `btoa(JSON.stringify)` throws on accented/emoji sort values). It is UNSIGNED, which is safe ONLY
 * because: the sort field(s) + direction(s) are re-derived server-side from the view config (never
 * read from the token), each decoded value is always a bound `?` param, and the forced
 * `status='published'` conjunct still gates rows — so a forged token can only REPOSITION within
 * already-published rows (it can't leak drafts, cross tenants, or inject SQL).
 *
 * PR-3b: `values` is a vector (multi-key). The codec is KEY-COUNT-AGNOSTIC — it does not know the
 * resolved key count; the `values.length === keys.length` drift check lives at the view-service
 * choke point, so a stale v1 token on a now-multi-key sort decodes then gets rejected there.
 */
export interface CursorPosition {
  readonly values: unknown[]
  readonly id: string
  /** Sort-key fingerprint ("field:dir" per key) baked in at encode time. Optional: tokens
   *  minted before it existed decode without it and fall back to the count-only drift check. */
  readonly keys?: string[]
}

const CURSOR_VERSION = 2

export function encodeCursor(pos: CursorPosition): string {
  const json = JSON.stringify({ v: CURSOR_VERSION, values: pos.values, id: pos.id, k: pos.keys })
  const bytes = new TextEncoder().encode(json)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** Decode a v1 (single `value`) OR v2 (`values` vector) token to a position, or `null` if malformed. */
export function decodeCursor(token: string): CursorPosition | null {
  try {
    const binary = atob(token)
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes))
    if (typeof parsed !== 'object' || parsed === null) return null
    const obj = parsed as { v?: unknown; value?: unknown; values?: unknown; id?: unknown; k?: unknown }
    if (typeof obj.id !== 'string') return null
    // v2: value vector (+ optional sort-key fingerprint; ignored unless every entry is a string).
    if (obj.v === 2 && Array.isArray(obj.values)) {
      const keys = Array.isArray(obj.k) && obj.k.every((e) => typeof e === 'string')
        ? (obj.k as string[])
        : undefined
      return { values: obj.values, id: obj.id, keys }
    }
    // v1 back-compat: single value → a one-element vector (the drift check rejects it if the
    // resolved sort is now multi-key).
    if (obj.v === 1 && 'value' in obj) return { values: [obj.value], id: obj.id }
    return null
  } catch {
    return null
  }
}
