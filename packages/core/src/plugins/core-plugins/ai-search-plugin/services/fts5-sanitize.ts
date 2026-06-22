/**
 * Shared FTS5 MATCH-query sanitizer.
 *
 * Single source of truth for turning raw user input into an FTS5 MATCH expression.
 * Ported verbatim from infowall (#822); zero imports, self-contained.
 */

const STOP_WORDS = new Set([
  'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be',
  'to', 'of', 'in', 'on', 'at', 'by', 'or', 'and', 'not', 'for', 'it',
  'as', 'do', 'if', 'no', 'so', 'up', 'but', 'its', 'has', 'had', 'near',
])

/** A term contains a Latin-script letter (so English stop-words / min-length apply). */
const hasLatinLetter = (term: string): boolean => /\p{Script=Latin}/u.test(term)

/**
 * Sanitize user input into an FTS5 MATCH expression.
 *
 * Unicode-aware (#822): keeps letters/numbers of **any** script — CJK, Cyrillic,
 * Greek, Arabic, etc. — instead of the old `[a-zA-Z0-9]` ASCII whitelist that
 * reduced non-Latin queries to an empty string (zero lexical results). Diacritics
 * are folded (NFD decomposition + combining-mark removal) so query-side matches
 * the index tokenizer's `remove_diacritics 2` (migration 0003) — e.g. "café"
 * matches indexed "cafe" properly instead of by accidental `caf*` prefix.
 *
 * Stop-word + min-length filtering is applied to **Latin-script terms only**:
 * English stop-words and a >1-char rule are meaningless for CJK (where a single
 * character is a whole word) and would silently drop those terms.
 *
 * Returns `'""'` (an empty FTS5 phrase) when nothing usable remains, so callers
 * get a valid — if non-matching — MATCH expression rather than a syntax error.
 */
export function sanitizeFTS5Query(query: string): string {
  if (!query || typeof query !== 'string') {
    return '""'
  }

  // Step 1: fold Latin diacritics, then strip to letters/numbers/space of any script.
  const sanitized = query
    .normalize('NFD')                            // decompose: é → e + ´; ジ → シ + ゙
    .replace(/(\p{Script=Latin})\p{M}+/gu, '$1') // fold diacritics on LATIN bases ONLY — matches the
                                                 // index's remove_diacritics 2 (migration 0003) while
                                                 // leaving non-Latin marks intact (e.g. the Japanese
                                                 // dakuten — stripping it turns ジ "ji" into シ "shi")
    .normalize('NFC')                            // recompose survivors (シ + ゙ → ジ) so they pass the
                                                 // \p{L} keep-filter below as single letters
    .replace(/-/g, ' ')                          // hyphens → spaces (preserve word boundaries)
    .replace(/[^\p{L}\p{N}\s]/gu, '')            // keep letters/numbers of ANY script + whitespace;
                                                 // drops every FTS5 operator / quote / punctuation
    .replace(/\s+/g, ' ')                        // collapse whitespace
    .trim()
    .toLowerCase()

  // Step 2: split into terms; filter stop/short words for Latin scripts only.
  const terms = sanitized.split(/\s+/).filter((t) => {
    if (!t) return false
    return hasLatinLetter(t) ? t.length > 1 && !STOP_WORDS.has(t) : true
  })

  if (terms.length === 0) {
    return '""'
  }

  // Single term: prefix matching for autocomplete-like behavior.
  if (terms.length === 1) {
    return `${terms[0]}*`
  }

  // Multiple terms: unquoted with OR so porter stemming applies and any matching
  // term contributes to BM25 ranking (more matches rank higher).
  return terms.join(' OR ')
}
