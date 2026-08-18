/**
 * Lexical FTS5 query engine over `documents_fts` (migration 0003).
 *
 * Ported from infowall's `fts5.service.ts` search path, re-pointed from `content_fts`/`content_id`/
 * `collection_id` to `documents_fts`/`document_id`/`type_id`. BM25 ranking with field boosts +
 * `snippet`/`highlight`, Unicode-safe query sanitizing.
 *
 * Visibility/tenancy is native — no JOIN to `documents`. The write-time projection
 * (DocumentProjection) deindexes soft-deleted / `visible=0` rows, so the index only holds live,
 * visible rows; the public filter is just `is_published = 1 AND tenant_id = ?` (Lane's LA2).
 *
 * bm25() takes one weight per column. `documents_fts` has 10 columns (title/slug/body indexed at
 * 0/1/2, the rest UNINDEXED), so the call passes exactly 10 weights — changing the column count
 * breaks the arity (the v1 bug).
 */
import type { D1Database } from '@cloudflare/workers-types'
import { sanitizeFTS5Query } from './fts5-sanitize'
import { escapeHtml } from '../../../../utils/sanitize'

// Hard cap on rows a single search may return, regardless of caller-supplied limit — the public
// /api/search endpoint is unauthenticated, so an unbounded limit is a cheap DoS lever.
const MAX_LIMIT = 100

// Private-use sentinels handed to FTS5 highlight()/snippet() as the match delimiters. FTS5 inserts
// them into the RAW (unescaped) source text, so we escapeHtml the whole result first and only THEN
// swap the sentinels for real <mark> tags — otherwise attacker HTML in a title/body (e.g.
// `<img onerror=…>`) would reach the admin search modal's innerHTML unescaped (R8 / stored XSS).
const HL_OPEN = String.fromCharCode(0xe000)
const HL_CLOSE = String.fromCharCode(0xe001)

export interface FtsEngineOptions {
  titleBoost?: number // default 5
  slugBoost?: number // default 2
  bodyBoost?: number // default 1
  snippetLength?: number // tokens, default 15
  highlightTag?: string // default 'mark'
}

export interface FtsSearchParams {
  query: string
  tenantId: string
  /** Restrict to these document type ids (e.g. searchable content types). Empty/omitted = all types. */
  typeIds?: string[]
  /** Public search filters is_published=1 (default true). */
  publishedOnly?: boolean
  limit?: number
  offset?: number
}

export interface FtsHit {
  documentId: string
  typeId: string
  title: string // highlighted (<mark>…</mark>)
  slug: string
  status: string
  snippet: string // body snippet, highlighted
  score: number // bm25 magnitude (higher = better)
  createdAt: number
  updatedAt: number
}

export interface FtsSearchResult {
  hits: FtsHit[]
  total: number
}

interface FtsRow {
  document_id: string
  type_id: string
  status: string
  slug: string
  created_at: number
  updated_at: number
  score: number
  body_snippet: string
  title_highlight: string
}

export class Fts5Engine {
  private readonly titleBoost: number
  private readonly slugBoost: number
  private readonly bodyBoost: number
  private readonly snippetLength: number
  private readonly tag: string

  constructor(private db: D1Database, opts: FtsEngineOptions = {}) {
    // Coerce to finite numbers — these are interpolated as SQL literals, so they must never be
    // attacker-controlled strings. They come from trusted settings, but Number() is belt-and-suspenders.
    this.titleBoost = Number(opts.titleBoost ?? 5) || 5
    this.slugBoost = Number(opts.slugBoost ?? 2) || 2
    this.bodyBoost = Number(opts.bodyBoost ?? 1) || 1
    this.snippetLength = Math.max(1, Math.floor(Number(opts.snippetLength ?? 15) || 15))
    this.tag = /^[a-zA-Z][a-zA-Z0-9]*$/.test(opts.highlightTag ?? '') ? (opts.highlightTag as string) : 'mark'
  }

  async search(params: FtsSearchParams): Promise<FtsSearchResult> {
    const match = sanitizeFTS5Query(params.query)
    if (!match || match === '""') return { hits: [], total: 0 }

    const publishedOnly = params.publishedOnly !== false
    const conditions: string[] = ['documents_fts MATCH ?', 'fts.tenant_id = ?']
    const binds: unknown[] = [match, params.tenantId]
    if (publishedOnly) conditions.push('fts.is_published = 1')
    if (params.typeIds?.length) {
      conditions.push(`fts.type_id IN (${params.typeIds.map(() => '?').join(',')})`)
      binds.push(...params.typeIds)
    }
    const where = conditions.join(' AND ')

    const limit = params.limit && params.limit > 0 ? Math.min(params.limit, MAX_LIMIT) : 20
    const offset = params.offset && params.offset > 0 ? params.offset : 0

    // bm25 weights: title, slug, body, then 7 UNINDEXED columns at 0 → 10 total (10-column table).
    // highlight()/snippet() delimit matches with the private-use sentinels, NOT literal <mark> — the
    // source text is escaped below before the sentinels become real tags (R8; see HL_OPEN comment).
    const sql = `
      SELECT
        fts.document_id, fts.type_id, fts.status, fts.slug, fts.created_at, fts.updated_at,
        bm25(documents_fts, ${this.titleBoost}, ${this.slugBoost}, ${this.bodyBoost}, 0, 0, 0, 0, 0, 0, 0) AS score,
        snippet(documents_fts, 2, ?, ?, '...', ${this.snippetLength}) AS body_snippet,
        highlight(documents_fts, 0, ?, ?) AS title_highlight
      FROM documents_fts fts
      WHERE ${where}
      ORDER BY score
      LIMIT ? OFFSET ?
    `
    const { results } = await this.db
      .prepare(sql)
      .bind(HL_OPEN, HL_CLOSE, HL_OPEN, HL_CLOSE, ...binds, limit, offset)
      .all<FtsRow>()

    const countResult = await this.db
      .prepare(`SELECT COUNT(*) AS total FROM documents_fts fts WHERE ${where}`)
      .bind(...binds)
      .first<{ total: number }>()

    // Escape the raw (possibly attacker-authored) title/body, THEN turn the sentinels into <mark>
    // tags — so the only HTML that survives into the result is the highlight markup we control.
    const openTag = `<${this.tag}>`
    const closeTag = `</${this.tag}>`
    const renderHl = (s: string | null | undefined): string =>
      s ? escapeHtml(s).split(HL_OPEN).join(openTag).split(HL_CLOSE).join(closeTag) : ''

    const hits: FtsHit[] = (results ?? []).map((r) => ({
      documentId: r.document_id,
      typeId: r.type_id,
      title: renderHl(r.title_highlight),
      slug: r.slug,
      status: r.status,
      snippet: renderHl(r.body_snippet),
      score: Math.abs(Number(r.score)), // bm25 is negative (more negative = better); expose magnitude
      createdAt: Number(r.created_at),
      updatedAt: Number(r.updated_at),
    }))

    return { hits, total: countResult?.total ?? 0 }
  }
}
