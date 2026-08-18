import { escapeHtml } from '../../../../utils/sanitize'

/** The display kind + its visible-field shape. Both kinds iterate ONLY their own
 *  explicit fields — never `Object.keys(row)` — so nothing un-whitelisted renders. */
export type PublicDisplaySpec =
  | { kind: 'table'; columns: string[] }
  | { kind: 'cards'; titleField: string; fields: string[] }

export interface PublicViewDisplayData {
  /** The view name, shown as a small caption. */
  title: string
  rows: Record<string, unknown>[]
  meta:
    | { total: number; page: number; pages: number; hasNext: boolean; hasPrev: boolean }
    | { hasNext: boolean; nextCursor: string | null }
  display: PublicDisplaySpec
}

/** `created_at` → `Created At`. */
function humanize(key: string): string {
  return key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase())
}

// Self-contained CSS. There is NO compiled Tailwind asset in core (the admin
// layout uses the Tailwind play-CDN), and a public embed must not depend on one —
// so styles are inlined, mirroring public-forms.ts.
const STYLES = `
*{box-sizing:border-box}
body{margin:0;padding:16px;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#18181b;background:#fff;font-size:14px}
.caption{margin:0 0 12px;font-size:12px;font-weight:600;color:#71717a;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e4e4e7;vertical-align:top}
th{font-size:12px;font-weight:600;color:#52525b;background:#fafafa;position:sticky;top:0}
tr:hover td{background:#fafafa}
td.empty{color:#a1a1aa;text-align:center;padding:24px}
.pager{display:flex;align-items:center;justify-content:space-between;margin-top:12px;font-size:12px;color:#71717a}
.pager a{color:#0e7490;text-decoration:none;padding:4px 8px}
.pager a:hover{text-decoration:underline}
.pager .disabled{color:#d4d4d8;padding:4px 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.card{border:1px solid #e4e4e7;border-radius:8px;padding:12px 14px}
.card-title{font-weight:600;font-size:15px;margin-bottom:8px;color:#18181b}
.card-field{display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:2px 0}
.card-label{color:#71717a}
.card-value{color:#18181b;text-align:right;word-break:break-word}
.cards-empty{color:#a1a1aa;text-align:center;padding:24px}
@media (prefers-color-scheme:dark){
  body{color:#e4e4e7;background:#18181b}
  th,td{border-bottom-color:#27272a}
  th{color:#a1a1aa;background:#1f1f23}
  tr:hover td{background:#1f1f23}
  .card{border-color:#27272a}
  .card-title,.card-value{color:#e4e4e7}
}
`

/** Render the table body — iterates the explicit `columns` only. */
function renderTableBody(columns: string[], rows: Record<string, unknown>[]): string {
  const head = columns.map((c) => `<th>${escapeHtml(humanize(c))}</th>`).join('')
  const body = rows.length
    ? rows
        .map((row) => `<tr>${columns.map((c) => `<td>${escapeHtml(String(row[c] ?? ''))}</td>`).join('')}</tr>`)
        .join('')
    : `<tr><td class="empty" colspan="${columns.length || 1}">No results.</td></tr>`
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`
}

/** Render the card grid — each card reads ONLY titleField + fields (never row keys). */
function renderCards(titleField: string, fields: string[], rows: Record<string, unknown>[]): string {
  if (!rows.length) return `<p class="cards-empty">No results.</p>`
  const cards = rows
    .map((row) => {
      const heading = `<div class="card-title">${escapeHtml(String(row[titleField] ?? ''))}</div>`
      const body = fields
        .map(
          (f) =>
            `<div class="card-field"><span class="card-label">${escapeHtml(humanize(f))}</span><span class="card-value">${escapeHtml(String(row[f] ?? ''))}</span></div>`
        )
        .join('')
      return `<div class="card">${heading}${body}</div>`
    })
    .join('')
  return `<div class="cards">${cards}</div>`
}

export function renderPublicViewDisplay(data: PublicViewDisplayData): string {
  const content =
    data.display.kind === 'table'
      ? renderTableBody(data.display.columns, data.rows)
      : renderCards(data.display.titleField, data.display.fields, data.rows)

  // RELATIVE pager links — the cached HTML must be slug-independent so one cache
  // entry (keyed by the canonical path) safely serves both path- and token-access.
  // Offset mode: page numbers + Prev/Next. Cursor mode: forward-only Next carrying the
  // OPAQUE token (encodeURIComponent — the base64 alphabet has +/= which a query string
  // mangles, must-fix #4) + a "Newest" reset; no page/total/Prev (keyset has none).
  const meta = data.meta
  let pager: string
  if ('page' in meta) {
    const prev = meta.hasPrev
      ? `<a href="?page=${meta.page - 1}">&larr; Prev</a>`
      : `<span class="disabled">&larr; Prev</span>`
    const next = meta.hasNext
      ? `<a href="?page=${meta.page + 1}">Next &rarr;</a>`
      : `<span class="disabled">Next &rarr;</span>`
    pager = `<div class="pager"><span>Page ${meta.page} of ${meta.pages} &middot; ${meta.total} result${meta.total !== 1 ? 's' : ''}</span><span>${prev} ${next}</span></div>`
  } else {
    const next = meta.hasNext && meta.nextCursor
      ? `<a href="?cursor=${encodeURIComponent(meta.nextCursor)}">Next &rarr;</a>`
      : `<span class="disabled">Next &rarr;</span>`
    pager = `<div class="pager"><span></span><span><a href="?">&larr; Newest</a> ${next}</span></div>`
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(data.title)}</title>
<style>${STYLES}</style>
</head>
<body>
<p class="caption">${escapeHtml(data.title)}</p>
${content}
${pager}
</body>
</html>`
}
