// packages/core/src/views/response-formatter.ts

export interface ViewMeta {
  total: number
  page: number
  limit: number
  pages: number
  hasNext: boolean
  hasPrev: boolean
  view: string
  collection: string
}

export interface JsonEnvelope {
  data: Record<string, unknown>[]
  meta: ViewMeta
}

/** Cursor-mode meta — deliberately NO `total`/`page`/`pages` (keyset skips the COUNT). A SEPARATE
 *  type from `ViewMeta` so every offset consumer + test stays byte-identical (PR-3 must-fix #4). */
export interface ViewCursorMeta {
  limit: number
  hasNext: boolean
  nextCursor: string | null
  view: string
  collection: string
}

export interface CursorJsonEnvelope {
  data: Record<string, unknown>[]
  meta: ViewCursorMeta
}

export function formatCursorResponse(
  rows: Record<string, unknown>[],
  nextCursor: string | null,
  limit: number,
  viewName: string,
  collectionName: string
): CursorJsonEnvelope {
  return {
    data: rows,
    meta: {
      limit,
      hasNext: nextCursor !== null,
      nextCursor,
      view: viewName,
      collection: collectionName,
    },
  }
}

export function formatJsonResponse(
  rows: Record<string, unknown>[],
  total: number,
  page: number,
  limit: number,
  viewName: string,
  collectionName: string
): JsonEnvelope {
  const pages = Math.ceil(total / limit) || 1
  return {
    data: rows,
    meta: {
      total,
      page,
      limit,
      pages,
      hasNext: page < pages,
      hasPrev: page > 1,
      view: viewName,
      collection: collectionName,
    },
  }
}

export function formatCsvResponse(
  rows: Record<string, unknown>[]
): string {
  if (rows.length === 0) return ''

  const headers = Object.keys(rows[0]!)
  const lines: string[] = [headers.join(',')]

  for (const row of rows) {
    const values = headers.map(h => {
      const val = row[h]
      if (val === null || val === undefined) return ''
      let str = typeof val === 'object' ? JSON.stringify(val) : String(val)
      // Formula-injection neutralization: a USER-AUTHORED string starting with = + - @
      // (or tab/CR) executes as a formula when the public CSV is opened in Excel/Sheets.
      // Prefix with a literal apostrophe (the spreadsheet "treat as text" marker). Only
      // strings — a negative NUMBER is data, and JSON.stringify output starts with
      // {/[/" and can't lead with a formula trigger.
      if (typeof val === 'string' && /^[=+\-@\t\r]/.test(str)) {
        str = `'${str}`
      }
      // Escape CSV: wrap in quotes if it contains a comma, quote, or any line break
      // (\n OR a lone \r — a bare CR would otherwise split the row in some parsers).
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`
      }
      return str
    })
    lines.push(values.join(','))
  }

  return lines.join('\n')
}
