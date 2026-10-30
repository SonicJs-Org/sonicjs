import { type HttpClient } from '../http'
import { type RequestAuth } from '../config'
import { type DocumentRow, type DocumentsPage, type DocumentsListOptions } from '../types'

const enc = encodeURIComponent

interface RawDocumentsResponse {
  data: DocumentRow[]
  pagination: {
    limit: number
    nextCursor: { cursor_updated_at: number; cursor_id: string } | null
  }
}

function toDocQuery(o: DocumentsListOptions): Record<string, unknown> {
  const q: Record<string, unknown> = { type: o.type }
  if (o.locale) q['locale'] = o.locale
  if (o.limit !== undefined) q['limit'] = o.limit
  if (o.cursor) q['cursor'] = o.cursor
  if (o.sort) q['sort'] = o.sort
  if (o.dir) q['dir'] = o.dir
  if (o.filter) q['filter'] = o.filter
  if (o.facet) q['facet'] = o.facet
  return q
}

export class DocumentsResource {
  constructor(private http: HttpClient) {}

  async list(o: DocumentsListOptions, auth?: RequestAuth): Promise<DocumentsPage<DocumentRow>> {
    const raw = await this.http.request<RawDocumentsResponse>('GET', '/api/documents', {
      query: toDocQuery(o),
      auth,
    })
    const nc = raw.pagination.nextCursor
    return {
      data: raw.data,
      nextCursor: nc ? { updatedAt: nc.cursor_updated_at, id: nc.cursor_id } : null,
    }
  }

  async *iterate(
    o: DocumentsListOptions,
    auth?: RequestAuth,
  ): AsyncGenerator<DocumentRow> {
    let cursor = o.cursor ?? null
    do {
      const page = await this.list({ ...o, cursor }, auth)
      for (const row of page.data) yield row
      cursor = page.nextCursor
    } while (cursor !== null)
  }

  getByRoot(rootId: string, auth?: RequestAuth) {
    return this.http.request<DocumentRow>('GET', `/api/documents/root/${enc(rootId)}`, { auth })
  }

  get(id: string, auth?: RequestAuth) {
    return this.http.request<DocumentRow>('GET', `/api/documents/${enc(id)}`, { auth })
  }
}
