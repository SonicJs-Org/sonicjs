import { type HttpClient } from '../http'
import { type RequestAuth } from '../config'
import {
  type ContentRecord,
  type ListResponse,
  type ItemResponse,
  type ListOptions,
} from '../types'

const enc = encodeURIComponent

function toListQuery(o: ListOptions): Record<string, unknown> {
  const q: Record<string, unknown> = {}
  if (o.limit !== undefined) q['limit'] = o.limit
  if (o.offset !== undefined) q['offset'] = o.offset
  if (o.status) q['status'] = o.status
  if (o.sort) q['sort'] = o.sort
  if (o.dir) q['dir'] = o.dir
  if (o.fields?.length) q['fields'] = o.fields
  if (o.include?.length) q['include'] = o.include
  if (o.where) q['where'] = o.where
  if (o.resolveVariables !== undefined) q['resolveVariables'] = o.resolveVariables
  return q
}

export class ContentResource {
  constructor(private http: HttpClient) {}

  list(o: ListOptions = {}, auth?: RequestAuth) {
    return this.http.request<ListResponse<ContentRecord>>('GET', '/api/content', {
      query: toListQuery(o),
      auth,
    })
  }

  get(
    id: string,
    o?: { fields?: string[]; resolveVariables?: boolean },
    auth?: RequestAuth,
  ) {
    const q: Record<string, unknown> = {}
    if (o?.fields?.length) q['fields'] = o.fields
    if (o?.resolveVariables !== undefined) q['resolveVariables'] = o.resolveVariables
    return this.http.request<ItemResponse<ContentRecord>>('GET', `/api/content/${enc(id)}`, {
      query: Object.keys(q).length ? q : undefined,
      auth,
    })
  }

  checkSlug(collectionId: string, slug: string, excludeId?: string) {
    const q: Record<string, unknown> = { collectionId, slug }
    if (excludeId) q['excludeId'] = excludeId
    return this.http.request<{ available: boolean; message?: string }>(
      'GET',
      '/api/content/check-slug',
      { query: q },
    )
  }

  create(
    input: {
      collectionId: string
      title: string
      slug?: string
      status?: 'draft' | 'published' | 'archived'
      data?: Record<string, unknown>
    },
    auth?: RequestAuth,
  ) {
    return this.http.request<ItemResponse<ContentRecord>>('POST', '/api/content', {
      body: input,
      auth,
    })
  }

  update(
    id: string,
    input: Partial<{
      title: string
      slug: string
      status: 'draft' | 'published' | 'archived'
      data: Record<string, unknown>
    }>,
    auth?: RequestAuth,
  ) {
    return this.http.request<ItemResponse<ContentRecord>>('PUT', `/api/content/${enc(id)}`, {
      body: input,
      auth,
    })
  }

  delete(id: string, auth?: RequestAuth) {
    return this.http.request<{ success: boolean }>('DELETE', `/api/content/${enc(id)}`, { auth })
  }
}
