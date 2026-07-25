import { type HttpClient } from '../http'
import { type RequestAuth } from '../config'
import {
  type ContentRecord,
  type CollectionInfo,
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

export class CollectionsResource {
  constructor(private http: HttpClient) {}

  list() {
    return this.http.request<ListResponse<CollectionInfo>>('GET', '/api/collections')
  }
}

export class ScopedCollection<TData = Record<string, unknown>> {
  constructor(
    private http: HttpClient,
    private name: string,
  ) {}

  list(o: ListOptions = {}, auth?: RequestAuth) {
    return this.http.request<ListResponse<ContentRecord & { data: TData }>>(
      'GET',
      `/api/${enc(this.name)}`,
      { query: toListQuery(o), auth },
    )
  }

  listWithHeaders(o: ListOptions = {}, auth?: RequestAuth) {
    return this.http.requestWithHeaders<ListResponse<ContentRecord & { data: TData }>>(
      'GET',
      `/api/${enc(this.name)}`,
      { query: toListQuery(o), auth },
    )
  }

  get(id: string, auth?: RequestAuth) {
    return this.http.request<ItemResponse<ContentRecord & { data: TData }>>(
      'GET',
      `/api/${enc(this.name)}/${enc(id)}`,
      { auth },
    )
  }

  create(
    input: { title?: string; slug?: string; status?: string; data?: TData },
    auth?: RequestAuth,
  ) {
    return this.http.request<ItemResponse<ContentRecord & { data: TData }>>(
      'POST',
      `/api/${enc(this.name)}`,
      { body: input, auth },
    )
  }

  update(
    id: string,
    input: Partial<{ title: string; slug: string; status: string; data: TData }>,
    auth?: RequestAuth,
  ) {
    return this.http.request<ItemResponse<ContentRecord & { data: TData }>>(
      'PUT',
      `/api/${enc(this.name)}/${enc(id)}`,
      { body: input, auth },
    )
  }

  delete(id: string, auth?: RequestAuth) {
    return this.http.request<{ success: boolean }>(
      'DELETE',
      `/api/${enc(this.name)}/${enc(id)}`,
      { auth },
    )
  }
}
