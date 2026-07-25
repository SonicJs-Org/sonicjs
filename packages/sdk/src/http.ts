import { type ClientOptions, type RequestAuth, resolveAuthHeaders } from './config'
import { SonicError } from './errors'
import { serializeQuery } from './query'

export interface HttpRequestInit {
  query?: Record<string, unknown>
  body?: unknown
  form?: FormData
  auth?: RequestAuth
}

function safeJson(text: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    return undefined
  }
}

export class HttpClient {
  constructor(private opts: ClientOptions) {}

  private get base(): string {
    return this.opts.url.replace(/\/$/, '')
  }

  private get fetchImpl(): typeof fetch {
    return (this.opts.fetch as typeof fetch) ?? globalThis.fetch.bind(globalThis)
  }

  private async _fetchRaw(
    method: string,
    path: string,
    init?: HttpRequestInit,
  ): Promise<Response> {
    const qStr = init?.query ? serializeQuery(init.query) : ''
    const url = this.base + path + (qStr ? '?' + qStr : '')
    const headers: Record<string, string> = {
      ...(this.opts.headers ?? {}),
      ...resolveAuthHeaders(this.opts, init?.auth),
    }
    let body: BodyInit | undefined
    if (init?.form) {
      body = init.form
      // Let fetch set the multipart Content-Type with boundary
    } else if (init?.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify(init.body)
    }
    try {
      return await this.fetchImpl(url, { method, headers, body })
    } catch (e) {
      throw new SonicError({
        status: 0,
        code: 'network',
        message: e instanceof Error ? e.message : String(e),
      })
    }
  }

  private throwIfError(res: Response, json: Record<string, unknown> | undefined): void {
    if (!res.ok) {
      throw new SonicError({
        status: res.status,
        code: 'http_error',
        message: (json?.['error'] as string | undefined) ?? res.statusText,
        details: json?.['details'] ?? (json !== undefined ? json : undefined),
      })
    }
  }

  async request<T>(method: string, path: string, init?: HttpRequestInit): Promise<T> {
    const res = await this._fetchRaw(method, path, init)
    const text = await res.text()
    const json = text ? safeJson(text) : undefined
    this.throwIfError(res, json)
    return json as T
  }

  async requestWithHeaders<T>(
    method: string,
    path: string,
    init?: HttpRequestInit,
  ): Promise<{ data: T; headers: Headers }> {
    const res = await this._fetchRaw(method, path, init)
    const text = await res.text()
    const json = text ? safeJson(text) : undefined
    this.throwIfError(res, json)
    return { data: json as T, headers: res.headers }
  }
}
