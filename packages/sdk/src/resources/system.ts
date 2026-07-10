import { type HttpClient } from '../http'

export interface HealthStatus {
  status: 'ok' | 'error'
  db?: string
  kv?: string
  r2?: string
  [k: string]: unknown
}

export interface SystemInfo {
  name?: string
  version?: string
  features?: string[]
  [k: string]: unknown
}

export interface SystemStats {
  content?: number
  media?: number
  collections?: number
  [k: string]: unknown
}

export class SystemResource {
  constructor(private http: HttpClient) {}

  health() {
    return this.http.request<HealthStatus>('GET', '/api/system/health')
  }

  info() {
    return this.http.request<SystemInfo>('GET', '/api/system/info')
  }

  stats() {
    return this.http.request<SystemStats>('GET', '/api/system/stats')
  }
}
