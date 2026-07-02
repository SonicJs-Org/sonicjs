/**
 * In-memory KV driver — KVNamespace-compatible adapter for self-hosted deployments.
 *
 * Values survive the process lifetime. For cross-restart persistence, wire the
 * optional `persistPath` to a JSON file; entries are written on every put/delete.
 *
 * Usage:
 *   import { createMemoryKVDriver } from '@sonicjs-cms/core/adapters'
 *   const kv = createMemoryKVDriver()
 *   // Pass `kv` anywhere SonicJS expects a KVNamespace (CACHE_KV binding).
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'

// ---------------------------------------------------------------------------
// Stored entry — value + optional expiry in epoch ms.
// ---------------------------------------------------------------------------

interface KVEntry {
  value: string
  expiresAt?: number
}

// ---------------------------------------------------------------------------
// KVDriver — the public KVNamespace-compatible interface.
// ---------------------------------------------------------------------------

export interface KVPutOptions {
  expirationTtl?: number
  /** Absolute Unix timestamp (seconds) at which the key expires. */
  expiration?: number
  metadata?: unknown
}

export interface KVListOptions {
  prefix?: string
  limit?: number
  cursor?: string
}

export interface KVListResult {
  keys: Array<{ name: string; expiration?: number }>
  list_complete: boolean
  cursor?: string
}

export interface KVGetWithMetadata<T> {
  value: T | null
  metadata: unknown
}

export interface KVDriver {
  get(key: string): Promise<string | null>
  get(key: string, type: 'text'): Promise<string | null>
  get<T = unknown>(key: string, type: 'json'): Promise<T | null>
  get(key: string, type: 'arrayBuffer'): Promise<ArrayBuffer | null>
  put(key: string, value: string | ArrayBuffer | ReadableStream, options?: KVPutOptions): Promise<void>
  delete(key: string): Promise<void>
  list(options?: KVListOptions): Promise<KVListResult>
  getWithMetadata<T = unknown>(key: string, type: 'json'): Promise<KVGetWithMetadata<T>>
}

// ---------------------------------------------------------------------------
// createMemoryKVDriver — public factory.
// ---------------------------------------------------------------------------

export interface MemoryKVOptions {
  /**
   * Path to a JSON file used for persistence across restarts.
   * The file is read on startup and written on every put/delete.
   * Omit for a pure in-memory (ephemeral) store.
   */
  persistPath?: string
}

export function createMemoryKVDriver(options: MemoryKVOptions = {}): KVDriver {
  const { persistPath } = options
  const store = new Map<string, KVEntry>()

  // Load persisted entries from disk.
  if (persistPath && existsSync(persistPath)) {
    try {
      const raw = JSON.parse(readFileSync(persistPath, 'utf8')) as Record<string, KVEntry>
      const now = Date.now()
      for (const [k, entry] of Object.entries(raw)) {
        if (entry.expiresAt == null || entry.expiresAt > now) {
          store.set(k, entry)
        }
      }
    } catch {
      // Corrupt file — start empty.
    }
  }

  function persist(): void {
    if (!persistPath) return
    const obj: Record<string, KVEntry> = {}
    for (const [k, v] of store) obj[k] = v
    try {
      writeFileSync(persistPath, JSON.stringify(obj), 'utf8')
    } catch {
      // Non-fatal — best-effort persistence.
    }
  }

  function isExpired(entry: KVEntry): boolean {
    return entry.expiresAt != null && entry.expiresAt <= Date.now()
  }

  function rawGet(key: string): string | null {
    const entry = store.get(key)
    if (!entry) return null
    if (isExpired(entry)) {
      store.delete(key)
      return null
    }
    return entry.value
  }

  async function get(key: string, type?: string): Promise<unknown> {
    const raw = rawGet(key)
    if (raw == null) return null
    if (type === 'json') {
      try { return JSON.parse(raw) } catch { return null }
    }
    if (type === 'arrayBuffer') {
      const buf = Buffer.from(raw, 'base64')
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
    }
    return raw
  }

  async function put(key: string, value: string | ArrayBuffer | ReadableStream, options?: KVPutOptions): Promise<void> {
    let stored: string
    if (typeof value === 'string') {
      stored = value
    } else if (value instanceof ArrayBuffer) {
      stored = Buffer.from(value).toString('base64')
    } else {
      // ReadableStream — consume and base64-encode.
      const chunks: Uint8Array[] = []
      const reader = (value as ReadableStream).getReader()
      let done = false
      while (!done) {
        const result = await reader.read()
        done = result.done
        if (!done) chunks.push(result.value)
      }
      stored = Buffer.concat(chunks).toString('base64')
    }

    let expiresAt: number | undefined
    if (options?.expirationTtl != null) {
      expiresAt = Date.now() + options.expirationTtl * 1000
    } else if (options?.expiration != null) {
      expiresAt = options.expiration * 1000
    }

    store.set(key, { value: stored, expiresAt })
    persist()
  }

  async function del(key: string): Promise<void> {
    store.delete(key)
    persist()
  }

  async function list(options: KVListOptions = {}): Promise<KVListResult> {
    const { prefix = '', limit = 1000 } = options
    const now = Date.now()
    const keys: Array<{ name: string; expiration?: number }> = []

    for (const [k, entry] of store) {
      if (entry.expiresAt != null && entry.expiresAt <= now) {
        store.delete(k)
        continue
      }
      if (k.startsWith(prefix)) {
        keys.push({
          name: k,
          expiration: entry.expiresAt != null ? Math.floor(entry.expiresAt / 1000) : undefined,
        })
      }
    }

    const sliced = keys.slice(0, limit)
    return {
      keys: sliced,
      list_complete: sliced.length === keys.length,
    }
  }

  async function getWithMetadata<T>(key: string, type: string): Promise<KVGetWithMetadata<T>> {
    const value = (await get(key, type)) as T | null
    return { value, metadata: null }
  }

  return {
    get: get as KVDriver['get'],
    put,
    delete: del,
    list,
    getWithMetadata: getWithMetadata as KVDriver['getWithMetadata'],
  }
}
