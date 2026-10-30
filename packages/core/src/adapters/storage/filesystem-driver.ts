/**
 * Filesystem storage driver — R2Bucket-compatible adapter for self-hosted deployments.
 *
 * Files land at `{storageDir}/{key}` preserving path structure.
 * Metadata (httpMetadata + customMetadata) is stored alongside as `{key}.meta.json`.
 *
 * Usage:
 *   import { createFilesystemDriver } from '@sonicjs-cms/core/adapters'
 *   const bucket = createFilesystemDriver('./data/media')
 *   // Pass `bucket` anywhere SonicJS expects the MEDIA_BUCKET R2Bucket binding.
 */

import { createReadStream, existsSync, mkdirSync, rmSync, statSync, writeFileSync, readFileSync } from 'node:fs'
import { writeFile, rm, readFile, stat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { Readable } from 'node:stream'

// ---------------------------------------------------------------------------
// R2 metadata shapes (locally defined — no runtime dep on workers-types).
// ---------------------------------------------------------------------------

export interface R2HttpMetadata {
  contentType?: string
  contentDisposition?: string
  contentEncoding?: string
  contentLanguage?: string
  cacheControl?: string
  cacheExpiry?: Date
}

export interface R2StoredMeta {
  httpMetadata?: R2HttpMetadata
  customMetadata?: Record<string, string>
}

// ---------------------------------------------------------------------------
// R2ObjectBody — the shape callers destructure from get().
// ---------------------------------------------------------------------------

export interface R2ObjectBody {
  key: string
  size: number
  etag: string
  httpMetadata: R2HttpMetadata
  customMetadata: Record<string, string>
  /** Web-standard ReadableStream over the file contents. */
  body: ReadableStream
  /** Convenience: consume as ArrayBuffer. */
  arrayBuffer(): Promise<ArrayBuffer>
  /** Convenience: consume as text. */
  text(): Promise<string>
}

// ---------------------------------------------------------------------------
// R2Object — metadata-only (returned by head()).
// ---------------------------------------------------------------------------

export interface R2ObjectInfo {
  key: string
  size: number
  etag: string
  httpMetadata: R2HttpMetadata
  customMetadata: Record<string, string>
}

// ---------------------------------------------------------------------------
// StorageDriver — the public R2Bucket-compatible interface.
// ---------------------------------------------------------------------------

export interface PutOptions {
  httpMetadata?: R2HttpMetadata
  customMetadata?: Record<string, string>
}

export interface StorageDriver {
  put(key: string, value: ArrayBuffer | ReadableStream | Blob | ArrayBufferView | string, options?: PutOptions): Promise<R2ObjectInfo>
  get(key: string): Promise<R2ObjectBody | null>
  delete(key: string): Promise<void>
  head(key: string): Promise<R2ObjectInfo | null>
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function filePath(storageDir: string, key: string): string {
  // Prevent path traversal — strip any leading slashes / `..` segments.
  const safe = key.replace(/\.\./g, '').replace(/^\/+/, '')
  return join(storageDir, safe)
}

function metaPath(dataPath: string): string {
  return dataPath + '.meta.json'
}

function readMeta(dataPath: string): R2StoredMeta {
  const mp = metaPath(dataPath)
  if (!existsSync(mp)) return {}
  try {
    return JSON.parse(readFileSync(mp, 'utf8')) as R2StoredMeta
  } catch {
    return {}
  }
}

function writeMeta(dataPath: string, meta: R2StoredMeta): void {
  writeFileSync(metaPath(dataPath), JSON.stringify(meta), 'utf8')
}

function safeEtag(dataPath: string): string {
  try {
    const s = statSync(dataPath)
    return `${s.size}-${s.mtimeMs}`
  } catch {
    return 'unknown'
  }
}

function toNodeReadable(value: ReadableStream | ArrayBuffer | Blob | ArrayBufferView | string): Promise<Buffer> {
  if (typeof value === 'string') {
    return Promise.resolve(Buffer.from(value, 'utf8'))
  }
  if (value instanceof ArrayBuffer) {
    return Promise.resolve(Buffer.from(value))
  }
  if (ArrayBuffer.isView(value)) {
    return Promise.resolve(Buffer.from(value.buffer, value.byteOffset, value.byteLength))
  }
  if (value instanceof Blob) {
    return value.arrayBuffer().then(ab => Buffer.from(ab))
  }
  // ReadableStream (web standard)
  const stream = value as ReadableStream
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = []
    const reader = stream.getReader()
    function pump() {
      reader.read().then(({ done, value: chunk }) => {
        if (done) { resolve(Buffer.concat(chunks)); return }
        chunks.push(chunk)
        pump()
      }).catch(reject)
    }
    pump()
  })
}

function nodeStreamToWebReadable(path: string): ReadableStream {
  const nodeStream = createReadStream(path)
  return new ReadableStream({
    start(controller) {
      nodeStream.on('data', (chunk) => controller.enqueue(chunk instanceof Buffer ? chunk : Buffer.from(chunk)))
      nodeStream.on('end', () => controller.close())
      nodeStream.on('error', (err) => controller.error(err))
    },
    cancel() {
      nodeStream.destroy()
    },
  })
}

// ---------------------------------------------------------------------------
// createFilesystemDriver — public factory.
// ---------------------------------------------------------------------------

/**
 * Create an R2Bucket-compatible filesystem storage driver.
 *
 * ```ts
 * const bucket = createFilesystemDriver('./data/media')
 * // bucket satisfies R2Bucket — pass it as c.env.MEDIA_BUCKET
 * ```
 *
 * @param storageDir  Absolute or relative path to the root storage directory.
 *                    Created automatically if it doesn't exist.
 */
export function createFilesystemDriver(storageDir: string): StorageDriver {
  const root = resolve(storageDir)
  mkdirSync(root, { recursive: true })

  return {
    async put(key, value, options = {}): Promise<R2ObjectInfo> {
      const fp = filePath(root, key)
      mkdirSync(dirname(fp), { recursive: true })

      const buf = await toNodeReadable(value)
      await writeFile(fp, buf)

      const meta: R2StoredMeta = {
        httpMetadata: options.httpMetadata,
        customMetadata: options.customMetadata,
      }
      writeMeta(fp, meta)

      const s = statSync(fp)
      return {
        key,
        size: s.size,
        etag: `${s.size}-${s.mtimeMs}`,
        httpMetadata: options.httpMetadata ?? {},
        customMetadata: options.customMetadata ?? {},
      }
    },

    async get(key): Promise<R2ObjectBody | null> {
      const fp = filePath(root, key)
      if (!existsSync(fp)) return null

      const meta = readMeta(fp)
      const s = statSync(fp)

      return {
        key,
        size: s.size,
        etag: safeEtag(fp),
        httpMetadata: meta.httpMetadata ?? {},
        customMetadata: meta.customMetadata ?? {},
        body: nodeStreamToWebReadable(fp),
        async arrayBuffer() {
          const buf = await readFile(fp)
          return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer
        },
        async text() {
          return readFile(fp, 'utf8')
        },
      }
    },

    async delete(key): Promise<void> {
      const fp = filePath(root, key)
      if (existsSync(fp)) {
        await rm(fp, { force: true })
        const mp = metaPath(fp)
        if (existsSync(mp)) await rm(mp, { force: true })
      }
    },

    async head(key): Promise<R2ObjectInfo | null> {
      const fp = filePath(root, key)
      if (!existsSync(fp)) return null

      const meta = readMeta(fp)
      const s = statSync(fp)

      return {
        key,
        size: s.size,
        etag: safeEtag(fp),
        httpMetadata: meta.httpMetadata ?? {},
        customMetadata: meta.customMetadata ?? {},
      }
    },
  }
}
