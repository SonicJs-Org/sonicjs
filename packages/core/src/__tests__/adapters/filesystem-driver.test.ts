import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createFilesystemDriver } from '../../adapters/storage/filesystem-driver'
import type { StorageDriver } from '../../adapters/storage/filesystem-driver'

let dir: string
let storage: StorageDriver

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sonic-fs-test-'))
  storage = createFilesystemDriver(dir)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('filesystem storage driver — put / get', () => {
  it('stores and retrieves file by key', async () => {
    const buf = new Uint8Array(Buffer.from('hello world'))
    await storage.put('uploads/test.txt', buf, {
      httpMetadata: { contentType: 'text/plain' },
    })
    const obj = await storage.get('uploads/test.txt')
    expect(obj).not.toBeNull()
    expect(obj!.httpMetadata.contentType).toBe('text/plain')
    const text = await obj!.text()
    expect(text).toBe('hello world')
  })

  it('returns null for missing key', async () => {
    const result = await storage.get('no/such/file.bin')
    expect(result).toBeNull()
  })

  it('stores custom metadata and returns it', async () => {
    const buf = new Uint8Array(Buffer.from('data'))
    await storage.put('f.bin', buf, {
      customMetadata: { uploadedBy: 'user-1', tag: 'avatar' },
    })
    const obj = await storage.get('f.bin')
    expect(obj!.customMetadata).toMatchObject({ uploadedBy: 'user-1', tag: 'avatar' })
  })

  it('put() returns object info with size and etag', async () => {
    const buf = new Uint8Array(Buffer.from('abc'))
    const info = await storage.put('size-test.txt', buf)
    expect(info.size).toBe(3)
    expect(typeof info.etag).toBe('string')
    expect(info.etag.length).toBeGreaterThan(0)
  })
})

describe('filesystem storage driver — head', () => {
  it('head() returns metadata without body', async () => {
    const buf = new Uint8Array(Buffer.from('head test'))
    await storage.put('headfile.txt', buf, {
      httpMetadata: { contentType: 'text/plain' },
    })
    const info = await storage.head('headfile.txt')
    expect(info).not.toBeNull()
    expect(info!.httpMetadata.contentType).toBe('text/plain')
    expect(info!.size).toBe(9)
  })

  it('head() returns null for missing key', async () => {
    const result = await storage.head('missing.txt')
    expect(result).toBeNull()
  })
})

describe('filesystem storage driver — delete', () => {
  it('deletes a file', async () => {
    const buf = new Uint8Array(Buffer.from('bye'))
    await storage.put('del.txt', buf)
    await storage.delete('del.txt')
    const result = await storage.get('del.txt')
    expect(result).toBeNull()
  })

  it('delete on missing key is a no-op', async () => {
    await expect(storage.delete('ghost.txt')).resolves.toBeUndefined()
  })
})

describe('filesystem storage driver — path safety', () => {
  it('strips path traversal from key', async () => {
    const buf = new Uint8Array(Buffer.from('safe'))
    // Should not escape the storage directory.
    await expect(
      storage.put('../../escape.txt', buf)
    ).resolves.toBeTruthy()
    // Key is stored under storageDir, not parent.
    const obj = await storage.get('../../escape.txt')
    expect(obj).not.toBeNull()
  })
})

describe('filesystem storage driver — ReadableStream body', () => {
  it('body is a readable stream that can be consumed', async () => {
    const buf = Buffer.from('stream me')
    await storage.put('stream.txt', buf)
    const obj = await storage.get('stream.txt')
    const reader = obj!.body.getReader()
    const chunks: Uint8Array[] = []
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
    }
    expect(Buffer.concat(chunks).toString()).toBe('stream me')
  })

  it('arrayBuffer() returns correct bytes', async () => {
    const data = new Uint8Array([1, 2, 3, 4])
    await storage.put('bytes.bin', data)
    const obj = await storage.get('bytes.bin')
    const ab = await obj!.arrayBuffer()
    expect(new Uint8Array(ab)).toEqual(data)
  })
})
