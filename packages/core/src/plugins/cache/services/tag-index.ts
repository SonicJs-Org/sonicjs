/**
 * Tag-based cache invalidation index.
 *
 * At cache-set time: for each rootId in the response, write a KV entry mapping
 *   rootId → cacheKey
 * so on content update/delete we can delete only the specific cache entries
 * that contain that document — instead of prefix-nuking the whole api:* namespace.
 *
 * KV key format: `_tag:{sha256(rootId)[0:32]}:{sha256(cacheKey)[0:32]}`
 * KV value:      full cacheKey string (so we can call cache.delete(cacheKey))
 */

interface KVLike {
  list(opts: { prefix: string }): Promise<{ keys: { name: string }[] }>
  get(key: string, type: 'text'): Promise<string | null>
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<void>
}

interface CtxLike {
  waitUntil(p: Promise<unknown>): void
}

const TAG_PREFIX = '_tag:'
const TAG_TTL = 2_592_000 // 30 days — same as catalog

let globalTagKv: KVLike | null = null

export function setGlobalTagKv(kv: KVLike): void {
  globalTagKv = kv
}

async function shortHash(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32)
}

/**
 * Register that `cacheKey` contains the given rootIds.
 * Called via waitUntil — never blocks the response.
 */
export function writeTagEntries(
  cacheKey: string,
  rootIds: string[],
  ctx: CtxLike,
): void {
  const kv = globalTagKv
  if (!kv || rootIds.length === 0) return
  ctx.waitUntil(
    (async () => {
      const ckHash = await shortHash(cacheKey)
      await Promise.all(
        rootIds.map(async (rootId) => {
          const rootHash = await shortHash(rootId)
          await kv.put(`${TAG_PREFIX}${rootHash}:${ckHash}`, cacheKey, { expirationTtl: TAG_TTL })
        }),
      )
    })(),
  )
}

/**
 * Invalidate all cache entries that contain `rootId`.
 * Looks up the tag index, calls cacheDelete for each matched key, then purges index entries.
 * Runs synchronously (awaited) — callers should not fire-and-forget.
 * Returns the number of cache keys invalidated.
 */
export async function invalidateByTag(
  rootId: string,
  cacheDelete: (key: string) => Promise<void>,
): Promise<number> {
  const kv = globalTagKv
  if (!kv) return 0
  const rootHash = await shortHash(rootId)
  const prefix = `${TAG_PREFIX}${rootHash}:`
  const { keys } = await kv.list({ prefix })
  if (keys.length === 0) return 0
  await Promise.all(
    keys.map(async (entry) => {
      const cacheKey = await kv.get(entry.name, 'text')
      if (cacheKey) await cacheDelete(cacheKey)
      await kv.delete(entry.name)
    }),
  )
  return keys.length
}
