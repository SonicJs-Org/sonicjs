/**
 * SonicJS's `SecondaryStorage` for Better Auth, backed by Cloudflare KV (`CACHE_KV`).
 *
 * WHY OURS RATHER THAN `better-auth-cloudflare`'s `createKVStorage`:
 *
 * Better Auth 1.7 made `getAndDelete` and `increment` REQUIRED members of the interface (both
 * were optional in 1.6). The shim's storage (0.4.x) implements only `get`, `set` and `delete`,
 * and is typed that way. It would work here, because two settings in `auth/config.ts`
 * (described below) keep Better Auth off both members. This object is used instead so that
 * those two settings cannot quietly regress:
 *   - it is typed as Better Auth's full `SecondaryStorage`, so the day Better Auth adds another
 *     required member, `tsc --noEmit` fails on this file;
 *   - if either setting is ever removed, `getAndDelete` logs a warning and `increment` throws an
 *     error naming the setting, instead of Better Auth's bare "is not a function".
 *
 * WHAT KV CAN AND CANNOT DO. KV offers no compare-and-swap, no conditional writes and no
 * atomic counters; concurrent writes to one key are last-write-wins, a key accepts at most one
 * write per second, and reads are eventually consistent across locations. Better Auth documents
 * both new members as atomic. KV cannot honour that, so neither can this file. The two
 * operations that need atomicity are therefore routed elsewhere in `auth/config.ts`:
 * verification values to D1 (`verification.storeInDatabase: true`) and rate-limit counters to
 * `rateLimit.storage`. Sessions live here, and Better Auth still writes each verification value
 * here too and reads it here first — but the single-use CONSUME (find + delete) runs against D1,
 * which is what makes a code or link redeemable once.
 */
import type { BetterAuthOptions } from 'better-auth'
import type { KVNamespace } from '@cloudflare/workers-types'

/** Better Auth's own interface, derived from the options type (no deep import of `@better-auth/core`). */
type SecondaryStorage = NonNullable<BetterAuthOptions['secondaryStorage']>

/** KV rejects an `expirationTtl` below 60 seconds. */
const KV_MIN_TTL_SECONDS = 60

/**
 * Build the secondary storage Better Auth uses for session caching — or `undefined` when there
 * is no KV binding, in which case Better Auth keeps sessions in D1 only.
 */
export function createSecondaryStorage(kv: KVNamespace | undefined): SecondaryStorage | undefined {
  if (!kv) return undefined

  // Per-instance: `createAuth` builds one per request, so this warns once per request that
  // reaches the path, and keeps mutable state out of the module (an isolate would otherwise
  // carry it between unrelated requests).
  let warnedNonAtomicConsume = false

  return {
    get: async (key) => kv.get(key),

    set: async (key, value, ttl) => {
      if (ttl === undefined) {
        await kv.put(key, value)
        return
      }
      // Clamp rather than fail: KV rejects a sub-60s TTL outright. A value that outlives its
      // window is still rejected on read, because Better Auth checks the `expiresAt` it stores
      // inside the payload.
      await kv.put(key, value, { expirationTtl: Math.max(ttl, KV_MIN_TTL_SECONDS) })
    },

    delete: async (key) => {
      await kv.delete(key)
    },

    /**
     * NOT atomic — KV has no primitive that makes it so. A concurrent reader can observe the
     * same value before the delete lands, so a single-use token could be consumed twice.
     *
     * Implemented rather than thrown because a future Better Auth may call it somewhere benign.
     * Today its one caller is the verification consume, which `verification.storeInDatabase:
     * true` keeps us off. The warning makes a regression of that setting visible in the logs.
     */
    getAndDelete: async (key) => {
      if (!warnedNonAtomicConsume) {
        warnedNonAtomicConsume = true
        console.warn(
          '[sonicjs/auth] SecondaryStorage.getAndDelete was called. Cloudflare KV cannot ' +
            'get-and-delete atomically, so a single-use value could be consumed twice under a ' +
            'race. Verification values are meant to use the D1 path — check that ' +
            'verification.storeInDatabase is still true in auth/config.ts.'
        )
      }
      const value = await kv.get(key)
      if (value !== null) await kv.delete(key)
      return value
    },

    /**
     * Throws by design. Its only caller is Better Auth's secondary-storage rate limiter, and a
     * rate limiter that silently under-counts fails open under exactly the load it exists for.
     * `auth/config.ts` sets `rateLimit.storage` explicitly so this is unreachable; if that ever
     * regresses, this fails loudly with an actionable message instead of Better Auth's own
     * "increment is not a function".
     */
    increment: async () => {
      throw new Error(
        '[sonicjs/auth] SecondaryStorage.increment is not implemented. Cloudflare KV has no ' +
          'atomic counter and caps writes at one per key per second, so a KV-backed rate ' +
          'limiter fails open. Set rateLimit.storage explicitly in auth/config.ts.'
      )
    },
  }
}
