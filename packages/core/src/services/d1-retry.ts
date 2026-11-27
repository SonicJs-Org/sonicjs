/**
 * Transient-D1 retry helper.
 *
 * Ported from infowall's `fts5.service.ts` (#871/#876). Document writes fold the FTS index
 * mutation into the SAME `db.batch([...])` as the row write, so the index can never silently
 * diverge from the document (atomic). What the batch is NOT protected against is a transient D1
 * error (connection reset, overload) failing the whole write under contention. This wraps the
 * batch with jittered exponential backoff.
 *
 * Blast radius: wrapping `DocumentsService`'s batches means ALL document writes — not just FTS —
 * gain transient-retry. That is an improvement, but call it out in review.
 */

export function isTransientD1Error(error: unknown): boolean {
  const msg = (error instanceof Error ? error.message : String(error)).toLowerCase()
  return (
    msg.includes('network connection lost') ||
    msg.includes('storage caused object to be reset') ||
    msg.includes('reset because its code was updated') ||
    msg.includes('please try again') ||
    msg.includes('overloaded') ||
    msg.includes('too many requests') ||
    // Additional CF D1 / Workers connection errors — these definitively indicate the
    // write did NOT commit (connection severed before the response), so retrying is safe.
    msg.includes('connection reset') ||
    msg.includes('connection refused') ||
    msg.includes('remotetransactionfailed') ||
    msg.includes('service temporarily unavailable') ||
    // SQLite busy errors that occur under concurrent D1 load
    msg.includes('database is locked') ||
    msg.includes('sqlite_busy') ||
    // CF D1 error code prefix — typically wraps retryable infrastructure faults
    (msg.includes('d1_error') && !msg.includes('no such table') && !msg.includes('no such column'))
  )
}

/**
 * Retry `fn` on transient D1 errors with jittered exponential backoff.
 * Jitter matters: without it, N writers that collided once back off on the same schedule and
 * collide again in lockstep. Non-transient errors and the final attempt re-throw unchanged, so
 * callers' error contracts are intact.
 */
export async function retryTransientD1<T>(fn: () => Promise<T>, attempts = 6, baseDelayMs = 25): Promise<T> {
  let lastError: unknown
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error
      if (attempt === attempts - 1 || !isTransientD1Error(error)) throw error
      const backoff = baseDelayMs * 2 ** attempt + Math.random() * baseDelayMs
      await new Promise((resolve) => setTimeout(resolve, backoff))
    }
  }
  throw lastError
}
