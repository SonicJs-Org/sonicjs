/**
 * Helpers for promises that are cached in a module global and therefore shared across requests.
 *
 * On Cloudflare a module global outlives the request that filled it, but the request's *work*
 * does not: pending I/O is cancelled the moment its client disconnects. A promise created in one
 * request's execution context and stored for everyone else to await can therefore be left
 * permanently pending — not slow, never — and every later request on that isolate signs up for
 * the same dead promise. One client that gives up wedges the isolate for every client after it,
 * which reads from the outside as a request that is accepted and never answered.
 *
 * So no shared promise is ever awaited unbounded. `settlesWithin` is the bound.
 */

/**
 * Resolve to true if `p` settles within `ms`, false if the clock wins.
 *
 * The timer is always cleared: a pending `setTimeout` holds the Worker's I/O context open past
 * the response, and callers put this on hot paths.
 */
export function settlesWithin(p: Promise<unknown>, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    p.then(
      () => true,
      () => true
    ),
    new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), ms)
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer)
  })
}
