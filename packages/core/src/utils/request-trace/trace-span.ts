import type { MiddlewareHandler } from 'hono'
import { getCurrentTrace } from './trace-context'

/**
 * Wrap a middleware so its queries are attributed to `name` and its timing
 * (total + self, excluding downstream `next()`) is recorded on the active trace.
 * Zero cost when no trace is active.
 */
export function traceSpan<H extends MiddlewareHandler<any, any, any>>(name: string, mw: H): H {
  const wrapped: MiddlewareHandler = async (c, next) => {
    const trace = getCurrentTrace()
    if (!trace) return mw(c, next)

    const start = trace.now()
    let downstream = 0
    trace.spanStack.push(name)
    const wrappedNext = async () => {
      const s = trace.now()
      trace.spanStack.pop()
      try {
        return await next()
      } finally {
        downstream += trace.now() - s
        trace.spanStack.push(name)
      }
    }
    try {
      return await mw(c, wrappedNext)
    } finally {
      trace.spanStack.pop()
      const total = trace.now() - start
      if (!trace.closed) {
        trace.spans.push({ name, startMs: start, durationMs: total, selfMs: Math.max(0, total - downstream) })
      }
    }
  }
  return wrapped as H
}
