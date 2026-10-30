/**
 * Synchronous Queue driver — Cloudflare Queue-compatible adapter for self-hosted deployments.
 *
 * Instead of enqueuing messages to a remote queue, `send()` immediately invokes
 * the registered handler in-process. This means "queued" work (e.g. scheduled
 * email jobs) runs synchronously before the HTTP response is returned — acceptable
 * for low-volume self-host deployments.
 *
 * Usage:
 *   import { createSyncQueueDriver } from '@sonicjs-cms/core/adapters'
 *
 *   const emailQueue = createSyncQueueDriver(async (messages) => {
 *     // same body as handleEmailQueueMessage() from email-templates-plugin
 *     for (const msg of messages) {
 *       await processJob(msg.body)
 *       msg.ack()
 *     }
 *   })
 *   // Pass emailQueue as c.env.EMAIL_QUEUE
 */

// ---------------------------------------------------------------------------
// Minimal message shapes — locally defined, no runtime dep on workers-types.
// ---------------------------------------------------------------------------

export interface QueueMessage<T = unknown> {
  id: string
  body: T
  timestamp: Date
  ack(): void
  retry(): void
}

export interface MessageBatch<T = unknown> {
  readonly queue: string
  readonly messages: QueueMessage<T>[]
  ackAll(): void
  retryAll(): void
}

export interface SendOptions {
  delaySeconds?: number
  contentType?: string
}

export type QueueHandler<T> = (batch: MessageBatch<T>) => Promise<void>

export interface QueueDriver<T = unknown> {
  /**
   * Send a message. The registered handler is invoked synchronously (after
   * `delaySeconds` have elapsed when non-zero, via a non-blocking `setTimeout`).
   */
  send(body: T, options?: SendOptions): Promise<void>
  /**
   * Send many messages in a single batch.
   */
  sendBatch(messages: Array<{ body: T; options?: SendOptions }>): Promise<void>
}

// ---------------------------------------------------------------------------
// createSyncQueueDriver — public factory.
// ---------------------------------------------------------------------------

let _msgCounter = 0

function makeMessage<T>(body: T): QueueMessage<T> {
  const id = `sync-${++_msgCounter}`
  let acked = false
  return {
    id,
    body,
    timestamp: new Date(),
    ack() { acked = true },
    retry() { /* no-op — synchronous, no retry infrastructure */ },
  }
}

function makeBatch<T>(messages: QueueMessage<T>[], queueName: string): MessageBatch<T> {
  return {
    queue: queueName,
    messages,
    ackAll() { messages.forEach(m => m.ack()) },
    retryAll() { /* no-op */ },
  }
}

/**
 * Create a synchronous Queue driver.
 *
 * @param handler   Called for each message (or batch). When `handler` is omitted,
 *                  messages are logged and discarded — useful when EMAIL_QUEUE is
 *                  optional and no handler is wired yet.
 * @param queueName Optional queue name shown in MessageBatch (cosmetic).
 */
export function createSyncQueueDriver<T = unknown>(
  handler?: QueueHandler<T>,
  queueName = 'sync-queue',
): QueueDriver<T> {
  async function dispatch(messages: QueueMessage<T>[]): Promise<void> {
    if (!handler) {
      // Silently drop — EMAIL_QUEUE is optional; no handler registered.
      return
    }
    try {
      await handler(makeBatch(messages, queueName))
    } catch (err) {
      console.error(`[SyncQueue:${queueName}] Handler error:`, err)
    }
  }

  return {
    async send(body: T, options: SendOptions = {}): Promise<void> {
      const msg = makeMessage(body)
      const delay = (options.delaySeconds ?? 0) * 1000
      if (delay > 0) {
        // Fire-and-forget after delay — keeps HTTP response unblocked.
        setTimeout(() => dispatch([msg]), delay)
      } else {
        await dispatch([msg])
      }
    },

    async sendBatch(messages): Promise<void> {
      const msgs = messages.map(m => makeMessage(m.body))
      const delays = messages.map(m => (m.options?.delaySeconds ?? 0) * 1000)
      const maxDelay = Math.max(...delays, 0)
      if (maxDelay > 0) {
        setTimeout(() => dispatch(msgs), maxDelay)
      } else {
        await dispatch(msgs)
      }
    },
  }
}
