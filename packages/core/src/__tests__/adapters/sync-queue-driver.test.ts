import { describe, it, expect, vi } from 'vitest'
import { createSyncQueueDriver } from '../../adapters/queue/sync-queue-driver'
import type { MessageBatch } from '../../adapters/queue/sync-queue-driver'

describe('sync queue driver — send', () => {
  it('calls handler synchronously with the message body', async () => {
    const received: unknown[] = []
    const queue = createSyncQueueDriver<string>(async (batch) => {
      for (const msg of batch.messages) {
        received.push(msg.body)
        msg.ack()
      }
    })

    await queue.send('hello')
    expect(received).toEqual(['hello'])
  })

  it('handler is called with a valid MessageBatch', async () => {
    let captured: MessageBatch<number> | null = null
    const queue = createSyncQueueDriver<number>(async (batch) => {
      captured = batch
      batch.ackAll()
    })

    await queue.send(42)
    expect(captured).not.toBeNull()
    expect(captured!.messages).toHaveLength(1)
    expect(captured!.messages[0].body).toBe(42)
    expect(typeof captured!.messages[0].id).toBe('string')
    expect(captured!.messages[0].timestamp).toBeInstanceOf(Date)
  })

  it('no-op when handler is not registered', async () => {
    const queue = createSyncQueueDriver<string>() // no handler
    await expect(queue.send('dropped')).resolves.toBeUndefined()
  })

  it('sendBatch dispatches all messages together', async () => {
    const bodies: number[] = []
    const queue = createSyncQueueDriver<number>(async (batch) => {
      for (const msg of batch.messages) {
        bodies.push(msg.body)
        msg.ack()
      }
    })

    await queue.sendBatch([{ body: 1 }, { body: 2 }, { body: 3 }])
    expect(bodies).toEqual([1, 2, 3])
  })

  it('handler errors are caught and logged, not thrown', async () => {
    const warnSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const queue = createSyncQueueDriver<string>(async () => {
      throw new Error('boom')
    })

    await expect(queue.send('x')).resolves.toBeUndefined()
    expect(warnSpy).toHaveBeenCalled()
    warnSpy.mockRestore()
  })
})

describe('sync queue driver — delayed send', () => {
  it('handler is called after delay (fire-and-forget)', async () => {
    vi.useFakeTimers()
    const received: string[] = []
    const queue = createSyncQueueDriver<string>(async (batch) => {
      for (const msg of batch.messages) received.push(msg.body)
    })

    const sendPromise = queue.send('delayed', { delaySeconds: 1 })
    // Handler not yet called before tick
    expect(received).toHaveLength(0)

    await sendPromise // resolves immediately (fire-and-forget)
    vi.advanceTimersByTime(1001)
    // Allow the micro-task from the setTimeout callback to settle
    await Promise.resolve()

    expect(received).toHaveLength(1)
    vi.useRealTimers()
  })
})
