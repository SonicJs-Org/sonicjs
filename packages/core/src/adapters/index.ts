// Database adapter — D1Database-compatible SQLite driver
export { createSqliteDriver } from './db/sqlite-driver'
export type { SqliteDriver, SqliteDriverOptions } from './db/sqlite-driver'

// Storage adapter — R2Bucket-compatible filesystem driver
export { createFilesystemDriver } from './storage/filesystem-driver'
export type {
  StorageDriver,
  PutOptions,
  R2HttpMetadata,
  R2StoredMeta,
  R2ObjectBody,
  R2ObjectInfo,
} from './storage/filesystem-driver'

// KV adapter — KVNamespace-compatible in-memory driver
export { createMemoryKVDriver } from './kv/memory-kv-driver'
export type {
  KVDriver,
  KVPutOptions,
  KVListOptions,
  KVListResult,
  KVGetWithMetadata,
  MemoryKVOptions,
} from './kv/memory-kv-driver'

// Queue adapter — Cloudflare Queue-compatible synchronous driver
export { createSyncQueueDriver } from './queue/sync-queue-driver'
export type {
  QueueDriver,
  QueueHandler,
  QueueMessage,
  MessageBatch,
  SendOptions,
} from './queue/sync-queue-driver'

// Node / Bun server adapter — wires all local drivers into a SonicJS app
export { createNodeSonicApp } from './node-server'
export type { NodeAdapterOptions } from './node-server'
