export { createClient, type SonicClient } from './client'
export { SonicError } from './errors'
export { secondsToDate, msToDate } from './time'

export type {
  ClientOptions,
  RequestAuth,
} from './config'

export type {
  ContentRecord,
  DocumentRow,
  MediaAsset,
  AuthResult,
  CollectionInfo,
  ListResponse,
  ItemResponse,
  DocumentsPage,
  KeysetCursor,
  ContentListMeta,
  ListOptions,
  DocumentsListOptions,
} from './types'

export type { HealthStatus, SystemInfo, SystemStats } from './resources/system'
