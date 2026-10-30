export interface ApiKeysSettings {
  /** Hard cap on active keys a single user may hold. Create is rejected beyond this. */
  maxKeysPerUser: number
  /** Default lifetime in days applied when a key is created without an explicit expiry. 0 = never expires. */
  defaultExpiryDays: number
}

export const DEFAULT_SETTINGS: ApiKeysSettings = {
  maxKeysPerUser: 50,
  defaultExpiryDays: 0,
}
