export type SecurityEventType =
  | 'login_success'
  | 'login_failure'
  | 'registration'
  | 'password_reset_request'
  | 'password_reset_complete'
  | 'account_lockout'
  | 'suspicious_activity'
  | 'logout'
  | 'permission_denied'
  // An admin cleared another account's second factor (two-factor-auth plugin's break-glass path).
  // Its own type rather than 'suspicious_activity' because it is a legitimate, expected action
  // that nonetheless removes a security control from an account other than the actor's own —
  // exactly the shape that needs to be findable after the fact.
  | 'two_factor_reset'

export type SecuritySeverity = 'info' | 'warning' | 'critical'

export interface SecurityEvent {
  id: string
  eventType: SecurityEventType
  severity: SecuritySeverity
  userId?: string | null
  email?: string | null
  ipAddress?: string | null
  userAgent?: string | null
  countryCode?: string | null
  requestPath?: string | null
  requestMethod?: string | null
  details?: Record<string, any> | null
  fingerprint?: string | null
  blocked: boolean
  createdAt: number
}

export interface SecurityEventInsert {
  eventType: SecurityEventType
  severity?: SecuritySeverity
  userId?: string
  email?: string
  ipAddress?: string
  userAgent?: string
  countryCode?: string
  requestPath?: string
  requestMethod?: string
  details?: Record<string, any>
  fingerprint?: string
  blocked?: boolean
}

export interface SecurityEventFilters {
  eventType?: SecurityEventType | SecurityEventType[]
  severity?: SecuritySeverity | SecuritySeverity[]
  email?: string
  ipAddress?: string
  search?: string
  startDate?: number
  endDate?: number
  blocked?: boolean
  page?: number
  limit?: number
  sortBy?: 'created_at' | 'event_type' | 'severity'
  sortOrder?: 'asc' | 'desc'
}

export interface SecurityStats {
  totalEvents: number
  failedLogins24h: number
  failedLoginsTrend: number // percentage change vs prior 24h
  activeLockouts: number
  flaggedIPs: number
  eventsByType: Record<string, number>
  eventsBySeverity: Record<string, number>
}

export interface TopIP {
  ipAddress: string
  countryCode: string | null
  failedAttempts: number
  lastSeen: number
  locked: boolean
}

export interface HourlyBucket {
  hour: string
  count: number
}

export interface SecurityAuditSettings {
  retention: {
    daysToKeep: number
    maxEvents: number
    autoPurge: boolean
  }
  bruteForce: {
    enabled: boolean
    maxFailedAttemptsPerIP: number
    maxFailedAttemptsPerEmail: number
    windowMinutes: number
    lockoutDurationMinutes: number
    alertThreshold: number
  }
  logging: {
    logSuccessfulLogins: boolean
    logLogouts: boolean
    logRegistrations: boolean
    logPasswordResets: boolean
    logPermissionDenied: boolean
  }
}

export const DEFAULT_SETTINGS: SecurityAuditSettings = {
  retention: {
    daysToKeep: 90,
    maxEvents: 100000,
    autoPurge: true
  },
  bruteForce: {
    enabled: true,
    maxFailedAttemptsPerIP: 10,
    maxFailedAttemptsPerEmail: 5,
    windowMinutes: 15,
    lockoutDurationMinutes: 30,
    alertThreshold: 20
  },
  logging: {
    logSuccessfulLogins: true,
    logLogouts: true,
    logRegistrations: true,
    logPasswordResets: true,
    logPermissionDenied: true
  }
}
