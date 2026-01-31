# SonicJS Architecture

Comprehensive guide to the SonicJS system architecture, covering the Cloudflare Workers platform, request lifecycle, plugin system, caching, database layer, and data flow patterns.

## Table of Contents

1. [Overview](#overview)
2. [Cloudflare Workers Architecture](#cloudflare-workers-architecture)
3. [System Architecture](#system-architecture)
4. [Request Lifecycle](#request-lifecycle)
5. [Middleware Pipeline](#middleware-pipeline)
6. [Plugin System Architecture](#plugin-system-architecture)
7. [Three-Tiered Caching System](#three-tiered-caching-system)
8. [Database Schema and ORM Layer](#database-schema-and-orm-layer)
9. [Template Rendering System](#template-rendering-system)
10. [Data Flow Patterns](#data-flow-patterns)
11. [Integration Points](#integration-points)

## Overview

SonicJS is a modern, TypeScript-first headless CMS built specifically for Cloudflare's edge platform. It leverages Cloudflare Workers, D1 database, R2 storage, and KV cache to deliver exceptional performance at the edge.

### Key Architectural Principles

- **Edge-First**: Runs entirely on Cloudflare's global edge network
- **Zero Cold Starts**: V8 isolates provide instant startup
- **TypeScript-Native**: Fully typed for developer experience
- **Plugin-Driven**: Extensible through a robust plugin system
- **Performance-Optimized**: Three-tier caching for sub-millisecond response times

### Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Workers                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    Application Layer                   │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │ │
│  │  │  Hono.js │  │TypeScript│  │  Drizzle │             │ │
│  │  │ Framework│  │   5.x    │  │   ORM    │             │ │
│  │  └──────────┘  └──────────┘  └──────────┘             │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                   Storage Layer                         │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │ │
│  │  │    D1    │  │    R2    │  │    KV    │             │ │
│  │  │ Database │  │  Storage │  │  Cache   │             │ │
│  │  └──────────┘  └──────────┘  └──────────┘             │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Cloudflare Workers Architecture

### V8 Isolates Model

SonicJS runs in V8 isolates, providing:
- **Instant startup** (no cold starts)
- **Memory isolation** between requests
- **Automatic scaling** to handle traffic spikes
- **Global distribution** across 300+ locations

```typescript
// Worker entry point (/Users/lane/Dev/refs/sonicjs-ai/src/index.ts)
type Bindings = {
  DB: D1Database          // Cloudflare D1 database
  KV: KVNamespace         // Key-value cache
  MEDIA_BUCKET: R2Bucket  // Object storage
  ASSETS: Fetcher         // Static assets
  EMAIL_QUEUE?: Queue     // Email queue (optional)
  ENVIRONMENT?: string    // Environment flag
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()
```

### Resource Access Pattern

```typescript
// Accessing Cloudflare resources in routes
app.get('/api/data', async (c) => {
  // Access D1 database
  const db = c.env.DB
  const result = await db.prepare('SELECT * FROM content').all()

  // Access KV cache
  const kv = c.env.KV
  const cached = await kv.get('key', 'json')

  // Access R2 storage
  const bucket = c.env.MEDIA_BUCKET
  const file = await bucket.get('image.jpg')

  return c.json(result)
})
```

## System Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client Request                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge Network                           │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                   Middleware Pipeline                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │  │
│  │  │Bootstrap │→ │ Logging  │→ │   Auth   │→ │  Plugin  │      │  │
│  │  │Middleware│  │Middleware│  │Middleware│  │Middleware│      │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                             │                                        │
│                             ▼                                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      Route Handler                             │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │  │
│  │  │   API    │  │  Admin   │  │  Auth    │  │  Plugin  │      │  │
│  │  │  Routes  │  │  Routes  │  │  Routes  │  │  Routes  │      │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                             │                                        │
│                             ▼                                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Service Layer                               │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │  │
│  │  │  Cache   │  │ Content  │  │   Auth   │  │  Plugin  │      │  │
│  │  │ Service  │  │ Service  │  │ Service  │  │ Service  │      │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                             │                                        │
│                             ▼                                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Data Layer                                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                     │  │
│  │  │ Memory   │  │    KV    │  │    D1    │                     │  │
│  │  │  Cache   │  │  Cache   │  │ Database │                     │  │
│  │  └──────────┘  └──────────┘  └──────────┘                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

**1. Middleware Pipeline**
- Request preprocessing
- Authentication and authorization
- Security headers
- Performance monitoring
- Logging

**2. Route Handler**
- Request routing
- Parameter validation
- Response formatting
- Error handling

**3. Service Layer**
- Business logic
- Data transformation
- Cache management
- External integrations

**4. Data Layer**
- Data persistence
- Cache storage
- Query execution

## Request Lifecycle

### Complete Request Flow

```
┌───────────────────────────────────────────────────────────────────┐
│ 1. Request arrives at Cloudflare edge                             │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 2. Bootstrap Middleware                                           │
│    - Run database migrations                                      │
│    - Sync collection configurations                               │
│    - Bootstrap core plugins                                       │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 3. Logging Middleware                                             │
│    - Generate request ID                                          │
│    - Record start time                                            │
│    - Extract request metadata                                     │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 4. Security Middleware                                            │
│    - Check for suspicious patterns                                │
│    - Add security headers                                         │
│    - Log security events                                          │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 5. Authentication Middleware (if required)                        │
│    - Read session from Better Auth (session cookie)                │
│    - Set user context (userId, email, role)                       │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 6. Permission Middleware (if required)                            │
│    - Check user permissions                                       │
│    - Verify role access                                           │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 7. Plugin Middleware                                              │
│    - Execute plugin hooks                                         │
│    - Apply plugin middleware                                      │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 8. Route Handler                                                  │
│    - Execute route logic                                          │
│    - Check cache (Memory → KV → Database)                         │
│    - Process business logic                                       │
│    - Generate response                                            │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 9. Response Processing                                            │
│    - Add cache headers                                            │
│    - Add timing metadata                                          │
│    - Log response metrics                                         │
└───────────┬───────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│ 10. Return to client                                              │
└───────────────────────────────────────────────────────────────────┘
```

### Code Example: Request Lifecycle

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/index.ts

// 1. Bootstrap middleware
app.use('*', bootstrapMiddleware())

// 2. Logging middleware
app.use('*', loggingMiddleware())
app.use('*', securityLoggingMiddleware())
app.use('*', performanceLoggingMiddleware(1000))

// 3. Core middleware
app.use('*', logger())
app.use('*', cors())
app.use('*', securityHeaders())

// 4. Route-specific middleware
app.use('/admin/*', async (c, next) => {
  return await requireAuth()(c, next)
})
app.use('/admin/*', requireRole(['admin', 'editor']))

// 5. Routes
app.route('/api', apiRoutes)
app.route('/admin', adminRoutes)
app.route('/auth', authRoutes)
```

## Middleware Pipeline

### Middleware Execution Order

The middleware pipeline processes requests in a specific order to ensure proper functionality:

```
1. Bootstrap (system initialization) [Priority: 0]
   ↓
2. Logging (request tracking) [Priority: 1]
   ↓
3. Security (headers, validation) [Priority: 2]
   ↓
4. CORS (cross-origin) [Priority: 3]
   ↓
5. Authentication (session from Better Auth) [Priority: 10]
   ↓
6. Authorization (permission checks) [Priority: 11]
   ↓
7. Plugin Middleware (custom logic) [Priority: 50+]
   ↓
8. Route Handler [Priority: 100]
```

### Bootstrap Middleware

Ensures system initialization on first request:

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/middleware/bootstrap.ts

export function bootstrapMiddleware() {
  return async (c: Context<{ Bindings: Bindings }>, next: Next) => {
    if (bootstrapComplete) {
      return next()
    }

    // Skip for static assets
    const path = c.req.path
    if (path.startsWith('/images/') || path === '/health') {
      return next()
    }

    try {
      // 1. Run database migrations
      const migrationService = new MigrationService(c.env.DB)
      await migrationService.runPendingMigrations()

      // 2. Sync collection configurations
      await syncCollections(c.env.DB)

      // 3. Bootstrap core plugins
      const bootstrapService = new PluginBootstrapService(c.env.DB)
      if (await bootstrapService.isBootstrapNeeded()) {
        await bootstrapService.bootstrapCorePlugins()
        await bootstrapService.installDemoPlugins()
      }

      bootstrapComplete = true
    } catch (error) {
      console.error('[Bootstrap] Error:', error)
    }

    return next()
  }
}
```

### Authentication Middleware

Session-based authentication (Better Auth). A global middleware calls Better Auth `getSession` and sets `user` on context when a valid session cookie is present. `requireAuth()` checks for `c.get('user')`.

```typescript
// packages/core/src/middleware/auth.ts

export const requireAuth = () => {
  return async (c: Context, next: Next) => {
    const user = c.get('user')  // Set by global session middleware from Better Auth

    if (!user) {
      return c.json({ error: 'Authentication required' }, 401)
    }

    return await next()
  }
}
```

### Permission Middleware

Role-based access control:

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/middleware/permissions.ts

export function requirePermission(permission: string) {
  return async (c: Context, next: Next) => {
    const user = c.get('user')
    if (!user) {
      return c.json({ error: 'Authentication required' }, 401)
    }

    const db = c.env.DB
    const hasPermission = await PermissionManager.hasPermission(
      db,
      user.userId,
      permission
    )

    if (!hasPermission) {
      return c.json({ error: `Permission denied: ${permission}` }, 403)
    }

    return await next()
  }
}
```

## Plugin System Architecture

### Plugin Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin Manager                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Registry  │  Hook System  │  Validator  │  Loader       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Core Plugins   │  │ System Plugins  │  │  User Plugins   │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │   Auth    │  │  │  │  Workflow │  │  │  │  Custom   │  │
│  │   Media   │  │  │  │    FAQ    │  │  │  │  Plugins  │  │
│  │   Cache   │  │  │  │  Database │  │  │  │           │  │
│  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┴────────────────────┘
                              │
                              ▼
         ┌────────────────────────────────────────┐
         │        Plugin Extension Points         │
         │  ┌──────┐  ┌──────┐  ┌──────┐         │
         │  │Routes│  │Hooks │  │Models│         │
         │  ┌──────┐  ┌──────┐  ┌──────┐         │
         │  │Middle│  │Servic│  │Assets│         │
         │  │ware  │  │es    │  │      │         │
         │  └──────┘  └──────┘  └──────┘         │
         └────────────────────────────────────────┘
```

### Plugin Components

**1. Plugin Registry**
- Registers and manages plugins
- Tracks plugin status
- Handles dependencies
- Manages activation/deactivation

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/plugins/core/plugin-registry.ts

export class PluginRegistryImpl implements PluginRegistry {
  private plugins: Map<string, Plugin> = new Map()
  private statuses: Map<string, PluginStatus> = new Map()
  private configs: Map<string, PluginConfig> = new Map()

  async register(plugin: Plugin): Promise<void> {
    const validation = this.validator.validate(plugin)
    if (!validation.valid) {
      throw new Error(`Invalid plugin: ${validation.errors.join(', ')}`)
    }

    this.plugins.set(plugin.name, plugin)
    this.statuses.set(plugin.name, {
      name: plugin.name,
      version: plugin.version,
      active: false,
      installed: true,
      hasErrors: false
    })
  }
}
```

**2. Hook System**
- Event-driven architecture
- Priority-based execution
- Scoped hooks per plugin

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/plugins/core/hook-system.ts

export class HookSystemImpl implements HookSystem {
  private hooks: Map<string, PluginHook[]> = new Map()

  register(hookName: string, handler: HookHandler, priority: number = 10): void {
    if (!this.hooks.has(hookName)) {
      this.hooks.set(hookName, [])
    }

    const hooks = this.hooks.get(hookName)!
    const hook: PluginHook = { name: hookName, handler, priority }

    // Insert in priority order
    const insertIndex = hooks.findIndex(h => h.priority! > priority)
    if (insertIndex === -1) {
      hooks.push(hook)
    } else {
      hooks.splice(insertIndex, 0, hook)
    }
  }

  async execute(hookName: string, data: any, context?: any): Promise<any> {
    const hooks = this.hooks.get(hookName)
    if (!hooks || hooks.length === 0) {
      return data
    }

    let result = data
    for (const hook of hooks) {
      result = await hook.handler(result, context)
    }
    return result
  }
}
```

**3. Plugin Manager**
- Orchestrates plugin lifecycle
- Manages plugin context
- Handles installation/uninstallation

## Three-Tiered Caching System

### Cache Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Request for Data                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Memory Cache (L1)   │  ~1ms latency
         │   - In-process        │  - 50MB per worker
         │   - LRU eviction      │  - Fastest access
         └───────────┬───────────┘
                     │ Cache Miss
                     ▼
         ┌───────────────────────┐
         │    KV Cache (L2)      │  ~10-50ms latency
         │   - Global edge       │  - Unlimited size
         │   - Distributed       │  - Global CDN
         └───────────┬───────────┘
                     │ Cache Miss
                     ▼
         ┌───────────────────────┐
         │  Database (Source)    │  ~100-200ms latency
         │   - D1 SQLite         │  - Source of truth
         │   - Persistent        │  - Full data
         └───────────────────────┘
```

### Cache Service Implementation

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/plugins/cache/services/cache.ts

export class CacheService {
  async get<T>(key: string): Promise<T | null> {
    this.stats.totalRequests++

    // Try memory cache first (Tier 1)
    if (this.config.memoryEnabled) {
      const memoryValue = this.memoryCache.get<T>(key)
      if (memoryValue !== null) {
        this.stats.memoryHits++
        return memoryValue
      }
      this.stats.memoryMisses++
    }

    // Try KV cache (Tier 2)
    if (this.config.kvEnabled && this.kvNamespace) {
      const kvValue = await this.kvNamespace.get(key, 'json')
      if (kvValue !== null) {
        this.stats.kvHits++

        // Populate memory cache
        if (this.config.memoryEnabled) {
          this.memoryCache.set(key, kvValue as T, this.config.ttl)
        }

        return kvValue as T
      }
      this.stats.kvMisses++
    }

    return null
  }

  async set<T>(key: string, value: T): Promise<void> {
    // Store in memory (Tier 1)
    if (this.config.memoryEnabled) {
      this.memoryCache.set(key, value, this.config.ttl, this.config.version)
    }

    // Store in KV (Tier 2)
    if (this.config.kvEnabled && this.kvNamespace) {
      await this.kvNamespace.put(key, JSON.stringify(value), {
        expirationTtl: this.config.ttl
      })
    }
  }
}
```

### Cache Configurations

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/plugins/cache/services/cache-config.ts

export const CACHE_CONFIGS = {
  api: {
    ttl: 300,              // 5 minutes
    kvEnabled: true,
    memoryEnabled: true,
    namespace: 'api',
    invalidateOn: ['content:save', 'content:delete'],
    version: 'v1'
  },
  admin: {
    ttl: 60,               // 1 minute
    kvEnabled: false,
    memoryEnabled: true,
    namespace: 'admin',
    invalidateOn: ['content:save'],
    version: 'v1'
  },
  static: {
    ttl: 3600,             // 1 hour
    kvEnabled: true,
    memoryEnabled: true,
    namespace: 'static',
    invalidateOn: [],
    version: 'v1'
  }
}
```

## Database Schema and ORM Layer

### Drizzle ORM Integration

SonicJS uses Drizzle ORM for type-safe database access:

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/db/index.ts

import { drizzle } from 'drizzle-orm/d1'
import * as schema from './schema'

export function createDb(d1: D1Database) {
  return drizzle(d1, { schema })
}

// Usage in routes
const db = createDb(c.env.DB)
const users = await db.select().from(schema.users).all()
```

### Migration System

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/services/migrations.ts

export class MigrationService {
  async runPendingMigrations(): Promise<{
    success: boolean
    message: string
    applied: string[]
  }> {
    const status = await this.getMigrationStatus()
    const pendingMigrations = status.migrations.filter(m => !m.applied)

    const applied: string[] = []
    for (const migration of pendingMigrations) {
      try {
        await this.applyMigration(migration)
        await this.markMigrationApplied(
          migration.id,
          migration.name,
          migration.filename
        )
        applied.push(migration.id)
      } catch (error) {
        console.error(`Failed to apply migration ${migration.id}:`, error)
        break
      }
    }

    return {
      success: true,
      message: `Applied ${applied.length} migration(s)`,
      applied
    }
  }
}
```

## Template Rendering System

### Handlebars-like Template Engine

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/utils/template-renderer.ts

export class TemplateRenderer {
  private renderTemplate(template: string, data: TemplateData): string {
    let rendered = template

    // Handle each loops
    rendered = rendered.replace(
      /\{\{#each\s+([^}]+)\}\}([\s\S]*?)\{\{\/each\}\}/g,
      (match, arrayName, content) => {
        const array = this.getNestedValue(data, arrayName.trim())
        if (!Array.isArray(array)) return ''

        return array.map((item, index) => {
          const itemContext = {
            ...data,
            '.': item,
            ...(typeof item === 'object' ? item : {}),
            '@index': index,
            '@first': index === 0,
            '@last': index === array.length - 1
          }
          return this.renderTemplate(content, itemContext)
        }).join('')
      }
    )

    // Handle conditionals
    rendered = rendered.replace(
      /\{\{#if\s+([^}]+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (match, condition, content) => {
        const value = this.getNestedValue(data, condition.trim())
        const isTruthy = value === true ||
          (value && value !== 0 && value !== '')
        return isTruthy ? this.renderTemplate(content, data) : ''
      }
    )

    // Handle variables
    rendered = rendered.replace(/\{\{([^}#\/]+)\}\}/g, (match, variable) => {
      const value = this.getNestedValue(data, variable.trim())
      return value !== undefined && value !== null ? String(value) : ''
    })

    return rendered
  }
}
```

## Data Flow Patterns

### API Request Flow

```
Client Request
     │
     ▼
┌─────────────┐
│ API Route   │
└──────┬──────┘
       │
       ▼
┌─────────────┐      Cache Hit
│ Cache Check ├──────────────────► Return Cached Data
└──────┬──────┘
       │ Cache Miss
       ▼
┌─────────────┐
│  Database   │
│   Query     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Transform   │
│    Data     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Cache Set  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Return    │
│  Response   │
└─────────────┘
```

### Code Example: API Flow with Caching

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/routes/api.ts

apiRoutes.get('/content', async (c) => {
  const executionStart = Date.now()
  const db = c.env.DB
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100)

  // Check cache
  const cache = getCacheService(CACHE_CONFIGS.api!)
  const cacheKey = cache.generateKey('content-list', `limit:${limit}`)

  const cacheResult = await cache.getWithSource<any>(cacheKey)
  if (cacheResult.hit && cacheResult.data) {
    // Cache hit - add metadata
    c.header('X-Cache-Status', 'HIT')
    c.header('X-Cache-Source', cacheResult.source)
    if (cacheResult.ttl) {
      c.header('X-Cache-TTL', Math.floor(cacheResult.ttl).toString())
    }

    return c.json({
      ...cacheResult.data,
      meta: {
        ...cacheResult.data.meta,
        cache: {
          hit: true,
          source: cacheResult.source,
          ttl: cacheResult.ttl
        }
      }
    })
  }

  // Cache miss - fetch from database
  c.header('X-Cache-Status', 'MISS')
  const stmt = db.prepare(`
    SELECT * FROM content
    ORDER BY created_at DESC
    LIMIT ${limit}
  `)
  const { results } = await stmt.all()

  // Transform and cache
  const transformedResults = results.map((row: any) => ({
    id: row.id,
    title: row.title,
    slug: row.slug,
    status: row.status,
    collectionId: row.collection_id,
    data: row.data ? JSON.parse(row.data) : {},
    created_at: row.created_at,
    updated_at: row.updated_at
  }))

  const responseData = {
    data: transformedResults,
    meta: {
      count: results.length,
      timestamp: new Date().toISOString(),
      cache: { hit: false, source: 'database' }
    }
  }

  await cache.set(cacheKey, responseData)
  return c.json(responseData)
})
```

## Integration Points

### External Service Integration

```typescript
// Email service integration
const emailService = {
  async sendEmail(to: string, subject: string, body: string) {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${c.env.SENDGRID_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: c.env.DEFAULT_FROM_EMAIL },
        subject,
        content: [{ type: 'text/html', value: body }]
      })
    })

    return response.ok
  }
}
```

### Cloudflare Images Integration

```typescript
// From /Users/lane/Dev/refs/sonicjs-ai/src/media/images.ts

export async function uploadToCloudflareImages(
  file: File,
  accountId: string,
  apiToken: string
): Promise<{ success: boolean; id?: string; url?: string }> {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/images/v1`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiToken}`
      },
      body: formData
    }
  )

  if (!response.ok) {
    return { success: false }
  }

  const result = await response.json()
  return {
    success: true,
    id: result.result.id,
    url: result.result.variants[0]
  }
}
```

## Performance Considerations

### Edge Performance Metrics

- **First request (cold)**: 50-100ms
- **Cached request (memory)**: 1-5ms
- **Cached request (KV)**: 10-50ms
- **Database query**: 100-200ms

### Optimization Strategies

1. **Cache Aggressively**: Use three-tier caching
2. **Minimize Database Queries**: Batch operations when possible
3. **Session in Cookie**: Better Auth manages session; no app-level token cache
4. **Optimize Middleware Order**: Fast checks first
5. **Lazy Load Plugins**: Only load when needed

## See Also

- [Caching System](caching.md)
- [Routing and Middleware](routing-middleware.md)
- [Plugin Development Guide](plugins/plugin-development-guide.md)
- [Database Documentation](database.md)
- [Authentication](authentication.md)
