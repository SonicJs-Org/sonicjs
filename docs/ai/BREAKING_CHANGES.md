# SonicJS Core Package - Breaking Changes Analysis

**Date**: 2025-01-17
**Purpose**: Identify and document all breaking changes from package extraction
**Status**: ✅ Complete

## Executive Summary

Extraction of SonicJS into `@sonicjs-cms/core` package introduces **4 categories** of breaking changes affecting **~46 user project files**. All changes have clear migration paths and can be partially automated.

**Breaking Change Categories**:
1. **Import Paths** (High Impact) - All user files affected
2. **Configuration API** (Medium Impact) - Main entry point changed
3. **Type Exports** (Low Impact) - Public API surface changed
4. **Migration System** (Low Impact) - Namespace separation

**Automation Potential**: 80% of changes can be automated via codemod scripts

## Breaking Change #1: Import Path Changes

### Impact Level: 🔴 HIGH
**Affected Files**: All user files (~46 files)
**Automation**: ✅ Fully automatable via codemod

### Current Import Pattern

```typescript
// Current: Relative imports from src/
import { requireAuth } from '../middleware/auth'
import { CollectionService } from '../services/collection-loader'
import type { CollectionConfig } from '../types/collection-config'
import { renderDashboard } from '../templates/pages/admin-dashboard.template'
```

### New Import Pattern

```typescript
// After: Package imports from @sonicjs-cms/core
import { requireAuth } from '@sonicjs-cms/core/middleware'
import { CollectionService } from '@sonicjs-cms/core/services'
import type { CollectionConfig } from '@sonicjs-cms/core'
import { renderDashboard } from '@sonicjs-cms/core/templates'
```

### Migration Examples

#### Example 1: Custom Route File

**Before** (`user-project/src/routes/custom-api.ts`):
```typescript
import { Hono } from 'hono'
import { requireAuth } from '../middleware/auth'
import { requireRole } from '../middleware/permissions'
import type { Bindings } from '../types'

export const customRoutes = new Hono<{ Bindings: Bindings }>()

customRoutes.get('/data', requireAuth(), async (c) => {
  // Custom logic
})
```

**After** (`user-project/src/routes/custom-api.ts`):
```typescript
import { Hono } from 'hono'
import { requireAuth, requireRole } from '@sonicjs-cms/core/middleware'
import type { Bindings } from '@sonicjs-cms/core'

export const customRoutes = new Hono<{ Bindings: Bindings }>()

customRoutes.get('/data', requireAuth(), async (c) => {
  // Custom logic - unchanged
})
```

**Change Summary**:
- ✅ Import from package instead of relative paths
- ✅ Logic remains identical
- ✅ No runtime behavior changes

#### Example 2: Custom Collection Config

**Before** (`user-project/src/collections/products.collection.ts`):
```typescript
import type { CollectionConfig } from '../types/collection-config'

export const productsCollection: CollectionConfig = {
  name: 'products',
  fields: {
    title: { type: 'text', required: true },
    price: { type: 'number', required: true }
  }
}
```

**After** (`user-project/src/collections/products.collection.ts`):
```typescript
import type { CollectionConfig } from '@sonicjs-cms/core'

export const productsCollection: CollectionConfig = {
  name: 'products',
  fields: {
    title: { type: 'text', required: true },
    price: { type: 'number', required: true }
  }
}
```

**Change Summary**:
- ✅ Import type from package
- ✅ Collection definition unchanged
- ✅ No schema changes

#### Example 3: Custom Plugin

**Before** (`user-project/src/plugins/my-plugin/index.ts`):
```typescript
import type { Plugin } from '../../plugins/types'
import { HookSystem } from '../../plugins/core/hook-system'

export class MyCustomPlugin implements Plugin {
  name = 'my-custom-plugin'
  version = '1.0.0'

  async onActivate() {
    // Plugin logic
  }
}
```

**After** (`user-project/src/plugins/my-plugin/index.ts`):
```typescript
import type { Plugin, HookSystem } from '@sonicjs-cms/core/plugins'

export class MyCustomPlugin implements Plugin {
  name = 'my-custom-plugin'
  version = '1.0.0'

  async onActivate() {
    // Plugin logic - unchanged
  }
}
```

### Automated Migration Script

```javascript
// scripts/migrate-imports.mjs
import { readFileSync, writeFileSync } from 'fs'
import { globSync } from 'glob'

const importMap = {
  '../middleware/auth': '@sonicjs-cms/core/middleware',
  '../middleware/permissions': '@sonicjs-cms/core/middleware',
  '../middleware/bootstrap': '@sonicjs-cms/core/middleware',
  '../services/collection-loader': '@sonicjs-cms/core/services',
  '../services/plugin-service': '@sonicjs-cms/core/services',
  '../services/migrations': '@sonicjs-cms/core/services',
  '../types/collection-config': '@sonicjs-cms/core',
  '../types/plugin': '@sonicjs-cms/core',
  '../types': '@sonicjs-cms/core',
  '../plugins/types': '@sonicjs-cms/core/plugins',
  '../plugins/core/hook-system': '@sonicjs-cms/core/plugins',
  '../utils/validators': '@sonicjs-cms/core/utils',
  '../utils/string-utils': '@sonicjs-cms/core/utils',
}

function migrateFile(filePath) {
  let content = readFileSync(filePath, 'utf-8')
  let changed = false

  for (const [oldPath, newPath] of Object.entries(importMap)) {
    const regex = new RegExp(`from ['"]${oldPath}['"]`, 'g')
    if (regex.test(content)) {
      content = content.replace(regex, `from '${newPath}'`)
      changed = true
    }
  }

  if (changed) {
    writeFileSync(filePath, content)
    console.log(`✓ Migrated: ${filePath}`)
  }
}

// Migrate all TypeScript files in user project
const files = globSync('src/**/*.ts', { ignore: ['node_modules/**', 'dist/**'] })
files.forEach(migrateFile)

console.log(`\n✓ Migration complete! Updated ${files.length} files.`)
```

**Usage**:
```bash
node scripts/migrate-imports.mjs
```

### Manual Review Required

After automated migration, review:
1. **Dynamic imports**: `await import('../services/...')`
2. **String paths**: Used in configuration files
3. **Template strings**: Embedded import paths
4. **Comments**: Documentation with old paths

## Breaking Change #2: Configuration API

### Impact Level: 🟡 MEDIUM
**Affected Files**: 1 file (`src/index.ts`)
**Automation**: ⚠️ Manual migration recommended

### Current Configuration

**Before** (`src/index.ts`):
```typescript
import { Hono } from 'hono'
import { apiRoutes } from './routes/api'
import { adminRoutes } from './routes/admin'
import { authRoutes } from './routes/auth'
import { requireAuth } from './middleware/auth'
import { bootstrapMiddleware } from './middleware/bootstrap'

type Bindings = {
  DB: D1Database
  KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  // ... more bindings
}

const app = new Hono<{ Bindings: Bindings }>()

// Manual setup
app.use('*', bootstrapMiddleware())
app.use('/admin/*', requireAuth())

app.route('/api', apiRoutes)
app.route('/admin', adminRoutes)
app.route('/auth', authRoutes)

export default app
```

### New Configuration

**After** (`src/index.ts`):
```typescript
import { createSonicJSApp } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// User custom routes (optional)
import { customRoutes } from './routes/custom-api'

const config: SonicJSConfig = {
  // Collections directory
  collections: {
    directory: './src/collections',
    autoSync: true
  },

  // Plugins directory
  plugins: {
    directory: './src/plugins',
    autoLoad: true
  },

  // Custom routes (optional)
  routes: [
    {
      path: '/custom',
      handler: customRoutes
    }
  ],

  // Custom middleware (optional)
  middleware: {
    beforeAuth: [
      // Custom middleware before authentication
    ],
    afterAuth: [
      // Custom middleware after authentication
    ]
  }
}

const app = createSonicJSApp(config)

export default app
```

### Migration Benefits

**Advantages of New API**:
1. ✅ **Simpler**: Less boilerplate code
2. ✅ **Declarative**: Configuration over imperative setup
3. ✅ **Type-safe**: Full TypeScript support
4. ✅ **Extensible**: Easy to add custom routes/middleware
5. ✅ **Maintainable**: Clear separation of concerns

### Migration Steps

1. **Install core package**:
   ```bash
   npm install @sonicjs-cms/core@1.0.0-alpha.1
   ```

2. **Create config object**:
   ```typescript
   const config: SonicJSConfig = { /* ... */ }
   ```

3. **Replace app instantiation**:
   ```typescript
   // Old: const app = new Hono()
   // New: const app = createSonicJSApp(config)
   ```

4. **Move custom routes**:
   ```typescript
   // Old: app.route('/custom', customRoutes)
   // New: Add to config.routes array
   ```

5. **Test thoroughly**:
   ```bash
   npm run dev
   npm run test
   ```

### Backward Compatibility Option

For gradual migration, support both patterns:

```typescript
// Option 1: New API (recommended)
import { createSonicJSApp } from '@sonicjs-cms/core'
const app = createSonicJSApp(config)

// Option 2: Keep existing pattern (compatibility)
import { Hono } from 'hono'
import { setupCoreRoutes, setupCoreMiddleware } from '@sonicjs-cms/core'

const app = new Hono()
setupCoreMiddleware(app)  // Adds bootstrap, auth, etc.
setupCoreRoutes(app)      // Adds API, admin routes
// Add custom routes
app.route('/custom', customRoutes)
```

## Breaking Change #3: Type Export Structure

### Impact Level: 🟢 LOW
**Affected Files**: ~20 files using types
**Automation**: ✅ Fully automatable

### Current Type Imports

**Before**:
```typescript
import type { CollectionConfig } from '../types/collection-config'
import type { PluginConfig } from '../types/plugin'
import type { User, Role } from '../types/auth'
import type { Bindings, Variables } from '../types/index'
```

### New Type Imports

**After**:
```typescript
// All types exported from main package
import type {
  CollectionConfig,
  PluginConfig,
  User,
  Role,
  Bindings,
  Variables
} from '@sonicjs-cms/core'

// Or from specific modules
import type { CollectionConfig } from '@sonicjs-cms/core/types'
import type { PluginConfig } from '@sonicjs-cms/core/plugins'
```

### Public Type Exports

```typescript
// @sonicjs-cms/core/index.ts
export type {
  // Collection types
  CollectionConfig,
  FieldConfig,
  FieldType,
  ValidationRule,

  // Plugin types
  PluginConfig,
  PluginManifest,
  Plugin,
  PluginHook,

  // Auth types
  User,
  Role,
  Permission,
  // JWTPayload removed; session user shape from Better Auth

  // Cloudflare types
  Bindings,
  Variables,

  // Content types
  Content,
  ContentVersion,
  WorkflowState,

  // Media types
  MediaFile,
  MediaFolder,
  ImageVariant
} from './types'
```

### Migration Script

```javascript
// Part of migrate-imports.mjs
const typeImportMap = {
  "from '../types/collection-config'": "from '@sonicjs-cms/core'",
  "from '../types/plugin'": "from '@sonicjs-cms/core'",
  "from '../types/auth'": "from '@sonicjs-cms/core'",
  "from '../types'": "from '@sonicjs-cms/core'"
}

// Apply transformations
```

## Breaking Change #4: Migration Namespace Separation

### Impact Level: 🟢 LOW
**Affected Files**: Migration files only
**Automation**: ⚠️ Manual migration required

### Current Migration System

**Before**: All migrations in `migrations/` directory with sequential numbering:
```
migrations/
├── 001_initial_schema.sql          # Core
├── 002_faq_plugin.sql              # Plugin
├── 003_stage5_enhancements.sql     # Core
├── 004_stage6_user_management.sql  # Core
└── 100_custom_table.sql            # User (if any)
```

### New Migration System

**After**: Separated by namespace:

**Core Package** (`@sonicjs-cms/core/migrations/`):
```
@sonicjs-cms/core/migrations/
├── 001_initial_schema.sql
├── 002_collections.sql
├── 003_user_management.sql
├── 004_workflow_system.sql
├── 005_plugin_system.sql
└── ...
```

**User Project** (`user-project/migrations/`):
```
user-project/migrations/
├── 100_custom_products_table.sql
├── 101_custom_orders_table.sql
└── 102_custom_analytics.sql
```

**Plugin Packages** (bundled with plugin):
```
@sonicjs/plugin-faq/migrations/
└── 001_faq_tables.sql

@sonicjs/plugin-workflow/migrations/
└── 001_workflow_tables.sql
```

### Migration Tracking Table

```sql
-- Enhanced migrations table with source tracking
CREATE TABLE IF NOT EXISTS migrations (
  id INTEGER PRIMARY KEY,
  filename TEXT NOT NULL,
  applied_at INTEGER NOT NULL,
  source TEXT NOT NULL,           -- 'core' | 'user' | 'plugin:{name}'
  core_version TEXT,              -- Core version when applied
  checksum TEXT                   -- File checksum for verification
);
```

### Migration Runner Changes

**Before**:
```typescript
// Old: Single migration runner
const migrations = await fs.readdir('migrations')
for (const file of migrations) {
  await runMigration(file)
}
```

**After**:
```typescript
// New: Multi-source migration runner
import { MigrationService } from '@sonicjs-cms/core'

const migrationService = new MigrationService(db)

// 1. Run core migrations first
await migrationService.runCoreMigrations()

// 2. Run plugin migrations
await migrationService.runPluginMigrations()

// 3. Run user migrations
await migrationService.runUserMigrations('./migrations')
```

### Migration Order Guarantee

```
1. Core migrations (001-099)     ← Always first
   ↓
2. Plugin migrations (001+)      ← After core, before user
   ↓
3. User migrations (100+)        ← Last, can depend on core + plugins
```

### Migration API

```typescript
// @sonicjs-cms/core/services/migrations
export class MigrationService {
  /**
   * Run migrations from core package
   */
  async runCoreMigrations(): Promise<MigrationResult>

  /**
   * Run migrations from installed plugins
   */
  async runPluginMigrations(): Promise<MigrationResult>

  /**
   * Run migrations from user project
   */
  async runUserMigrations(directory: string): Promise<MigrationResult>

  /**
   * Get migration status across all sources
   */
  async getStatus(): Promise<MigrationStatus>
}
```

## Summary of Breaking Changes

| # | Change | Impact | Affected Files | Automation | Priority |
|---|--------|--------|----------------|------------|----------|
| 1 | Import Paths | 🔴 High | ~46 files | ✅ Full | P0 |
| 2 | Configuration API | 🟡 Medium | 1 file | ⚠️ Manual | P0 |
| 3 | Type Exports | 🟢 Low | ~20 files | ✅ Full | P1 |
| 4 | Migration System | 🟢 Low | Migration files | ⚠️ Manual | P2 |

## Migration Timeline

### Phase 1: Preparation (Day 1)
- ✅ Read migration guide
- ✅ Backup project
- ✅ Review breaking changes
- ✅ Plan migration strategy

### Phase 2: Package Installation (Day 1)
```bash
npm install @sonicjs-cms/core@1.0.0-alpha.1
```

### Phase 3: Automated Fixes (Day 1)
```bash
# Run codemod for import paths
npx @sonicjs/migrate --from=current --to=1.0.0

# Verify changes
git diff

# Test
npm run test
```

### Phase 4: Manual Fixes (Day 2)
1. Update `src/index.ts` with new config API
2. Review and test custom routes
3. Update custom middleware
4. Test thoroughly

### Phase 5: Migration Runner (Day 2)
```bash
# Run database migrations
npm run db:migrate

# Verify all migrations applied
npm run db:status
```

### Phase 6: Testing (Day 2-3)
```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Manual testing
npm run dev
```

### Phase 7: Deployment (Day 3)
```bash
# Deploy to preview
npm run deploy:preview

# Test preview
# Deploy to production
npm run deploy:production
```

## Migration Tools

### 1. CLI Migration Tool

```bash
npx @sonicjs/migrate --from=current --to=1.0.0

# Interactive mode
npx @sonicjs/migrate --interactive

# Dry run (show changes without applying)
npx @sonicjs/migrate --dry-run

# Specific migration
npx @sonicjs/migrate --fix=import-paths
```

### 2. Validation Tool

```bash
# Validate project structure
npx @sonicjs/validate

# Output:
# ✓ Core package installed (@sonicjs-cms/core@1.0.0)
# ✓ TypeScript configured
# ✓ Collections directory exists
# ✓ Migrations directory exists
# ⚠ Found 3 files using old import paths
#   - src/routes/custom.ts:5
#   - src/plugins/my-plugin/index.ts:2
#   - src/collections/products.collection.ts:1
```

### 3. Compatibility Checker

```bash
# Check if your code is compatible with new version
npx @sonicjs/compat-check

# Output:
# Checking compatibility with @sonicjs-cms/core@1.0.0...
#
# ✓ Import paths: 43/46 files updated
# ⚠ Configuration: src/index.ts needs manual update
# ✓ Types: All type imports updated
# ✓ Migrations: Namespace separation applied
#
# Overall: 95% compatible
# Manual changes needed: 1 file
```

## Rollback Plan

If migration fails:

### 1. Quick Rollback (< 5 minutes)

```bash
# Restore package.json
git checkout HEAD package.json package-lock.json

# Reinstall dependencies
npm install

# Restore source files
git checkout HEAD src/

# Restart
npm run dev
```

### 2. Database Rollback

```bash
# Restore database from backup
wrangler d1 restore DB --backup=<backup-id>

# Or manually revert migrations
wrangler d1 execute DB --command="
  DELETE FROM migrations WHERE source = 'core' AND core_version = '1.0.0'
"
```

## Support Resources

### Documentation
- **Migration Guide**: `docs/migration/v1-migration.md`
- **API Reference**: `docs/api-reference.md`
- **Changelog**: `CHANGELOG.md`
- **Breaking Changes**: This document

### Community Support
- **GitHub Issues**: Report problems
- **Discord**: Real-time help
- **Stack Overflow**: Q&A with `sonicjs` tag

### Professional Support
- **Migration Assistance**: Help with complex migrations
- **Code Review**: Review migration changes
- **Training**: Team training on new API

## Success Criteria

Migration is successful when:
- ✅ All tests passing
- ✅ Application builds without errors
- ✅ Dev server starts successfully
- ✅ All features working as before
- ✅ Database migrations applied
- ✅ No console errors in production

## FAQs

### Q: Do I need to migrate immediately?
**A**: No. Current version (v0.x) will be maintained for 6 months. Migrate when ready.

### Q: Can I migrate gradually?
**A**: Yes. Use the backward compatibility option to migrate routes/features incrementally.

### Q: What if my custom code breaks?
**A**: Use the validation and compatibility tools to identify issues before deployment.

### Q: Will my data be lost?
**A**: No. Database schema and data remain unchanged. Always backup first.

### Q: Can I rollback after migration?
**A**: Yes. Follow the rollback plan. Keep backups of database and code.

### Q: How long does migration take?
**A**: 1-3 days depending on project size and customizations.

---

**Document Status**: ✅ Complete
**Date Completed**: 2025-01-17
**Breaking Changes Identified**: 4 categories
**Automation Coverage**: ~80%
**Ready for**: Phase 1 Task 4 (Monorepo Setup)
