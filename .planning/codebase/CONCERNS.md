# Codebase Concerns

**Analysis Date:** 2026-02-01

## Security Issues

**Hardcoded JWT Secret in Middleware:**
- Issue: Default JWT secret stored in source code instead of environment variable
- Files: `src/middleware/auth.ts` (line 14)
- Impact: All tokens use same predictable secret; enables token forgery and session hijacking
- Current state: Comment says "change in production" but no runtime validation enforces this
- Fix approach: Load JWT_SECRET from environment variables at runtime, fail fast if not set in production

**Insecure Password Hashing in Seed Data:**
- Issue: Seed data plugin uses plaintext 'password123' instead of proper bcrypt hashing
- Files: `src/plugins/core-plugins/seed-data-plugin/services/seed-data-service.ts` (line 104)
- Impact: Test/demo accounts use trivially guessable passwords; security risk if seed data runs in production
- Fix approach: Use proper bcrypt hashing for all passwords, remove plaintext hardcoding

**SQL Injection Risk - Dynamic Table Names:**
- Issue: Table name directly interpolated into DELETE query without validation
- Files: `src/routes/admin-settings.ts` (line 438)
- Vulnerable pattern: `` await db.prepare(`DELETE FROM ${tableName}`).run() ``
- Impact: Malicious table names could execute arbitrary SQL if input validation insufficient
- Current mitigation: User must be admin role, but insufficient for defense-in-depth
- Fix approach: Whitelist allowed table names, validate before interpolation

**XSS via innerHTML in AI Search Plugin:**
- Issue: User search query strings injected directly into innerHTML without sanitization
- Files: `src/plugins/core-plugins/ai-search-plugin/components/search-modal.ts` (lines 198-200, 285-294)
- Vulnerable patterns:
  - `suggestionsDiv.innerHTML = data.map(s => \`...\${s}\`)`
  - `resultsDiv.innerHTML = searchData.results.map(result => \`...\${result.title}\`)`
- Impact: Attackers can inject JavaScript through search suggestions, targeting admin users
- Current mitigation: Only admin users can access, but pattern is still unsafe
- Fix approach: Use textContent for user-generated data, sanitize HTML with DOMPurify before innerHTML

**innerHTML in Demo Login Plugin:**
- Issue: HTML content set via innerHTML without proper context escaping
- Files: `src/plugins/core-plugins/demo-login/index.ts` (line 30)
- Pattern: `notice.innerHTML = '🎯 <strong>Demo Mode:</strong> ...'`
- Impact: Low risk for this hardcoded message, but establishes unsafe pattern
- Fix approach: Use textContent or createElement for user-controlled data

**Unsafe Password Hash Implementation:**
- Issue: Password hashing uses SHA-256 with static salt instead of bcrypt
- Files: `src/middleware/auth.ts` (lines 45-52)
- Pattern: Simple SHA-256 with hardcoded salt string
- Impact: Passwords vulnerable to rainbow table attacks, insufficient salt
- Fix approach: Use bcrypt with random salt generation per password

## Tech Debt

**Activity Logging Not Implemented:**
- Issue: Multiple TODO comments for activity logging functionality, no implementation
- Files:
  - `src/routes/auth.ts` (lines 897, 962, 1206)
- Impact: No audit trail for critical auth operations (login, registration, password reset)
- Security gap: Cannot investigate security incidents or user behavior
- Priority: High
- Fix approach: Implement activity logging service that records auth events with user, timestamp, action

**Middleware Stubs - Placeholder Implementations:**
- Issue: Multiple middleware exports are empty pass-through stubs
- Files: `src/middleware/index.ts` (lines 28-44)
- Includes (all return pass-through middleware):
  - loggingMiddleware
  - detailedLoggingMiddleware
  - securityLoggingMiddleware
  - performanceLoggingMiddleware
  - cacheHeaders
  - compressionMiddleware
  - securityHeaders
  - requirePermission
  - requireAnyPermission
  - logActivity
  - requireActivePlugin
  - requireActivePlugins
- Impact: No actual logging, caching, compression, or permission enforcement - features silently disabled
- Fix approach: Implement middleware or document as "not yet implemented", make explicit in logs

**Plugin Settings Not Loaded from Configuration:**
- Issue: Plugins have hardcoded configuration values instead of loading from plugin settings
- Files: `src/plugins/available/magic-link-auth/index.ts` (lines 46, 60, 78)
- Hardcoded values:
  - Line 46: `const rateLimitPerHour = 5 // TODO: Get from plugin settings`
  - Line 60: `const allowNewUsers = false // TODO: Get from plugin settings`
  - Line 78: `const linkExpiryMinutes = 15 // TODO: Get from plugin settings`
- Impact: Plugins cannot be configured without code changes, admin UI settings have no effect
- Fix approach: Load all configuration from plugin settings database on plugin initialization

**Cache Implementation Removed, Not Replaced:**
- Issue: Cache functionality removed during migration with plans to restore via plugin - never completed
- Files: `src/routes/admin-media.ts` (lines 54, 163, 556, 709, 875)
- Impact: No caching for media, content, or settings queries - performance degradation
- Performance hit: Every page load queries database for collections, settings, media lists
- Fix approach: Implement cache plugin or service with TTL, add invalidation on mutations

**Incomplete Migration of authValidationService:**
- Issue: Auth validation service not fully migrated to core package
- Files: `src/routes/admin-plugins.ts` (line 6-7, comment: "TODO: authValidationService not yet migrated")
- Impact: Permission system for plugin management not fully functional
- Lines 743-745: Cache invalidation commented out because service not available
- Fix approach: Complete migration of authValidationService, uncomment cache invalidation

**Backup Feature Stub Only:**
- Issue: Database backup endpoint returns success but performs no backup
- Files: `src/routes/admin-settings.ts` (lines 395-400)
- Response: `"Database backup feature coming soon. Use Cloudflare Dashboard for backups."`
- Impact: Users think backups created when they're not - data loss risk
- Fix approach: Implement actual backup to Cloudflare or S3, or remove feature from UI

**Incomplete Event System:**
- Issue: Event architecture planned but not fully implemented
- Files: `src/routes/api-media.ts` (line 14, comment: "TODO: Implement proper event system")
- Current state: Console logging with TODO for full implementation
- Impact: Cannot hook into media operations for workflows or notifications
- Fix approach: Implement event system for plugin lifecycle and media operations

**AI Search Indexing Not Implemented:**
- Issue: Cloudflare AI Search API integration is stubbed
- Files: `src/plugins/core-plugins/ai-search-plugin/services/indexer.ts` (line 146)
- Comment: `// TODO: Call Cloudflare AI Search API to index document`
- Impact: AI search plugin cannot index new documents
- Fix approach: Integrate with Cloudflare AI Search API endpoints

**RAG Chunk Tracking Not Implemented:**
- Issue: No tracking of which source chunks used in search results
- Files: `src/plugins/core-plugins/ai-search-plugin/services/custom-rag.service.ts` (line 377)
- Comment: `// TODO: Implement proper chunk tracking`
- Impact: Cannot trace search results back to source documents
- Fix approach: Implement chunk tracking in RAG retrieval pipeline

**Query Time Tracking Missing:**
- Issue: Analytics don't track query execution times
- Files: `src/plugins/core-plugins/ai-search-plugin/services/ai-search.ts` (line 593)
- Value: `average_query_time: 0, // TODO: Track query times`
- Impact: Cannot identify slow queries or analyze search performance
- Fix approach: Add query timing instrumentation to search service

## Known Bugs

**Permission System Not Enforced:**
- Symptoms: Plugin management permission checks are incomplete
- Files: `src/routes/admin-plugins.ts` (line 143)
- Comment: `// TODO: Fix permission system`
- Current state: Only admin role check, permissions ignored
- Workaround: Only admin users can manage plugins
- Risk: Once permission system implemented, behavior may change unexpectedly

**Auth Validation Cache Invalidation Broken:**
- Symptoms: Plugin auth settings changes may not take effect
- Files: `src/routes/admin-plugins.ts` (line 744, commented out)
- Trigger: Update core-auth plugin settings in admin interface
- Workaround: Restart application for changes to take effect
- Fix needed: Uncomment cache invalidation once authValidationService migration completes

**Concurrent Content Edits Not Handled:**
- Symptoms: Last-write-wins on simultaneous edits, no conflict detection
- Files: `src/routes/admin-content.ts` (implied from no version tracking)
- Trigger: Two users editing same content item simultaneously
- Impact: Data loss from overwritten changes
- Fix approach: Add version/revision tracking and optimistic locking

## Test Coverage Gaps

**Skipped Test Suites - 10+ Major Areas:**
- Issue: Test suites marked with describe.skip() preventing test execution
- Skipped files:
  - `src/__tests__/services/collections.schema.test.ts`
  - `src/__tests__/services/collections.integration.test.ts`
  - `src/__tests__/services/content.models.test.ts`
  - `src/__tests__/services/content.workflow.test.ts`
  - `src/__tests__/services/media.images.test.ts` (multiple suites)
  - `src/__tests__/services/media.storage.test.ts`
  - `src/__tests__/services/notifications.test.ts`
  - `src/__tests__/middleware/middleware.permissions.test.ts`
  - `src/__tests__/middleware/logging.test.ts`
  - `src/__tests__/routes/routes.api.test.ts`
  - `src/__tests__/routes/routes.api.final.test.ts`
- Impact: Zero test coverage for content models, workflows, media ops, permissions, API routes
- Risk: Changes break untested functionality silently
- Fix approach: Unskip tests, implement missing dependencies

**Overall Low Test Coverage:**
- Issue: 33 test files for 220+ source files = ~15% coverage
- Route layer: 21 route files with minimal test coverage
- Services: Most services untested
- Plugins: Core plugins lack test coverage
- Missing coverage: Auth flows, permissions, plugins, media operations
- Fix approach: Incremental coverage improvements, focus on security-critical paths

**Form Field Validation Not Tested:**
- What's missing: Comprehensive tests for all field types (blocks, complex JSON, dynamic selects)
- Files: `src/routes/admin-content.ts` (form handling)
- Risk: Invalid data saved due to missing validation
- Priority: Medium

**Plugin Permission System Not Tested:**
- What's missing: Permission validation for plugin install/uninstall/update
- Files: `src/routes/admin-plugins.ts`
- Risk: Unauthorized operations may succeed
- Priority: High

**Plugin Dependency Resolution Not Tested:**
- What's missing: Complex dependency chains, circular deps, missing deps
- Files: `src/services/plugin-service.ts`
- Risk: Plugin system becomes unstable
- Priority: Medium

**Cache Operations Not Tested:**
- What's missing: Cache invalidation, TTL behavior, cache warming
- Files: `src/services/cache.ts`
- Risk: Stale data served to users
- Priority: Medium

**Concurrent Operations Not Tested:**
- What's missing: Concurrent uploads, edits, media operations
- Files: `src/routes/admin-content.ts`, `src/routes/admin-media.ts`
- Risk: Race conditions, data corruption
- Priority: High

## Fragile Areas

**Large Monolithic Files - Difficult to Maintain:**
- Issue: Multiple files exceed 1,500 lines of code
- Files with line counts:
  - `src/templates/components/dynamic-field.template.ts` (1,671 lines)
  - `src/routes/admin-users.ts` (1,581 lines)
  - `src/routes/admin-content.ts` (1,574 lines)
  - `src/templates/pages/admin-settings.template.ts` (1,568 lines)
  - `src/routes/auth.ts` (1,218 lines)
- Impact: Difficult to understand, modify, test; high risk for bug introduction
- Safe modification: Any change requires full file review; single function changes risk side effects
- Test coverage: Incomplete for these files
- Fix approach: Break into smaller modules by responsibility (form handlers, templates, routes)

**Type Safety Issues - Widespread 'any' Usage:**
- Issue: Extensive use of `any` type in middleware and services
- Files: `src/middleware/index.ts` (all stub middleware typed as `any`)
- Pattern: `export const loggingMiddleware: any = () => ...`
- Impact: Type checking disabled for critical auth/permission code
- Risk areas: Middleware composition, plugin context, error handling
- Fix approach: Implement proper TypeScript types for middleware, enforce no-implicit-any

**Permission System Incomplete:**
- Issue: Permission checking middleware is stubbed, permissions not enforced
- Files: `src/middleware/index.ts` (lines 38-44)
- Current state: `export const requirePermission: any = () => ...`
- Impact: Role-based access control not working
- Safe modification: Cannot modify without understanding full permission intent
- Test coverage: Permissions not tested
- Fix approach: Implement permission system, wire up middleware

**Plugin System Under Active Development:**
- Issue: Multiple plugin-related systems partially implemented
- Fragile components:
  - Plugin installation (depends on incomplete permission system)
  - Plugin settings (hardcoded instead of dynamic)
  - Plugin activation (cache invalidation disabled)
  - Plugin events (not implemented)
- Safe modification: Large refactor in progress - changes may conflict with ongoing migration
- Fix approach: Complete plugin migration, stabilize API before third-party plugins

**Dynamic Field Rendering with Type-Specific Logic:**
- Issue: Long switch statements with type-specific parsing
- Files: `src/routes/admin-content.ts` (form handling)
- Why fragile:
  - No validation of field options shape before using
  - Field types hardcoded in multiple places
  - JSON parsing without error context
- Safe modification: Extract field parsers into separate functions, add type validation
- Test coverage: Partial - some field types tested, others not

## Performance Bottlenecks

**Missing Caching Layer for All Queries:**
- Issue: Cache functionality removed during migration, no replacement
- Files: `src/routes/admin-media.ts` (multiple TODOs mentioning removed cache)
- Problem: Media library, content listings, settings queries hit database every time
- Impact: Slow page loads, higher database load
- Scale limit: Becomes critical with hundreds of content items
- Fix approach: Implement Redis/KV-based cache with invalidation on updates

**Query Time Tracking Missing:**
- Issue: TODO to track query times but no implementation
- Files: `src/plugins/core-plugins/ai-search-plugin/services/ai-search.ts` (line 593)
- Impact: Cannot identify slow queries or analyze performance
- Fix approach: Add query timing instrumentation

**No Pagination Optimization for Large Datasets:**
- Issue: Media queries use basic LIMIT/OFFSET pagination without optimization
- Files: `src/routes/admin-media.ts` (lines 50-95)
- Problem: No indexes, no cursor-based pagination, no result caching
- Scale limit: 100K+ files become slow
- Fix approach: Add database indexes, implement cursor-based pagination

## Scaling Limits

**Auth Validation Not Cached:**
- Issue: Auth validation queries database on every request, no caching
- Files: `src/routes/admin-plugins.ts` (line 744) - cache invalidation commented out
- Current capacity: Works fine with <100 users
- Limit: ~500 concurrent users before database bottleneck
- Scaling path: Implement auth validation caching with TTL

**D1 Database Direct Usage Across Routes:**
- Current capacity: D1 serverless scales automatically
- Limit: Query performance degrades with large datasets; no connection pooling
- Scaling path: Cache query results, add indexes, implement query optimization

**In-Memory Plugin Registry:**
- Current capacity: Plugin list held in memory
- Limit: Changes require server restart to take effect
- Scaling path: Implement plugin registry caching with TTL and cache invalidation

## Unfinished Features

**Activity Logging System:**
- Problem: No audit trail for user actions or system changes
- What's missing: Activity table schema, logging middleware, UI for viewing logs
- Blocks: Security compliance, debugging, forensics
- Files: `src/routes/auth.ts` (multiple TODOs for activity logging)
- Fix approach: Implement activity logging service integrated with all user-modifying endpoints

**Configuration Management for Plugins:**
- Problem: Plugin settings UI exists but settings don't configure plugins
- What's missing: Plugin settings loading and validation, dynamic configuration application
- Blocks: Admin control of plugin behavior, rate limiting, expiry times
- Files: `src/plugins/available/magic-link-auth/index.ts` (hardcoded values)
- Fix approach: Implement settings service that plugins load from at initialization

**Rate Limiting:**
- Problem: No rate limiting on public endpoints (forms, API)
- Blocks: DoS protection, abuse prevention
- Implementation path: Rate limiting middleware, per-endpoint configuration

**Backup and Disaster Recovery:**
- Problem: Backup endpoint exists but is non-functional
- Blocks: Data recovery capabilities
- Implementation path: D1 backup integration, scheduled backups, restore point management

## Dependencies at Risk

**Partial TypeScript Migration:**
- Risk: 712+ uses of `any` type throughout codebase
- Impact: Type safety cannot improve without addressing widespread any usage
- Migration plan: Enable strict TypeScript config, gradually migrate high-risk files

**Partially Migrated Service Architecture:**
- Risk: Services being refactored, leaving holes in functionality
- Impact: Features like caching and activity logging incomplete
- Migration plan: Complete plugin migration, test all services in integration

**Plugin System API Stability Unknown:**
- Risk: Plugin SDK API may change; third-party plugins may break
- Impact: Plugin compatibility uncertain across releases
- Stability path: Establish semantic versioning, document compatibility guarantees

---

*Concerns audit: 2026-02-01*
