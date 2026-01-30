# External Integrations

**Analysis Date:** 2026-01-30

## APIs & External Services

**Email Services:**
- **Resend** - Transactional email provider
  - SDK/Client: Direct fetch to `https://api.resend.com/emails`
  - Auth: API key stored in plugin settings (database)
  - Implementation: `packages/core/src/plugins/core-plugins/email-plugin/index.ts`
  - Used for: Test emails, transactional notifications
  - Configuration: Requires `apiKey`, `fromEmail`, `fromName`, optional `replyTo`

**CAPTCHA/Verification:**
- **Cloudflare Turnstile** - Bot verification
  - Verify endpoint: `https://challenges.cloudflare.com/turnstile/v0/siteverify`
  - Implementation: `packages/core/src/plugins/core-plugins/turnstile-plugin/services/turnstile.ts`
  - Configuration: Site key, secret key, theme, size, mode stored in plugin settings
  - Used for: Form submission protection

**Search/AI:**
- **Cloudflare Workers AI** - Semantic embeddings (optional)
  - Binding: `AI` (if configured in wrangler.toml)
  - Implementation: `packages/core/src/plugins/core-plugins/ai-search-plugin/services/ai-search.ts`
  - Purpose: Generate embeddings for vector search
  - Fallback: Keyword search only if AI not available

- **Cloudflare Vectorize** - Vector database (optional)
  - Binding: Can be added to wrangler.toml
  - Implementation: Custom RAG service in ai-search plugin
  - Purpose: Semantic search via vector similarity

**Maps:**
- **Google Maps Embed API** - Location embedding
  - Endpoint: `https://www.google.com/maps/embed/v1/place`
  - Configuration: `GOOGLE_MAPS_API_KEY` environment variable
  - Implementation: `my-sonicjs-app/src/plugins/contact-form/routes/public.ts`
  - Usage: Contact form location display

**Fonts:**
- **Google Fonts** - Typography
  - CDN: `https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap`
  - Used in: Admin layout templates (`packages/core/src/templates/layouts/`)

## Data Storage

**Databases:**
- **Cloudflare D1** (SQLite)
  - Connection: Via `c.env.DB` (Hono context binding)
  - Client: Drizzle ORM (`drizzle-orm 0.44.2`)
  - Database ID: `68223153-215a-4c8f-a9bf-797f11236758`
  - Tables defined in: `packages/core/src/db/schema.ts`
  - Tables: `users`, `collections`, `content`, `contentVersions`, `media`, `apiTokens`, `workflowHistory`, `webhooks`, `plugins`, `logs`, `forms`, `formSubmissions`, `emailLogs`, `emailTemplates`
  - Migrations: Located in `migrations/` directory, managed by Drizzle Kit

**File Storage:**
- **Cloudflare R2** - Object storage for media
  - Bucket binding: `MEDIA_BUCKET` (sonicjs-ci-media)
  - Purpose: Store uploaded images, documents, media files
  - Implementation: Media service in `packages/core/src/routes/admin-media.ts`
  - CDN URL: Stored in `media.publicUrl` field after upload

**Caching:**
- **Cloudflare KV** - Key-value cache
  - Binding: `CACHE_KV` (a16f8246fc294d809c90b0fb2df6d363)
  - Purpose: Cache API responses, rendered content
  - Implementation: Cache invalidation in `packages/core/src/plugins/cache/`

## Authentication & Identity

**Auth Provider:**
- Custom implementation
  - Strategy: Session-based with JWT tokens or API tokens
  - Database: User table in D1 (`packages/core/src/db/schema.ts`)
  - Password hashing: Via `passwordHash` field (implementation in auth services)
  - Roles: admin, editor, author, viewer (stored in `users.role`)
  - API Tokens: Support for programmatic access (stored in `apiTokens` table)

**Authentication Plugins (Optional):**
- **Demo Login Plugin** - For development/testing (`packages/core/src/plugins/core-plugins/demo-login/`)
- **OTP Login Plugin** - One-time password authentication (`packages/core/src/plugins/core-plugins/otp-login-plugin/`)
  - Email delivery: Uses email plugin
  - Templates: `email-templates.ts`

**Email-based Auth:**
- **Magic Link Auth** - Email verification links (`packages/core/src/plugins/available/magic-link-auth/`)
- **Email Verification** - Registration and password reset
  - Handled by email plugin and OTP plugin
  - Email queue system: `packages/core/src/plugins/available/email-templates-plugin/services/email-queue.ts`

## Monitoring & Observability

**Telemetry:**
- **SonicJS Stats Endpoint** - Custom privacy-first telemetry
  - Endpoint: `{TELEMETRY_HOST}/v1/events` (configurable)
  - Implementation: `packages/core/src/services/telemetry-service.ts`
  - Features: Installation tracking, event logging, error reporting
  - Privacy: No PII collection, opt-out by default, silent failures

**Error Tracking:**
- Implicit via telemetry service with `sanitizeErrorMessage()`
- Error logs stored in D1 logs table
- No third-party error tracking service integrated

**Logs:**
- **Database-backed logging:**
  - Destination: `logs` table in D1
  - Service: `packages/core/src/services/logger.ts`
  - Levels: INFO, WARN, ERROR
  - Queryable via admin UI: `/admin/logs`

## CI/CD & Deployment

**Hosting:**
- **Cloudflare Workers** - Serverless edge computing
  - Deployment: Via Wrangler CLI (`npm run deploy`)
  - Entry point: `src/index.ts`
  - Compatibility date: 2025-05-05
  - Node.js compatibility flags enabled

**CI Pipeline:**
- **GitHub Actions** (inferred from wrangler.toml comment)
  - Auto-updates `database_id` in wrangler.toml on deployments
  - E2E tests: Playwright configured (`tests/playwright.config.ts`)

**Build System:**
- **Wrangler build** - Automatic bundling during deployment
- No separate build script needed; Wrangler handles TypeScript compilation

## Environment Configuration

**Required env vars:**
- `ENVIRONMENT` - Set to "development" in local wrangler.toml
- `GOOGLE_MAPS_API_KEY` - Optional, for map embeds in forms
- Database bindings: `DB`, `MEDIA_BUCKET`, `CACHE_KV` (configured in wrangler.toml)

**Plugin Settings (Stored in Database):**
- **Email Plugin:**
  - `apiKey` - Resend API key
  - `fromEmail` - Sender email address
  - `fromName` - Sender display name
  - `replyTo` - Optional reply-to address

- **Turnstile Plugin:**
  - `siteKey` - Cloudflare Turnstile site key
  - `secretKey` - Cloudflare Turnstile secret key
  - `enabled` - Boolean flag
  - `theme`, `size`, `mode` - UI configuration

- **AI Search Plugin:**
  - `enabled` - Boolean flag
  - `ai_mode_enabled` - Use embeddings vs keyword search
  - `selected_collections` - Array of collection IDs to index
  - `autocomplete_enabled` - Boolean flag
  - `cache_duration` - Cache TTL in hours
  - `results_limit` - Max results per search

**Secrets location:**
- Plugin settings: Stored in `plugins.settings` JSON field in D1
- No .env files committed (security best practice)
- Wrangler handles secret injection via `wrangler secret put` command

## Webhooks & Callbacks

**Incoming:**
- **Webhook endpoints for content events:**
  - Service: `packages/core/src/plugins/core-plugins/workflow-plugin/services/webhooks.ts`
  - Supported events: Content creation, update, deletion, status changes
  - Configuration: Webhook registry stored in D1 `webhooks` table
  - Security: Optional HMAC secret signing per webhook

**Outgoing:**
- **Content event webhooks:**
  - Triggered on: Content published, updated, deleted
  - Delivery: HTTP POST with event payload and HMAC signature (if secret configured)
  - Retry logic: Configurable retry count and timeout per webhook
  - Logging: Webhook deliveries tracked in database for debugging

**Email Delivery Callbacks:**
- **Resend webhook support:** (Configured in Resend dashboard, not in codebase)
  - Can send delivery status updates back to email service

---

*Integration audit: 2026-01-30*
