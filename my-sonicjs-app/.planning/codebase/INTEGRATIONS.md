# External Integrations

**Analysis Date:** 2026-01-30

## APIs & External Services

**Email Delivery:**
- Resend - Transactional email service
  - SDK/Client: Fetch API to `https://api.resend.com/emails`
  - Auth: API key (stored in plugin settings, environment variable: optional `RESEND_API_KEY`)
  - Used by: Email plugin (`packages/core/src/plugins/core-plugins/email-plugin/index.ts`)
  - Use cases: Registration confirmations, password resets, OTP codes, custom notifications

**Bot Protection:**
- Cloudflare Turnstile - CAPTCHA-free bot protection
  - SDK/Client: JavaScript widget via `https://challenges.cloudflare.com/turnstile/v0/api.js`
  - Verification endpoint: `https://challenges.cloudflare.com/turnstile/v0/siteverify` (POST)
  - Auth: Site key (public) and secret key (private, in plugin settings)
  - Implementation: `packages/core/src/plugins/core-plugins/turnstile-plugin/`
  - Use cases: Form protection, signup protection, API rate limiting

**Search & AI:**
- Cloudflare Workers AI - Semantic search using embeddings
  - Binding: `ai` (optional, from Cloudflare Workers environment)
  - Used by: AI Search plugin (`packages/core/src/plugins/core-plugins/ai-search-plugin/`)
  - Models: Embedding models for semantic search (text-to-embeddings)
  - Use cases: Semantic search across content, autocomplete suggestions

**Google Maps:**
- Google Maps API
  - Auth: API key via environment variable `GOOGLE_MAPS_API_KEY`
  - Used by: Forms (`packages/core/src/routes/public-forms.ts`, `packages/core/src/routes/admin-forms.ts`)
  - Use cases: Location field autocomplete in forms

**Email Templates (Optional Plugin):**
- SendGrid - Email service alternative
  - SDK/Client: Fetch API to `https://api.sendgrid.com/v3/mail/send`
  - Auth: API key via environment variable `SENDGRID_API_KEY`
  - Used by: Email templates plugin (`packages/core/src/plugins/available/email-templates-plugin/`)
  - Use cases: Template-based email delivery

**Image Optimization (Optional):**
- Cloudflare Images - Image optimization and resizing
  - Auth: Account ID (`IMAGES_ACCOUNT_ID`) and API token (`IMAGES_API_TOKEN`)
  - Used by: System endpoints detecting availability (`packages/core/src/routes/api-system.ts`)
  - Use cases: Image resizing, format conversion, CDN delivery

## Data Storage

**Databases:**
- Cloudflare D1 (SQLite)
  - Connection: Binding `DB` from wrangler.toml
  - Client: Drizzle ORM (`drizzle-orm/d1`)
  - Binding name in Hono context: `c.env.DB`
  - Configuration in `wrangler.toml`:
    ```
    [[d1_databases]]
    binding = "DB"
    database_name = "sonicjs-worktree-lane711-otp-email-branding"
    database_id = "68223153-215a-4c8f-a9bf-797f11236758"
    migrations_dir = "./migrations"
    ```

**File Storage:**
- Cloudflare R2 (S3-compatible object storage)
  - Binding: `MEDIA_BUCKET`
  - Bucket name: `sonicjs-ci-media`
  - Accessible via: `/files/*` public endpoint
  - Used by: Media management routes, content assets

**Caching:**
- Cloudflare KV (distributed key-value store)
  - Binding: `CACHE_KV`
  - ID: `a16f8246fc294d809c90b0fb2df6d363`
  - Used by: Cache plugin for request caching

**Vector Storage (Optional):**
- Cloudflare Vectorize - Vector database for embeddings
  - Binding: `vectorize` (from Workers environment)
  - Used by: AI Search plugin for semantic search indexes

## Authentication & Identity

**Auth Provider:**
- Custom (built-in)
  - Implementation: `packages/core/src/middleware/auth.ts`
  - Method: JWT tokens in cookies
  - Token signing: Hono JWT utilities
  - Password hashing: Stored as `password_hash` in users table
  - User roles: admin, editor, author, viewer

**Optional Auth Plugins:**
- OTP Login Plugin - One-time password authentication
  - Implementation: `packages/core/src/plugins/core-plugins/otp-login-plugin/`
  - Delivery: Email via Resend API
  - Use cases: Passwordless login

- Magic Link Auth Plugin - Passwordless email link authentication
  - Implementation: `packages/core/src/plugins/available/magic-link-auth/`
  - Delivery: Email-based authentication links
  - Use cases: Passwordless signup and login

## Monitoring & Observability

**Error Tracking:**
- Not detected - No third-party error tracking integrated

**Logs:**
- Built-in logging to D1 database
  - Implementation: `packages/core/src/services/logger.ts`
  - Table: Uses query logging (exact table name varies)
  - Accessible via: Admin logs endpoint (`packages/core/src/routes/admin-logs.ts`)

**Telemetry:**
- Custom telemetry service
  - Implementation: `packages/core/src/utils/telemetry-config.ts`
  - Environment variable: `SONICJS_TELEMETRY_ENDPOINT` (optional custom endpoint)
  - Respects: `DO_NOT_TRACK` environment variable
  - Configurable: Can be disabled via `SONICJS_TELEMETRY=false`

**Observability (Cloudflare):**
- Cloudflare Workers observability enabled in wrangler.toml
  - Setting: `[observability] enabled = true`
  - Provides: Request metrics, error tracking via Cloudflare dashboard

## CI/CD & Deployment

**Hosting:**
- Cloudflare Workers (serverless edge platform)
- Account ID: `f9d6328dc3115e621758a741dda3d5c4`

**Deployment:**
- Wrangler CLI (`wrangler deploy`)
- Configuration: `wrangler.toml`

**CI Pipeline:**
- GitHub Actions (implied by GitHub Actions comments in wrangler.toml)
- Database and bucket auto-updated by GitHub Actions
- Note in wrangler.toml: "database_name and database_id are automatically updated by GitHub Actions"

## Environment Configuration

**Required env vars (wrangler.toml):**
```
ENVIRONMENT = "development"
```

**Optional env vars (secrets or vars):**
- `RESEND_API_KEY` - Resend email service API key
- `SENDGRID_API_KEY` - SendGrid email service API key (alternative)
- `GOOGLE_MAPS_API_KEY` - Google Maps API key
- `IMAGES_ACCOUNT_ID` - Cloudflare Images account ID
- `IMAGES_API_TOKEN` - Cloudflare Images API token
- `SONICJS_TELEMETRY_ENDPOINT` - Custom telemetry endpoint
- `SONICJS_TELEMETRY` - Enable/disable telemetry (default: enabled)
- `DO_NOT_TRACK` - Respect DNT header (disables telemetry)
- `NODE_ENV` - Runtime environment

**Secrets location:**
- Not in source code
- Managed via Cloudflare Workers secret management
- Set via `wrangler secret` CLI commands (not version controlled)

## Webhooks & Callbacks

**Incoming Webhooks:**
- Not detected in core framework

**Workflow Webhooks:**
- Workflow plugin has webhook infrastructure
  - Implementation: `packages/core/src/plugins/core-plugins/workflow-plugin/services/webhooks.ts`
  - Purpose: Event-driven automation and integrations
  - Storage: D1 database

**Email Queue (Optional):**
- Cloudflare Queue binding (optional)
  - Binding: `EMAIL_QUEUE` (if configured)
  - Used by: Email plugin for async email delivery
  - Not visible in current wrangler.toml but supported in Bindings interface

**Outgoing:**
- Not detected as implemented

## API Integration Patterns

**All integrations use Fetch API:**
- No SDK dependencies for Resend, SendGrid, or Turnstile
- Direct HTTP/REST API calls using native Fetch
- Headers include Authorization tokens or API keys

**Error Handling:**
- Try/catch blocks with user-friendly error messages
- Cloudflare API errors logged and returned to client
- Fallback behaviors for optional services (e.g., Turnstile can be disabled)

**Rate Limiting & Caching:**
- Turnstile settings cached in D1 to avoid repeated lookups
- Email settings stored in plugin settings table
- No explicit rate limiting detected but inherited from Cloudflare Workers

---

*Integration audit: 2026-01-30*
