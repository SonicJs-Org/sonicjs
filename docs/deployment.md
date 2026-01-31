# SonicJS AI Deployment Guide

Complete guide for deploying SonicJS AI to production on Cloudflare's edge platform.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Wrangler Configuration](#wrangler-configuration)
- [D1 Database Setup](#d1-database-setup)
- [R2 Bucket Setup](#r2-bucket-setup)
- [KV Namespace Setup](#kv-namespace-setup)
- [Environment Variables and Secrets](#environment-variables-and-secrets)
- [Deployment Workflow](#deployment-workflow)
- [Custom Domains and SSL](#custom-domains-and-ssl)
- [Production Checklist](#production-checklist)
- [Monitoring and Logging](#monitoring-and-logging)
- [Rollback Procedures](#rollback-procedures)
- [Performance Optimization](#performance-optimization)
- [CI/CD with GitHub Actions](#cicd-with-github-actions)
- [Troubleshooting](#troubleshooting)

## Overview

SonicJS AI runs on Cloudflare's global edge network, providing:

- **Cloudflare Workers**: Serverless application runtime at 300+ edge locations
- **D1 Database**: SQLite-based distributed database at the edge
- **R2 Object Storage**: S3-compatible object storage for media files
- **KV Storage**: Low-latency key-value storage for caching
- **Zero cold starts**: Instant response times globally

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Cloudflare Edge                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Workers    │  │  D1 Database │  │  R2 Storage  │  │
│  │  (Runtime)   │──│  (SQLite)    │  │   (Media)    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│         │                                   │            │
│         └───────────── KV Cache ────────────┘            │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

### Required Accounts

1. **Cloudflare Account**
   - Sign up at https://dash.cloudflare.com/sign-up
   - Workers Paid plan ($5/month minimum)
   - Payment method on file

2. **Domain Name** (optional but recommended)
   - Can use workers.dev subdomain for testing
   - Custom domain for production recommended

### Required Tools

```bash
# Node.js 18+ and npm
node --version  # Should be v18.0.0 or higher
npm --version

# Wrangler CLI (Cloudflare Workers CLI)
npm install -g wrangler@latest
wrangler --version  # Should be v3.0.0 or higher

# Git for version control
git --version
```

### Install and Login to Wrangler

```bash
# Install Wrangler globally
npm install -g wrangler@latest

# Login to Cloudflare
wrangler login

# This will:
# 1. Open browser for authentication
# 2. Save credentials locally
# 3. Verify account access

# Verify login
wrangler whoami
```

## Environment Configuration

SonicJS AI supports three environments:

1. **Development** (`dev`) - Local development with local D1
2. **Preview** (`preview`) - Staging environment for testing
3. **Production** (`production`) - Live production environment

### Environment Strategy

```
┌─────────────┬──────────────┬─────────────┬──────────────┐
│ Environment │ Database     │ R2 Bucket   │ Domain       │
├─────────────┼──────────────┼─────────────┼──────────────┤
│ dev         │ local D1     │ dev bucket  │ localhost    │
│ preview     │ shared D1    │ preview     │ preview.dev  │
│ production  │ prod D1      │ prod bucket │ yourdomain   │
└─────────────┴──────────────┴─────────────┴──────────────┘
```

## Wrangler Configuration

The `wrangler.toml` file defines all environments and bindings.

### Current Configuration Structure

```toml
name = "sonicjs-ai"
main = "src/index.ts"
compatibility_date = "2024-06-01"
compatibility_flags = ["nodejs_compat"]

# Build configuration
[build]
command = ""

[build.upload]
format = "modules"

[[build.upload.rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallthrough = true

# Static assets binding
[assets]
directory = "./public"
binding = "ASSETS"

# Development environment variables
[vars]
ENVIRONMENT = "development"

# D1 Database binding (development)
[[d1_databases]]
binding = "DB"
database_name = "sonicjs-dev"
database_id = "874cad37-313c-4d71-97fa-ad7184526f5a"

# R2 bucket binding (development)
[[r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "sonicjs-media-dev"

# KV namespace binding (development)
[[kv_namespaces]]
binding = "CACHE_KV"
id = "a16f8246fc294d809c90b0fb2df6d363"
preview_id = "25360861fb2745fab3b1ef2f0f13ffc8"

# Preview environment
[env.preview]
name = "sonicjs-ai-preview"

[env.preview.vars]
ENVIRONMENT = "preview"

[[env.preview.d1_databases]]
binding = "DB"
database_name = "sonicjs-dev"
database_id = "874cad37-313c-4d71-97fa-ad7184526f5a"

[[env.preview.r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "sonicjs-media-preview"

[[env.preview.kv_namespaces]]
binding = "CACHE_KV"
id = "6fc451bee9bb412ebd1d325723779c9c"
preview_id = "38c54bd2b55643c097412fa3464c2ddd"

# Production environment
[env.production]
name = "sonicjs-ai-prod"

[env.production.vars]
ENVIRONMENT = "production"

[[env.production.d1_databases]]
binding = "DB"
database_name = "sonicjs-ai"
database_id = "583c089c-1a4a-477d-9d58-06c07bf7c1d7"

[[env.production.r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "sonicjs-media-prod"

[[env.production.kv_namespaces]]
binding = "CACHE_KV"
id = "7171ca98640e43b6b33dbff516a5a6cf"
preview_id = "aed99543752d438b8051a0b6809ced10"
```

### Key Configuration Elements

| Binding | Purpose | Type |
|---------|---------|------|
| `DB` | Main database | D1 Database |
| `MEDIA_BUCKET` | Media/file storage | R2 Bucket |
| `CACHE_KV` | Cache storage | KV Namespace |
| `ASSETS` | Static files | Assets binding |

## D1 Database Setup

### Step 1: Create Production Database

```bash
# Create a new D1 database for production
wrangler d1 create sonicjs-ai

# Output example:
# ✅ Successfully created DB 'sonicjs-ai'
#
# [[d1_databases]]
# binding = "DB"
# database_name = "sonicjs-ai"
# database_id = "583c089c-1a4a-477d-9d58-06c07bf7c1d7"
```

### Step 2: Update wrangler.toml

Copy the output and update your `wrangler.toml` production section:

```toml
[[env.production.d1_databases]]
binding = "DB"
database_name = "sonicjs-ai"
database_id = "YOUR-DATABASE-ID-HERE"
```

### Step 3: Apply Database Schema

SonicJS uses Drizzle ORM for migrations. Apply all migrations to production:

```bash
# Apply migrations to production database
npm run db:migrate:prod

# Or manually with wrangler
wrangler d1 migrations apply DB --env production

# This will:
# 1. Read migration files from drizzle/migrations/
# 2. Apply them in order to production D1
# 3. Track applied migrations
```

### Step 4: Verify Database Schema

```bash
# List tables in production database
wrangler d1 execute sonicjs-ai --env production --command="SELECT name FROM sqlite_master WHERE type='table';"

# Expected tables:
# - users
# - collections
# - content
# - content_versions
# - media
# - api_tokens
# - plugins
# - plugin_routes
# - plugin_hooks
# - plugin_assets
# - plugin_activity_log
```

### Step 5: Seed Initial Data (Optional)

Create admin user and initial collections:

```bash
# Use the production seed script
wrangler d1 execute sonicjs-ai --env production --file=./scripts/seed-production-content.sql

# Or create a custom admin user
wrangler d1 execute sonicjs-ai --env production --command="
INSERT INTO users (id, email, username, first_name, last_name, role, is_active, created_at, updated_at)
VALUES (
  'admin-' || lower(hex(randomblob(16))),
  'admin@yourdomain.com',
  'admin',
  'Admin',
  'User',
  'admin',
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
);
"
```

### Local Development Database

```bash
# For local development, use local D1
wrangler d1 execute sonicjs-dev --local --file=./drizzle/migrations/0000_happy_donald_blake.sql

# Apply all migrations locally
npm run db:migrate
```

## R2 Bucket Setup

### Step 1: Create Production R2 Bucket

```bash
# Create R2 bucket for production media storage
wrangler r2 bucket create sonicjs-media-prod

# Verify creation
wrangler r2 bucket list

# Output:
# sonicjs-media-dev
# sonicjs-media-preview
# sonicjs-media-prod
```

### Step 2: Configure Bucket CORS (Optional)

If you need direct browser uploads:

```bash
# Create cors-config.json
cat > cors-config.json << 'EOF'
{
  "CORSRules": [
    {
      "AllowedOrigins": ["https://yourdomain.com"],
      "AllowedMethods": ["GET", "PUT", "POST"],
      "AllowedHeaders": ["*"],
      "MaxAgeSeconds": 3600
    }
  ]
}
EOF

# Apply CORS configuration
# Note: CORS configuration currently requires Cloudflare Dashboard
# Go to R2 > your-bucket > Settings > CORS
```

### Step 3: Generate R2 Access Tokens (Optional)

For programmatic access outside Workers:

```bash
# Go to Cloudflare Dashboard > R2 > Manage R2 API Tokens
# Create new API token with:
# - Permissions: Read & Write
# - Buckets: sonicjs-media-prod

# Save these securely:
# - Access Key ID
# - Secret Access Key
# - Endpoint URL: https://[account-id].r2.cloudflarestorage.com
```

### Step 4: Configure Custom Domain for R2 (Optional)

```bash
# In Cloudflare Dashboard:
# 1. Go to R2 > sonicjs-media-prod > Settings
# 2. Click "Connect Domain"
# 3. Enter: media.yourdomain.com
# 4. DNS records will be created automatically

# This allows public access to media files via:
# https://media.yourdomain.com/uploads/image.jpg
```

### Bucket Organization

Recommended folder structure:

```
sonicjs-media-prod/
├── uploads/          # User uploaded media
├── avatars/          # User avatar images
├── thumbnails/       # Generated thumbnails
├── documents/        # PDF and documents
└── temp/            # Temporary files (auto-cleanup)
```

## KV Namespace Setup

### Step 1: Create Production KV Namespace

```bash
# Create KV namespace for cache
wrangler kv:namespace create "CACHE_KV" --env production

# Output:
# ✅ Created namespace with id "7171ca98640e43b6b33dbff516a5a6cf"
# Add the following to your wrangler.toml:
# [[env.production.kv_namespaces]]
# binding = "CACHE_KV"
# id = "7171ca98640e43b6b33dbff516a5a6cf"

# Create preview namespace
wrangler kv:namespace create "CACHE_KV" --env production --preview

# Output:
# ✅ Created preview namespace with id "aed99543752d438b8051a0b6809ced10"
```

### Step 2: Update wrangler.toml

Add the KV namespace IDs to production config:

```toml
[[env.production.kv_namespaces]]
binding = "CACHE_KV"
id = "7171ca98640e43b6b33dbff516a5a6cf"
preview_id = "aed99543752d438b8051a0b6809ced10"
```

### Step 3: Verify KV Access

```bash
# List all KV namespaces
wrangler kv:namespace list

# Test write
wrangler kv:key put --binding CACHE_KV --env production "test" "Hello from production"

# Test read
wrangler kv:key get --binding CACHE_KV --env production "test"

# Delete test key
wrangler kv:key delete --binding CACHE_KV --env production "test"
```

### KV Usage in SonicJS

The cache plugin uses KV for:
- API response caching
- Collection metadata caching
- Content caching
- Admin dashboard stats

Cache keys follow the pattern:
```
cache:api:collections:all
cache:api:content-list:limit:50
cache:collection-content:blog-posts:limit:50
```

## Environment Variables and Secrets

### Types of Configuration

1. **Public Variables** (`[vars]` in wrangler.toml)
   - Non-sensitive configuration
   - Available at build time
   - Examples: ENVIRONMENT, feature flags

2. **Secrets** (via `wrangler secret`)
   - Sensitive data (passwords, API keys)
   - Encrypted at rest
   - Only available at runtime
   - Examples: BETTER_AUTH_SECRET, API keys

### Required Secrets for Production

```bash
# Better Auth: session signing and base URL (required for authentication)
# BETTER_AUTH_SECRET: min 32 characters; used to sign session cookies
openssl rand -base64 32 | wrangler secret put BETTER_AUTH_SECRET --env production

# BETTER_AUTH_URL: public URL of your app (e.g. https://your-app.com or https://your-app.workers.dev)
# For local dev, use http://localhost:8787 in .dev.vars
wrangler secret put BETTER_AUTH_URL --env production

# Admin password for initial setup (optional)
echo "your-secure-admin-password" | wrangler secret put ADMIN_PASSWORD --env production

# R2 Access credentials (if using external access)
echo "your-r2-access-key-id" | wrangler secret put R2_ACCESS_KEY_ID --env production
echo "your-r2-secret-key" | wrangler secret put R2_SECRET_ACCESS_KEY --env production

# Email service credentials (if using email features)
echo "your-sendgrid-api-key" | wrangler secret put SENDGRID_API_KEY --env production

# Analytics/monitoring tokens (optional)
echo "your-sentry-dsn" | wrangler secret put SENTRY_DSN --env production
```

### Managing Secrets

```bash
# List all secrets (names only, not values)
wrangler secret list --env production

# Update a secret
echo "new-value" | wrangler secret put SECRET_NAME --env production

# Delete a secret
wrangler secret delete SECRET_NAME --env production

# Secrets from file
cat secret.txt | wrangler secret put SECRET_NAME --env production
```

### Public Variables in wrangler.toml

```toml
[env.production.vars]
ENVIRONMENT = "production"
# CDN_DOMAIN = "media.yourdomain.com"
# IMAGES_ACCOUNT_ID = "your-cloudflare-account-id"
# FEATURE_NEW_EDITOR = "true"
# RATE_LIMIT_REQUESTS = "100"
# RATE_LIMIT_WINDOW = "60"
```

### Accessing Variables in Code

```typescript
// In your Worker code
export default {
  async fetch(request: Request, env: Env) {
    // Public variables
    const environment = env.ENVIRONMENT  // "production"

    // Secrets (encrypted)
    const authSecret = env.BETTER_AUTH_SECRET

    // Bindings
    const db = env.DB
    const bucket = env.MEDIA_BUCKET
    const cache = env.CACHE_KV

    // ...
  }
}
```

## Deployment Workflow

### Development Workflow

```bash
# 1. Start local development server
npm run dev

# This runs: wrangler dev
# - Uses local D1 database
# - Live reload on file changes
# - Access at: http://localhost:8787

# 2. Run tests
npm test

# 3. Build project
npm run build

# This runs: tsc && wrangler deploy --dry-run
# - Compiles TypeScript
# - Validates configuration
# - No actual deployment
```

### Preview Deployment

```bash
# Deploy to preview environment
wrangler deploy --env preview

# Output:
# ✅ Successfully deployed to preview
# URL: https://sonicjs-ai-preview.workers.dev

# Test the preview deployment
curl https://sonicjs-ai-preview.workers.dev/api/health
```

### Production Deployment

#### Step 1: Pre-deployment Checks

```bash
# Run all tests
npm test

# Check TypeScript compilation
npm run build

# Verify migrations are up to date
wrangler d1 migrations list DB --env production
```

#### Step 2: Deploy to Production

```bash
# Option 1: Using predeploy script (runs tests + build)
npm run predeploy && npm run deploy

# Option 2: Direct deployment
wrangler deploy --env production

# Output:
# ✅ Successfully deployed to production
# URL: https://sonicjs-ai-prod.workers.dev
#
# Deployment details:
# - Version: 2024-01-15-abc123
# - Size: 2.4 MB
# - Upload time: 3.2s
```

#### Step 3: Post-deployment Verification

```bash
# Health check
curl https://sonicjs-ai-prod.workers.dev/api/health

# Expected response:
# {
#   "status": "healthy",
#   "timestamp": "2024-01-15T12:00:00.000Z",
#   "schemas": ["users", "collections", "content", ...]
# }

# Test API endpoints
curl https://sonicjs-ai-prod.workers.dev/api/collections

# Check admin panel
curl -I https://sonicjs-ai-prod.workers.dev/admin
```

### Deployment Environments

```bash
# Deploy to development (default)
wrangler deploy

# Deploy to preview
wrangler deploy --env preview

# Deploy to production
wrangler deploy --env production

# Deploy with specific version
wrangler deploy --env production --name sonicjs-ai-prod-v1.0.0
```

### View Deployment History

```bash
# List recent deployments
wrangler deployments list --env production

# Output:
# Created       ID                          Version
# 2024-01-15    abc123def456                v1.2.3
# 2024-01-14    def456abc789                v1.2.2
# 2024-01-13    ghi789jkl012                v1.2.1

# View specific deployment
wrangler deployments view abc123def456 --env production
```

## Custom Domains and SSL

### Step 1: Add Domain to Cloudflare

```bash
# Option 1: Domain already in Cloudflare
# Go to Cloudflare Dashboard > Add site > Enter domain

# Option 2: Domain elsewhere
# - Add nameservers to your registrar
# - Wait for DNS propagation (up to 24 hours)
```

### Step 2: Add Worker Route

#### Via Cloudflare Dashboard

1. Go to **Workers & Pages** > **sonicjs-ai-prod**
2. Click **Triggers** tab
3. Click **Add Custom Domain**
4. Enter: `yourdomain.com`
5. Click **Add Custom Domain**

#### Via wrangler.toml

```toml
[env.production]
name = "sonicjs-ai-prod"
routes = [
  { pattern = "yourdomain.com/*", zone_name = "yourdomain.com" },
  { pattern = "www.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

Then deploy:

```bash
wrangler deploy --env production
```

### Step 3: Configure DNS

Cloudflare automatically creates DNS records when you add a custom domain.

Verify DNS records:

```bash
# Check DNS propagation
dig yourdomain.com

# Or using nslookup
nslookup yourdomain.com
```

Manual DNS configuration (if needed):

```
Type: AAAA
Name: @
Content: 100::
Proxy: Enabled (orange cloud)

Type: AAAA
Name: www
Content: 100::
Proxy: Enabled (orange cloud)
```

### Step 4: SSL Certificate

SSL is automatic with Cloudflare:

1. **Universal SSL**: Issued automatically
2. **Edge Certificates**: Free, auto-renewed
3. **Full (Strict)**: Recommended encryption mode

Configure SSL mode:

```bash
# Via Dashboard:
# SSL/TLS > Overview > Full (strict)
```

Verify SSL:

```bash
# Check certificate
curl -vI https://yourdomain.com 2>&1 | grep -i "ssl\|tls"

# Or use SSL checker
# https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com
```

### Step 5: Force HTTPS

Add redirect rule in Cloudflare:

```bash
# Via Dashboard:
# Rules > Page Rules > Create Page Rule
# URL: http://*yourdomain.com/*
# Setting: Always Use HTTPS
```

Or add to Worker:

```typescript
// In src/index.ts
app.use('*', async (c, next) => {
  const url = new URL(c.req.url)
  if (url.protocol === 'http:') {
    url.protocol = 'https:'
    return c.redirect(url.toString(), 301)
  }
  await next()
})
```

### Multiple Domains

```toml
[env.production]
routes = [
  { pattern = "yourdomain.com/*", zone_name = "yourdomain.com" },
  { pattern = "www.yourdomain.com/*", zone_name = "yourdomain.com" },
  { pattern = "app.yourdomain.com/*", zone_name = "yourdomain.com" },
  { pattern = "api.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

## Production Checklist

Use this checklist before going live:

### Infrastructure

- [ ] Production D1 database created and migrated
- [ ] Production R2 bucket created
- [ ] Production KV namespace created
- [ ] All bindings configured in wrangler.toml
- [ ] Secrets uploaded (BETTER_AUTH_SECRET, BETTER_AUTH_URL, etc.)
- [ ] Custom domain added and DNS configured
- [ ] SSL certificate active and valid

### Database

- [ ] All migrations applied successfully
- [ ] Initial data seeded (users, collections)
- [ ] Admin user created with secure password
- [ ] Database indexes verified
- [ ] Backup strategy in place

### Application

- [ ] Health check endpoint responding
- [ ] API endpoints working correctly
- [ ] Admin panel accessible
- [ ] Authentication system working
- [ ] Media upload functionality tested
- [ ] Cache system operational

### Security

- [ ] HTTPS enforced (no HTTP access)
- [ ] Strong Better Auth secret configured (BETTER_AUTH_SECRET)
- [ ] CORS properly configured
- [ ] Rate limiting enabled (if applicable)
- [ ] Security headers configured
- [ ] Admin password is strong and unique

### Performance

- [ ] Cache headers configured
- [ ] Static assets compressed
- [ ] Database queries optimized
- [ ] KV cache working correctly
- [ ] R2 CDN domain configured (if needed)

### Monitoring

- [ ] Error logging configured
- [ ] Performance monitoring enabled
- [ ] Uptime monitoring setup
- [ ] Alert notifications configured
- [ ] Log retention policy set

### Documentation

- [ ] Deployment process documented
- [ ] Environment variables documented
- [ ] Rollback procedure documented
- [ ] Team access configured
- [ ] Support contacts documented

### Testing

- [ ] End-to-end tests passing
- [ ] Load testing completed
- [ ] Security scan performed
- [ ] Mobile responsiveness verified
- [ ] Cross-browser testing done

## Monitoring and Logging

### Cloudflare Analytics

Access real-time analytics:

```bash
# Via Dashboard:
# Workers & Pages > sonicjs-ai-prod > Analytics
```

Key metrics:
- **Requests**: Total requests and errors
- **Success Rate**: % of successful requests
- **Duration**: P50, P95, P99 response times
- **CPU Time**: Average CPU usage
- **Errors**: Error count and types

### Application Logging

View real-time logs:

```bash
# Tail production logs
wrangler tail --env production

# Filter by status
wrangler tail --env production --status error

# Filter by request method
wrangler tail --env production --method POST

# Sample rate (10%)
wrangler tail --env production --sampling-rate 0.1
```

### Structured Logging

SonicJS uses structured JSON logging:

```typescript
// Example log format
console.log(JSON.stringify({
  level: 'info',
  message: 'Content created',
  userId: 'user-123',
  contentId: 'content-456',
  timestamp: new Date().toISOString(),
  requestId: crypto.randomUUID()
}))
```

### Health Check Monitoring

Set up external monitoring for the health endpoint:

```bash
# Health check endpoint
GET https://yourdomain.com/api/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00.000Z",
  "schemas": ["users", "collections", "content", "media", "plugins"]
}
```

Recommended monitoring services:
- **UptimeRobot**: https://uptimerobot.com
- **Pingdom**: https://www.pingdom.com
- **Better Uptime**: https://betteruptime.com

### Error Tracking

Integration with error tracking services:

```typescript
// Sentry integration example
import * as Sentry from '@sentry/cloudflare'

Sentry.init({
  dsn: env.SENTRY_DSN,
  environment: env.ENVIRONMENT,
  tracesSampleRate: 0.1
})

// Capture errors
try {
  // Application code
} catch (error) {
  Sentry.captureException(error)
  throw error
}
```

### Custom Metrics

Track custom metrics using Workers Analytics Engine:

```typescript
// Track API usage
c.env.ANALYTICS.writeDataPoint({
  blobs: ['api_request', endpoint],
  doubles: [responseTime, statusCode],
  indexes: [userId]
})
```

### Log Retention

Cloudflare Workers logs retention:
- **Free Plan**: Last 1 hour
- **Paid Plan**: Last 24 hours
- **Enterprise**: Customizable

For long-term storage, forward logs to:
- **Cloudflare Logpush**: S3, GCS, Azure
- **Datadog**: Real-time monitoring
- **New Relic**: Application performance
- **Splunk**: Log aggregation

## Rollback Procedures

### Viewing Deployment History

```bash
# List recent deployments
wrangler deployments list --env production

# Output:
# Created       ID                Version
# 2024-01-15    abc123            v1.2.3  (current)
# 2024-01-14    def456            v1.2.2
# 2024-01-13    ghi789            v1.2.1
```

### Rollback to Previous Version

```bash
# Option 1: Rollback to previous deployment
wrangler rollback --env production

# This will rollback to: v1.2.2

# Option 2: Rollback to specific version
wrangler rollback --message "Rolling back to v1.2.1" --env production --deployment-id ghi789

# Verify rollback
curl https://yourdomain.com/api/health
```

### Rollback with Database Migrations

If the new version included database migrations:

```bash
# 1. Export current database
wrangler d1 export sonicjs-ai --env production --output backup-before-rollback.sql

# 2. Rollback Worker deployment
wrangler rollback --env production

# 3. If needed, manually revert migrations
# Check which migrations to revert:
wrangler d1 migrations list DB --env production

# No automatic down migrations in D1
# Manual SQL required for schema changes
```

### Emergency Rollback Procedure

```bash
#!/bin/bash
# emergency-rollback.sh

echo "Starting emergency rollback..."

# 1. Backup current state
echo "Creating backup..."
wrangler d1 export sonicjs-ai --env production --output "emergency-backup-$(date +%Y%m%d-%H%M%S).sql"

# 2. Rollback deployment
echo "Rolling back deployment..."
wrangler rollback --env production

# 3. Clear cache
echo "Clearing KV cache..."
wrangler kv:key list --binding CACHE_KV --env production | \
  jq -r '.[].name' | \
  xargs -I {} wrangler kv:key delete --binding CACHE_KV --env production {}

# 4. Verify health
echo "Verifying health..."
curl -f https://yourdomain.com/api/health || echo "❌ Health check failed"

echo "Rollback complete"
```

### Canary Deployments

For safer deployments, use gradual rollout:

```bash
# Deploy to preview first
wrangler deploy --env preview

# Test preview thoroughly
curl https://sonicjs-ai-preview.workers.dev/api/health

# If successful, deploy to production
wrangler deploy --env production

# Monitor for 5-10 minutes
wrangler tail --env production --status error

# If issues detected, rollback immediately
wrangler rollback --env production
```

## Performance Optimization

### Caching Strategy

SonicJS implements multi-layer caching:

```typescript
// 1. Edge Cache (Cloudflare CDN)
// Static assets cached automatically

// 2. KV Cache (SonicJS Cache Plugin)
// API responses, collections, content
const cache = getCacheService(CACHE_CONFIGS.api!)
const cacheKey = cache.generateKey('collections', 'all')
const result = await cache.getWithSource(cacheKey)

// 3. D1 Prepared Statements
// Queries are compiled and cached
const stmt = db.prepare('SELECT * FROM collections WHERE is_active = 1')
```

### Cache Configuration

```typescript
// Cache TTL settings in src/plugins/cache/index.ts
export const CACHE_CONFIGS = {
  api: {
    defaultTTL: 300,        // 5 minutes
    maxTTL: 3600,           // 1 hour
    staleWhileRevalidate: true
  },
  content: {
    defaultTTL: 600,        // 10 minutes
    maxTTL: 86400           // 24 hours
  }
}
```

### Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);
CREATE INDEX IF NOT EXISTS idx_content_collection ON content(collection_id);
CREATE INDEX IF NOT EXISTS idx_content_slug ON content(slug);
CREATE INDEX IF NOT EXISTS idx_media_folder ON media(folder);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_collections_name ON collections(name);

-- Use prepared statements (automatic in Drizzle ORM)
-- Queries are compiled once and reused
```

### Asset Optimization

```toml
# Compress responses
[build]
command = "npm run build"

[build.upload]
format = "modules"

# Enable compression
[[build.upload.rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallthrough = true
```

### R2 with Cloudflare CDN

```bash
# Configure custom domain for R2
# Dashboard > R2 > sonicjs-media-prod > Settings
# Add custom domain: media.yourdomain.com

# Benefits:
# - Global CDN caching
# - Reduced R2 egress costs
# - Faster media delivery
# - Custom cache rules
```

### Worker Size Optimization

```bash
# Check bundle size
wrangler deploy --dry-run --env production --outdir dist

# Optimize:
# 1. Remove unused dependencies
# 2. Use tree-shaking
# 3. Minimize imports
# 4. Lazy load routes

# Current size limit: 10 MB (free), 25 MB (paid)
```

### Response Time Optimization

```typescript
// Add timing headers
apiRoutes.use('*', async (c, next) => {
  const startTime = Date.now()
  await next()
  const totalTime = Date.now() - startTime
  c.header('X-Response-Time', `${totalTime}ms`)
})

// Parallel queries
const [collections, content] = await Promise.all([
  db.select().from(collections),
  db.select().from(content)
])
```

### Geographic Distribution

Cloudflare Workers run at 300+ locations:

```
┌─────────────────────────────────────────┐
│  Request → Nearest Edge Location        │
│  ↓                                       │
│  Worker executes locally                │
│  ↓                                       │
│  D1 query → Nearest D1 location         │
│  ↓                                       │
│  Response cached at edge                │
└─────────────────────────────────────────┘

Result: <50ms response times globally
```

## CI/CD with GitHub Actions

While SonicJS doesn't currently include GitHub Actions workflows, here's a recommended setup:

### Basic Deployment Workflow

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Cloudflare Workers

on:
  push:
    branches:
      - main
      - develop
  pull_request:
    branches:
      - main

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

      - name: Build
        run: npm run build

  deploy-preview:
    needs: test
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Deploy to Preview
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: deploy --env preview

  deploy-production:
    needs: test
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://yourdomain.com
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Run database migrations
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: d1 migrations apply DB --env production

      - name: Deploy to Production
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: deploy --env production

      - name: Verify deployment
        run: |
          curl -f https://yourdomain.com/api/health || exit 1
```

### Database Backup Workflow

Create `.github/workflows/backup.yml`:

```yaml
name: Database Backup

on:
  schedule:
    # Daily at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install Wrangler
        run: npm install -g wrangler@latest

      - name: Backup Database
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        run: |
          DATE=$(date +%Y%m%d-%H%M%S)
          wrangler d1 export sonicjs-ai --env production --output "backup-$DATE.sql"

      - name: Upload to S3
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Copy to S3
        run: |
          DATE=$(date +%Y%m%d-%H%M%S)
          aws s3 cp "backup-$DATE.sql" "s3://your-backup-bucket/sonicjs-backups/"
```

### Required GitHub Secrets

Add these secrets in GitHub Settings > Secrets:

```bash
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
CLOUDFLARE_ACCOUNT_ID=your-cloudflare-account-id
AWS_ACCESS_KEY_ID=your-aws-key (for backups)
AWS_SECRET_ACCESS_KEY=your-aws-secret (for backups)
```

Generate Cloudflare API token:
1. Go to Cloudflare Dashboard > My Profile > API Tokens
2. Create Token > Custom Token
3. Permissions:
   - Account > Workers Scripts > Edit
   - Account > D1 > Edit
   - Zone > Workers Routes > Edit

### Environment Protection Rules

Configure in GitHub Settings > Environments > production:
- Required reviewers: Add team members
- Wait timer: 5 minutes
- Deployment branches: Only `main`

## Troubleshooting

### Common Deployment Issues

#### Issue: Database Connection Errors

```bash
# Symptom
Error: D1_ERROR: no such table: users

# Solution
# Apply migrations
wrangler d1 migrations apply DB --env production

# Verify tables exist
wrangler d1 execute sonicjs-ai --env production --command="SELECT name FROM sqlite_master WHERE type='table';"
```

#### Issue: Secrets Not Found

```bash
# Symptom
Error: Uncaught ReferenceError: BETTER_AUTH_SECRET is not defined

# Solution
# List secrets
wrangler secret list --env production

# Add required auth secrets
openssl rand -base64 32 | wrangler secret put BETTER_AUTH_SECRET --env production
wrangler secret put BETTER_AUTH_URL --env production
```

#### Issue: R2 Bucket Access Denied

```bash
# Symptom
Error: R2 bucket 'sonicjs-media-prod' not found

# Solution
# Verify bucket exists
wrangler r2 bucket list

# Create if missing
wrangler r2 bucket create sonicjs-media-prod

# Verify binding in wrangler.toml
[[env.production.r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "sonicjs-media-prod"
```

#### Issue: KV Namespace Errors

```bash
# Symptom
Error: KV namespace binding 'CACHE_KV' not found

# Solution
# List namespaces
wrangler kv:namespace list

# Create if missing
wrangler kv:namespace create "CACHE_KV" --env production

# Update wrangler.toml with the ID
```

### Performance Issues

#### Slow Database Queries

```sql
-- Add missing indexes
CREATE INDEX idx_content_status ON content(status);
CREATE INDEX idx_content_collection ON content(collection_id);

-- Analyze query performance
EXPLAIN QUERY PLAN SELECT * FROM content WHERE status = 'published';
```

#### High Memory Usage

```bash
# Check Worker size
wrangler deploy --dry-run --env production

# Optimize bundle
# - Remove unused dependencies
# - Use dynamic imports
# - Minimize vendor code
```

#### Cache Not Working

```bash
# Clear KV cache
wrangler kv:key list --binding CACHE_KV --env production

# Delete all cache keys
wrangler kv:key delete --binding CACHE_KV --env production "cache:api:collections:all"

# Verify cache headers
curl -I https://yourdomain.com/api/collections | grep -i cache
```

### Domain and SSL Issues

#### SSL Certificate Errors

```bash
# Check SSL status
curl -vI https://yourdomain.com 2>&1 | grep -i ssl

# Solutions:
# 1. Wait for certificate issuance (up to 24 hours)
# 2. Verify domain is proxied (orange cloud)
# 3. Check SSL/TLS mode is "Full (strict)"
```

#### Domain Not Routing

```bash
# Verify DNS
dig yourdomain.com

# Check Worker routes
wrangler routes list

# Verify route in wrangler.toml
[env.production]
routes = [
  { pattern = "yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

### Debugging Production

```bash
# Real-time logs
wrangler tail --env production

# Filter errors only
wrangler tail --env production --status error

# Filter by method
wrangler tail --env production --method POST

# Sample logs (10%)
wrangler tail --env production --sampling-rate 0.1
```

### Getting Help

- **Cloudflare Community**: https://community.cloudflare.com
- **Discord**: https://discord.gg/cloudflaredev
- **Cloudflare Docs**: https://developers.cloudflare.com/workers
- **SonicJS Issues**: https://github.com/lane711/sonicjs/issues
- **Stack Overflow**: Tag `cloudflare-workers`

### Support Contacts

```bash
# Check Cloudflare status
https://www.cloudflarestatus.com

# Open support ticket
# Dashboard > Support > Contact Support

# Emergency: For production outages with paid plan
```

## Related Documentation

- [Getting Started Guide](getting-started.md) - Initial setup and local development
- [Database Documentation](database.md) - Schema design and migrations
- [API Documentation](../api/) - REST API endpoints and usage
- [Configuration Guide](configuration.md) - Environment variables and settings
- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/) - Official platform docs
- [Cloudflare D1 Docs](https://developers.cloudflare.com/d1/) - Database documentation
- [Cloudflare R2 Docs](https://developers.cloudflare.com/r2/) - Object storage documentation

## Deployment Checklist Summary

Quick reference checklist:

```bash
# Infrastructure Setup
□ D1 database created and migrated
□ R2 bucket created
□ KV namespace created
□ Secrets configured
□ Custom domain added

# Deployment
□ Tests passing
□ Build successful
□ Deployed to preview
□ Deployed to production
□ Health check passing

# Verification
□ API endpoints working
□ Admin panel accessible
□ Media uploads working
□ Cache functioning
□ SSL active

# Monitoring
□ Logs monitoring setup
□ Error tracking configured
□ Uptime monitoring active
□ Backup automation running
```

---

**Need help?** Check the [Troubleshooting](#troubleshooting) section or reach out to the community.
