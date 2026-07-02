# Getting Started with SonicJS AI

**SonicJS AI v2.0.0** is a modern, TypeScript-first headless CMS built for Cloudflare's edge platform. This comprehensive guide will help you set up, configure, and start building with SonicJS.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Core Concepts](#core-concepts)
- [First Steps](#first-steps)
- [Available Scripts](#available-scripts)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (version 18 or higher)
- **npm** or **pnpm**
- **Git**
- **Cloudflare account** (for deployment and production use)

### Recommended Tools

- **TypeScript** knowledge (project is fully typed)
- **Visual Studio Code** (for best TypeScript experience)
- **Wrangler CLI** (installed automatically with dependencies)

## Quick Start

### Option 1: Create New Project (Recommended)

Get started in under 60 seconds with the official CLI:

```bash
# Create a new SonicJS project
npx create-sonicjs my-cms

# Navigate to project
cd my-cms

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

Your SonicJS instance will be available at **<http://localhost:8787>**

### Option 2: Clone Repository (Development)

For contributing or developing SonicJS itself:

```bash
# Clone the repository
git clone https://github.com/lane711/sonicjs-ai.git
cd sonicjs-ai

# Install dependencies
npm install

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/lane711/sonicjs-ai.git
cd sonicjs-ai
```

### 2. Install Dependencies

```bash
npm install
```

This will install all required dependencies including:

- **Hono** - Ultra-fast web framework
- **Drizzle ORM** - Type-safe database queries
- **Wrangler** - Cloudflare Workers CLI
- **Vitest** - Unit testing framework
- **Playwright** - E2E testing framework

### 3. Database Setup

SonicJS uses Cloudflare D1 (SQLite) for local development and production.

**Run migrations locally:**

```bash
npm run db:migrate
```

This command applies all database migrations and creates the initial schema including:

- User authentication tables
- Content and collections
- Media library
- Plugin system
- Workflow and automation
- Email templates

**Available database commands:**

```bash
# Generate new migration files (if you modify schema)
npm run db:generate

# Apply migrations to local database
npm run db:migrate

# Apply migrations to production
npm run db:migrate:prod

# Open interactive database studio (Drizzle Studio)
npm run db:studio
```

### 4. Environment Configuration

SonicJS is configured via **wrangler.toml** instead of .env files.

**wrangler.toml** (automatically configured):

```toml
name = "sonicjs-ai"
main = "src/index.ts"
compatibility_date = "2024-06-01"

[vars]
ENVIRONMENT = "development"
# Add every frontend origin that needs cross-origin API/auth access (comma-separated)
CORS_ORIGINS = "http://localhost:8787,http://localhost:4321"

[[d1_databases]]
binding = "DB"
database_name = "sonicjs-dev"
database_id = "your-database-id"

[[r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "sonicjs-media-dev"

[[kv_namespaces]]
binding = "CACHE_KV"
id = "your-kv-id"
```

**Key Bindings:**

- **DB** - D1 Database for all data storage
- **MEDIA_BUCKET** - R2 bucket for media files
- **CACHE_KV** - KV namespace for caching layer
- **ASSETS** - Static asset serving

### 5. Start Development Server

```bash
npm run dev
```

**What happens on startup:**

1. **Bootstrap Phase:**
   - Runs database migrations
   - Syncs collection configurations
   - Bootstraps core plugins (auth, media, cache, database-tools, seed-data)
   - Installs demo plugins (workflow, FAQ, demo-login)

2. **Server Ready:**
   - Admin interface: <http://localhost:8787/admin>
   - API documentation: <http://localhost:8787/api>
   - Health check: <http://localhost:8787/health>

## Project Structure

```
sonicjs-ai/
├── docs/                      # Documentation (you are here!)
├── src/
│   ├── index.ts              # Application entry point
│   ├── middleware/           # Request middleware
│   │   ├── auth.ts          # JWT authentication
│   │   ├── bootstrap.ts     # App initialization
│   │   ├── logging.ts       # Request/security logging
│   │   ├── performance.ts   # Cache headers & optimization
│   │   ├── permissions.ts   # RBAC authorization
│   │   └── plugin-middleware.ts
│   ├── routes/              # HTTP routes
│   │   ├── admin.ts        # Admin dashboard
│   │   ├── api.ts          # Public API
│   │   ├── auth.ts         # Authentication
│   │   ├── content.ts      # Content endpoints
│   │   ├── media.ts        # Media upload/management
│   │   └── ...
│   ├── services/           # Business logic
│   │   ├── plugin-service.ts
│   │   ├── plugin-bootstrap.ts
│   │   ├── collection-loader.ts
│   │   ├── collection-sync.ts
│   │   ├── migrations.ts
│   │   ├── logger.ts
│   │   └── ...
│   ├── templates/          # HTML templates
│   │   ├── layouts/       # Page layouts
│   │   ├── pages/         # Full page templates
│   │   └── components/    # Reusable UI components
│   ├── plugins/           # Plugin system
│   │   ├── core/          # Plugin architecture
│   │   ├── core-plugins/  # Built-in plugins
│   │   ├── cache/         # Caching plugin
│   │   └── available/     # Optional plugins
│   ├── collections/       # Collection definitions
│   │   ├── blog-posts.collection.ts
│   │   ├── pages.collection.ts
│   │   └── products.collection.ts
│   ├── types/            # TypeScript types
│   └── cli/             # CLI tools
├── migrations/          # D1 database migrations
├── tests/
│   ├── unit/           # Vitest unit tests
│   └── e2e/            # Playwright E2E tests
├── public/             # Static assets
├── wrangler.toml       # Cloudflare Workers config
└── package.json
```

### Key Directories Explained

**`src/middleware/`** - Request processing pipeline:

- Bootstrap → Logging → Auth → Permissions → Routes

**`src/routes/`** - Route handlers organized by domain:

- Public routes (content, auth)
- Admin routes (dashboard, management)
- API routes (RESTful endpoints)

**`src/services/`** - Business logic layer:

- Database operations
- Plugin management
- Collection handling
- Logging and monitoring

**`src/templates/`** - HTMX-powered templates:

- Layouts with navigation/sidebar
- Page templates for admin UI
- Reusable components

**`src/plugins/`** - Extensibility system:

- Core plugin architecture
- Built-in core plugins
- Optional/demo plugins

**`src/collections/`** - Content type definitions:

- TypeScript-based schemas
- Auto-synced to database
- Type-safe content modeling

## Core Concepts

### 1. Cloudflare Workers Architecture

SonicJS runs on Cloudflare's edge network using **V8 isolates** (not containers):

- **Instant cold starts** (< 5ms)
- **Global deployment** (300+ cities)
- **Automatic scaling** (unlimited concurrency)
- **Zero DevOps** (no servers to manage)

**Bindings provide access to:**

- **D1** - Edge-native SQLite database
- **KV** - Global key-value store
- **R2** - S3-compatible object storage
- **Queues** - Async task processing

### 2. Plugin System

SonicJS is built on a powerful plugin architecture:

**Core Plugins** (auto-installed):

- `core-auth` - Authentication & user management
- `core-media` - Media upload & R2 storage
- `core-cache` - Three-tiered caching system
- `database-tools` - DB management utilities
- `seed-data` - Test data generation

**Demo Plugins** (optional):

- `workflow` - Content workflow & scheduling
- `faq-plugin` - FAQ management
- `demo-login-plugin` - Pre-filled login credentials

**Plugin Lifecycle:**

```typescript
// Plugins can hook into application events
install() -> activate() -> [running] -> deactivate() -> uninstall()
```

### 3. Collection System

Collections define your content types using **TypeScript schemas**:

```typescript
// src/collections/blog-posts.collection.ts
export const blogPostsCollection: CollectionConfig = {
  name: 'blog_posts',
  displayName: 'Blog Posts',
  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', required: true },
      slug: { type: 'slug' },
      content: { type: 'richtext' },
      author: { type: 'reference', collection: 'users' },
      publishDate: { type: 'datetime' }
    }
  },
  managed: true,  // Config-managed (read-only in UI)
  isActive: true
}
```

**Automatic Syncing:**

- Collections are TypeScript files in `src/collections/`
- Automatically synced to database on startup
- Type-safe content operations

### 4. Three-Tiered Caching

SonicJS implements intelligent caching across three tiers:

**Tier 1: In-Memory Cache**

- Fastest access (< 1ms)
- 50MB size limit per worker
- LRU eviction policy

**Tier 2: Cloudflare KV**

- Global distribution
- Eventually consistent
- 5-60 minute TTLs

**Tier 3: D1 Database**

- Source of truth
- Strong consistency
- Full query capabilities

**Cache Flow:**

```
Request → Memory → KV → Database → Populate KV → Populate Memory → Response
```

### 5. Authentication & Authorization

**JWT-based Authentication:**

- 24-hour token expiration
- Cookie and header support
- KV-based token caching (5-min TTL)

**Role-Based Access Control (RBAC):**

```typescript
// Require authentication
requireAuth()

// Require specific role
requireRole(['admin', 'editor'])

// Require permission
requirePermission('manage:content')

// Optional authentication
optionalAuth()
```

**User Roles:**

- `admin` - Full system access
- `editor` - Content management
- `author` - Content creation
- `viewer` - Read-only access

## First Steps

### 1. Access the Admin Dashboard

Navigate to **<http://localhost:8787/admin>**

**Default Credentials** (if seed data is loaded):

- Email: <admin@sonicjs.com>
- Password: sonicjs!

**Note:** The `demo-login-plugin` auto-fills these credentials in development.

### 2. Explore the Dashboard

The admin interface provides:

**System Overview:**

- Real-time health checks (D1, KV, R2, Webserver)
- Recent activity feed
- Quick actions

**Content Management:**

- Create/edit/delete content
- Collection-based organization
- Rich text editing with TinyMCE
- Version history
- Workflow states (draft, review, published)

**Media Library:**

- Drag-and-drop upload
- R2 bucket storage
- Cloudflare Images optimization
- Folder organization
- Bulk operations

**User Management:**

- User accounts and roles
- Permission assignment
- Activity logging
- API token generation

**Plugin Management:**

- Install/activate/deactivate plugins
- Plugin settings configuration
- Dependency management
- Activity monitoring

**Cache Dashboard:**

- Real-time statistics
- Hit rate monitoring
- Manual invalidation
- Pattern-based clearing

### 3. Create Your First Content

**Via Admin UI:**

1. Navigate to **Content** → **New Content**
2. Select a collection (e.g., "Blog Posts")
3. Fill in the fields:
   - Title: "My First Post"
   - Slug: "my-first-post" (auto-generated)
   - Content: Write your content
   - Status: "published"
4. Click **Save**

**Via API:**

```bash
# Get auth token
curl -X POST http://localhost:8787/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sonicjs.com","password":"sonicjs!"}'

# Create content
curl -X POST http://localhost:8787/admin/content \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "collection": "blog_posts",
    "title": "My First Post",
    "data": {
      "slug": "my-first-post",
      "content": "<p>Hello World!</p>",
      "status": "published"
    }
  }'
```

### 4. Upload Media Files

**Via Admin UI:**

1. Navigate to **Media**
2. Click **Upload Files** or drag files into the upload zone
3. Select folder destination (optional)
4. Add alt text and captions
5. Files are automatically uploaded to R2

**Via API:**

```bash
curl -X POST http://localhost:8787/media/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "files=@image.jpg" \
  -F "folder=blog-images" \
  -F "alt=My Image"
```

**Supported Formats:**

- Images: JPG, PNG, GIF, WebP, SVG
- Documents: PDF, DOC, DOCX
- Videos: MP4, WebM
- Audio: MP3, WAV

### 5. Explore the API

**API Documentation:**
Visit **<http://localhost:8787/api>** for interactive OpenAPI docs.

**Key Endpoints:**

```bash
# Health check
GET /health

# List collections
GET /api/collections

# Get all content (paginated)
GET /api/content?limit=50

# Get collection content
GET /api/collections/blog_posts/content

# Get single content item
GET /api/content/:id

# Search content
GET /api/content?search=keyword
```

**Response Format:**

```json
{
  "data": [...],
  "meta": {
    "count": 10,
    "timestamp": "2025-10-06T...",
    "cache": {
      "hit": true,
      "source": "memory",
      "ttl": 3598
    },
    "timing": {
      "total": 15,
      "execution": 12,
      "unit": "ms"
    }
  }
}
```

### 6. Create a Custom Collection

**Create a new collection file:**

```typescript
// src/collections/products.collection.ts
import { CollectionConfig } from '../types/collection-config'

export const productsCollection: CollectionConfig = {
  name: 'products',
  displayName: 'Products',
  description: 'E-commerce product catalog',
  schema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        required: true,
        minLength: 3,
        maxLength: 200
      },
      sku: {
        type: 'string',
        required: true,
        pattern: '^[A-Z0-9-]+$'
      },
      price: {
        type: 'number',
        required: true,
        minimum: 0
      },
      description: {
        type: 'richtext'
      },
      images: {
        type: 'array',
        items: {
          type: 'media',
          accept: 'image/*'
        }
      },
      category: {
        type: 'select',
        enum: ['electronics', 'clothing', 'home', 'sports']
      },
      inStock: {
        type: 'boolean',
        default: true
      },
      tags: {
        type: 'array',
        items: { type: 'string' }
      }
    }
  },
  icon: '🛍️',
  color: 'blue',
  managed: true,
  isActive: true,
  defaultSort: 'created_at',
  defaultSortOrder: 'desc',
  listFields: ['name', 'sku', 'price', 'inStock'],
  searchFields: ['name', 'sku', 'description']
}
```

**Sync the collection:**

```bash
# Collections are auto-synced on server restart
npm run dev
```

## Available Scripts

These are the scripts available in your SonicJS application.

### Development

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with Wrangler |
| `npm run deploy` | Deploy to Cloudflare Workers |
| `npm run type-check` | Run TypeScript type checking |

### Database

| Command | Description |
|---------|-------------|
| `npm run db:migrate:local` | Apply migrations to local D1 database |
| `npm run db:migrate` | Apply migrations to remote D1 database |
| `npm run db:reset` | Reset and reinitialize local database |
| `npm run db:studio` | Open Drizzle Studio (database GUI) |

### Testing

| Command | Description |
|---------|-------------|
| `npm test` | Run Vitest unit tests |
| `npm run test:watch` | Run tests in watch mode |

### Updates

| Command | Description |
|---------|-------------|
| `npm run update` | Update @sonicjs-cms/core to latest version |
| `npm run update:beta` | Update to latest beta version |

## Monorepo Scripts (Contributors)

If you're contributing to SonicJS and working in the monorepo, these additional scripts are available at the root level.

### Setup

| Command | Description |
|---------|-------------|
| `npm run workspace` | Fresh workspace setup (install deps + reset database) |
| `npm run db:reset` | Reset the local development database |
| `npm run kill` | Kill workerd process and restart dev server |

### Development

| Command | Description |
|---------|-------------|
| `npm run dev` | Run the demo app (my-sonicjs-app) |
| `npm run dev:www` | Run the documentation website locally |
| `npm run build` | Build core package and demo app |
| `npm run build:core` | Build only the core package |
| `npm run build:www` | Build the documentation website |

### Testing

| Command | Description |
|---------|-------------|
| `npm test` | Run unit tests |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:cov` | Run tests with coverage report |
| `npm run e2e` | Run Playwright E2E tests |
| `npm run e2e:ui` | Run E2E tests with UI mode |
| `npm run e2e:smoke` | Run smoke tests |
| `npm run type-check` | Run TypeScript type checking |
| `npm run lint` | Run linting (alias for type-check) |

### Publishing

| Command | Description |
|---------|-------------|
| `npm run version:patch` | Bump patch version |
| `npm run version:minor` | Bump minor version |
| `npm run version:major` | Bump major version |
| `npm run publish:core` | Build and publish core package |
| `npm run publish:create-app` | Publish create-sonicjs CLI |
| `npm run publish:all` | Publish all packages |
| `npm run release:patch` | Version bump + publish + announce |
| `npm run release:minor` | Version bump + publish + announce |
| `npm run release:major` | Version bump + publish + announce |

### Deployment

| Command | Description |
|---------|-------------|
| `npm run deploy` | Deploy demo app to Cloudflare Workers |
| `npm run deploy:www` | Deploy documentation website |

## Troubleshooting

### Common Issues

#### CORS Errors from a Frontend Framework (Astro, Next.js, etc.)

**Symptom:** Browser console shows `Cross-Origin Request Blocked` or `Access-Control-Allow-Origin` missing when calling `/auth/login` or any API endpoint from a different port.

**Solution:**

Add your frontend origin to `CORS_ORIGINS` in `wrangler.toml` and restart the dev server:

```toml
[vars]
CORS_ORIGINS = "http://localhost:8787,http://localhost:4321"
```

Then ensure your `fetch` calls include `credentials: 'include'`:

```typescript
const res = await fetch('http://localhost:8787/auth/login', {
  method: 'POST',
  credentials: 'include',          // required for session cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
})
```

For production, add your deployed frontend URL to `CORS_ORIGINS` in the `[env.production]` section.

---

#### Database Connection Errors

**Error:** `Error: no such table: users`

**Solution:**

```bash
# Run migrations
npm run db:migrate

# Verify migration status
wrangler d1 migrations list DB --local
```

---

#### Port Already in Use

**Error:** `Error: listen EADDRINUSE: address already in use :::8787`

**Solution:**

```bash
# Find and kill the process using port 8787
lsof -ti:8787 | xargs kill -9

# Or specify a different port in wrangler.toml
# [dev]
# port = 3000
```

---

#### Module Not Found / Import Errors

**Error:** `Cannot find module 'hono'`

**Solution:**

```bash
# Clear and reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Clear TypeScript build cache
rm -rf .wrangler
```

---

#### Plugin Not Discovered

**Error:** Cache plugin not showing in admin

**Solution:**

1. Check plugin is in `CORE_PLUGINS` array (`src/services/plugin-bootstrap.ts`)
2. Verify plugin manifest exists (`src/plugins/cache/manifest.json`)
3. Restart dev server to trigger bootstrap
4. Check bootstrap logs for errors

```bash
# Check bootstrap logs
npm run dev 2>&1 | grep -i "bootstrap\|plugin"
```

---

#### Cache Not Working

**Issue:** Cache statistics show all misses

**Solution:**

1. Verify cache plugin is **activated** in `/admin/plugins`
2. Check KV binding is configured in `wrangler.toml`
3. Ensure routes have caching enabled
4. Review cache configuration in plugin settings

```bash
# Test cache directly
curl http://localhost:8787/api/content
# Check response headers for X-Cache-Status
```

---

#### Media Upload Fails

**Error:** `Failed to upload to R2`

**Solution:**

1. Verify R2 bucket exists and binding is correct in `wrangler.toml`
2. Check bucket permissions
3. Ensure file size is under limits (10MB default for images)
4. Verify MIME type is allowed

```bash
# Test R2 bucket
wrangler r2 bucket list

# Check specific bucket
wrangler r2 bucket info sonicjs-media-dev
```

---

#### TypeScript Errors

**Error:** `Type 'D1Database' is not assignable to...`

**Solution:**

```bash
# Update Cloudflare Workers types
npm install --save-dev @cloudflare/workers-types@latest

# Regenerate TypeScript definitions
npx tsc --noEmit
```

---

#### Wrangler Build Failures

**Error:** `Build failed: Could not resolve...`

**Solution:**

1. Ensure `compatibility_flags = ["nodejs_compat"]` is in `wrangler.toml`
2. Check for incompatible Node.js modules
3. Verify all imports use explicit extensions for TypeScript

```toml
# wrangler.toml
compatibility_flags = ["nodejs_compat"]
compatibility_date = "2024-06-01"
```

---

### Development Tips

**Hot Reload Issues:**

If changes aren't reflected:

1. Stop dev server (Ctrl+C)
2. Clear Wrangler cache: `rm -rf .wrangler`
3. Restart: `npm run dev`

**Database Schema Changes:**

When modifying the database schema:

1. Update migration files in `migrations/`
2. Run `npm run db:migrate`
3. Update TypeScript types if needed
4. Restart dev server

**Collection Changes:**

When modifying collections:

1. Edit collection file in `src/collections/`
2. Run `npm run sync-collections`
3. Or restart dev server (auto-syncs)

**Plugin Development:**

When creating new plugins:

1. Add plugin to appropriate directory
2. Register in plugin registry
3. Create manifest.json
4. Restart to trigger bootstrap
5. Activate in `/admin/plugins`

### Getting Help

**Resources:**

- 📚 [Full Documentation](https://docs.sonicjs.com)
- 🐛 [GitHub Issues](https://github.com/lane711/sonicjs-ai/issues)
- 💬 [Discussions](https://github.com/lane711/sonicjs-ai/discussions)
- 📖 [API Reference](/docs/api-reference)
- 🏗️ [Architecture Guide](/docs/architecture)

**Report Bugs:**

```bash
# Include this information
1. SonicJS version (check package.json)
2. Node.js version (node --version)
3. Operating system
4. Error message and stack trace
5. Steps to reproduce
```

## Next Steps

Now that you have SonicJS running, explore these guides:

### Essential Reading

1. **[Architecture Overview](/docs/architecture)** - Understand the system design
2. **[Plugin Development](/docs/plugins/plugin-development-guide)** - Build custom plugins
3. **[Collection Configuration](/docs/collections-config)** - Define content types
4. **[API Reference](/docs/api-reference)** - Integrate with your frontend

### Advanced Topics

5. **[Caching System](/docs/caching)** - Optimize performance
6. **[Authentication](/docs/authentication)** - Secure your application
7. **[Templating](/docs/templating)** - Customize the admin UI
8. **[Deployment](/docs/deployment)** - Deploy to production

### Practical Guides

9. **[Testing](/docs/testing)** - Write unit and E2E tests
10. **[Database Management](/docs/database)** - Work with D1 and migrations
11. **[Media Management](/docs/media)** - Handle uploads and R2 storage
12. **[Workflow System](/docs/workflow)** - Implement content workflows

---

**Ready to build something amazing? 🚀**

Start with [Creating Your First Plugin](/docs/plugins/plugin-development-guide) or explore the [API Documentation](/docs/api-reference).
