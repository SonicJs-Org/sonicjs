# SonicJS

[![GitHub stars](https://img.shields.io/github/stars/lane711/sonicjs?style=social)](https://github.com/lane711/sonicjs)
[![npm downloads](https://img.shields.io/npm/dm/@sonicjs-cms/core.svg)](https://www.npmjs.com/package/@sonicjs-cms/core)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/lane711/sonicjs)](https://github.com/lane711/sonicjs/commits)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-5865F2?logo=discord&logoColor=white)](https://discord.gg/8bMy6bv3sZ)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![PR Tests](https://github.com/lane711/sonicjs/actions/workflows/pr-tests.yml/badge.svg)](https://github.com/lane711/sonicjs/actions/workflows/pr-tests.yml)
[![codecov](https://codecov.io/gh/SonicJs-Org/sonicjs/branch/main/graph/badge.svg)](https://codecov.io/gh/SonicJs-Org/sonicjs)
[![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Flane711%2F4fc1969ff683812bc49788d43fb4d7e2%2Fraw%2Ftest-count.json)](https://github.com/lane711/sonicjs)
[![npm version](https://img.shields.io/npm/v/@sonicjs-cms/core.svg)](https://www.npmjs.com/package/@sonicjs-cms/core)

**The only headless CMS born on the edge.** Zero cold starts. 15–50ms API responses. 300+ global locations. TypeScript-first. 100% MIT open source — every feature free, no Enterprise gate, ever.

**[sonicjs.com](https://sonicjs.com)**

## 📦 Get Started

```bash
npx create-sonicjs@latest my-app
```

$0 to start · No signup required · Runs anywhere SQLite runs

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/lane711)
[![Open Collective](https://img.shields.io/badge/Open_Collective-Support-7FADF2?style=for-the-badge&logo=opencollective)](https://opencollective.com/sonicjs)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/lane711/sonicjs-deploy-now)

> **⚠️ Note:** This repository is for **developing the SonicJS core package**. To build an application with SonicJS, use the command above to create a new project.

## 🐳 Self-Hosting with Docker

No Cloudflare account? Run SonicJS on any server with Docker and SQLite:

```bash
docker build -t sonicjs .
docker run -d --name sonicjs -p 3000:3000 \
  -v $(pwd)/data:/app/data \
  -e JWT_SECRET=$(openssl rand -base64 32) \
  -e BETTER_AUTH_SECRET=$(openssl rand -base64 32) \
  sonicjs

# Create the first admin user
docker exec sonicjs npm run reset
# → admin@sonicjs.com / sonicjs! (change after first login)
```

See the [Self-Hosting guide](https://sonicjs.com/self-hosting) for Docker Compose, Node.js, backup strategy, and production hardening.

## 🚀 Features

### Edge Performance
- **⚡ Zero Cold Starts**: 0–5ms cold start vs 500–2000ms on Node.js CMSs
- **🌍 Global by Default**: 300+ edge locations — not one region, one continent
- **🚀 Sub-50ms APIs**: 15–50ms API responses vs 1–4s with relations elsewhere
- **📈 Auto-Scaling**: Cloudflare handles traffic spikes — no ops required

### Developer Experience
- **🔧 Schema-as-Code**: Define your content model in TypeScript; SonicJS generates the REST API and admin UI
- **📦 `create-sonicjs` CLI**: From schema to global API in minutes
- **🔥 Hot Reload**: Fast local development with Wrangler
- **📱 Modern Stack**: Hono.js, TypeScript, D1, R2, HTMX

### AI-Native Content Layer
- **🤖 Native MCP Server**: Auto-generated tools let Claude Code, Cursor, and VS Code read, create, and publish content
- **🔍 RAG-Powered Search**: Semantic search with natural-language queries — zero extra infra
- **🛠 12 Specialized Claude Code Agents**: Purpose-built agents for development ([View all agents](https://sonicjs.com/ai-agents))

### Content Management
- **📝 Rich Text Editor**: TinyMCE integration with customizable toolbars
- **🎛️ Dynamic Fields**: Text, number, date, boolean, select, media, slug, and more
- **📚 Content Versioning**: Complete revision history with restore — free, no paywall
- **⏰ Content Scheduling**: Publish/unpublish automation with date controls
- **🔄 Draft → Published Workflow**: Role-based permissions throughout
- **💾 Auto-Save**: Automatic content saving every 30 seconds
- **🛡️ XSS Protection**: Comprehensive input validation and HTML escaping

### No Lock-In, No Paywalls
- **100% MIT**: Every feature in the core. No Growth tier. No Enterprise gate. Ever.
- **No VC Clock**: No license rug-pull. No infra lock-in.
- **Runs Anywhere**: Edge-native on Cloudflare Workers, or self-host on Docker/VPS — anywhere SQLite runs.

## 📊 How SonicJS Compares

| | SonicJS | Strapi | Payload |
|--|---------|--------|---------|
| **Edge-native** | ✅ Yes | ❌ No | ❌ No |
| **Cold start** | 0–5ms | 500–2000ms | 500–2000ms |
| **API response** | 15–50ms | 1–4s | 1–4s |
| **Global locations** | 300+ | 1 region | 1 region |
| **Version history** | Free | Paywalled | Paywalled |
| **SSO / Audit logs** | Free | $99+/mo | $99+/mo |
| **AI / MCP** | Included | Upsold | Upsold |
| **License** | MIT (all features) | MIT (limited) | MIT (limited) |

> SonicJS is the **only production-ready CMS** built specifically for edge computing.

## 🛠 Technology Stack

### Core Framework
- **Hono.js** - Ultrafast web framework for Cloudflare Workers
- **TypeScript** - Strict type safety throughout
- **HTMX** - Enhanced HTML for dynamic interfaces

### Cloudflare Services
- **D1** - SQLite database at the edge
- **R2** - Object storage for media
- **Workers** - Serverless compute runtime
- **KV** - Key-value storage for caching
- **Images API** - Image optimization and transformation

### Development Tools
- **Vitest** - Fast unit testing
- **Playwright** - End-to-end testing
- **Wrangler** - Local development and deployment
- **Drizzle ORM** - Type-safe database queries

## 🏁 Quick Start

### For Application Developers (Using SonicJS)

```bash
# Create a new SonicJS application
npx create-sonicjs@latest my-app

cd my-app
npm run dev

# Visit http://localhost:8787
```

Your app includes:
- ✅ SonicJS CMS pre-configured
- ✅ Database migrations ready
- ✅ Example content collections
- ✅ Admin interface at `/admin`
- ✅ Ready to deploy to Cloudflare

### For Package Developers (Contributing to SonicJS)

```bash
# Clone this repository
git clone https://github.com/lane711/sonicjs.git
cd sonicjs

# Install dependencies
npm install

# Build the core package
npm run build:core

# Create a test app to validate changes
npx create-sonicjs@latest my-sonicjs-app

# Run tests
npm test
```

#### Setting Up a Fresh Database

```bash
# Create a fresh D1 database for your branch (run from project root)
npm run db:reset
```

This creates a new D1 database named `sonicjs-worktree-<branch-name>`, applies all migrations, and updates `wrangler.toml`.

#### Working with Database Migrations

Migrations live in `packages/core/migrations/`. Test apps reference them via npm workspace symlink.

**From your test app directory** (e.g., `my-sonicjs-app/`):

```bash
# Check migration status
wrangler d1 migrations list DB --local

# Apply pending migrations
wrangler d1 migrations apply DB --local

# Apply to production
wrangler d1 migrations apply DB --remote
```

**Creating New Migrations:**

SonicJS bundles migrations at build time (Workers can't access the filesystem at runtime).

1. Create `packages/core/migrations/NNN_description.sql` (use `CREATE TABLE IF NOT EXISTS` and `INSERT OR IGNORE` for idempotency)
2. Regenerate bundle: `cd packages/core && npm run generate:migrations`
3. Rebuild: `npm run build:core`
4. Apply locally: `cd my-sonicjs-app && wrangler d1 migrations apply DB --local`

### Common Commands

```bash
npm run dev          # Start dev server
npm run deploy       # Deploy to Cloudflare
npm run db:migrate   # Apply migrations
npm run db:studio    # Open database studio
npm test             # Run tests
```

## 📁 Project Structure

```
sonicjs/
├── packages/
│   ├── core/              # 📦 Main CMS package (@sonicjs-cms/core)
│   │   ├── src/
│   │   │   ├── routes/    # Route handlers (admin, API, auth)
│   │   │   ├── templates/ # HTML templates & components
│   │   │   ├── middleware/# Authentication & middleware
│   │   │   ├── utils/     # Utility functions
│   │   │   └── db/        # Database schemas & migrations
│   │   └── package.json
│   ├── templates/         # Template system package
│   └── scripts/           # Build scripts & generators
│
├── my-sonicjs-app/        # 🧪 Test application (gitignored)
│                          # Created with: npx create-sonicjs@latest
│
├── www/                   # 🌐 Marketing website
└── tests/e2e/             # End-to-end test suites
```

⚠️ **This is NOT an application repository** — it's for developing the `@sonicjs-cms/core` npm package.

## 🔧 Content Management

### Creating Collections

Collections are TypeScript config objects registered at app startup — no database table required.

```typescript
// src/collections/blog-posts.collection.ts
import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'blog_post',
  displayName: 'Blog Post',
  slug: 'blog-posts',
  description: 'Article content collection',

  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true, maxLength: 200 },
      content: { type: 'lexical', title: 'Content', required: true },
      publishedAt: { type: 'datetime', title: 'Published Date' },
    },
    required: ['title', 'content'],
  },

  managed: true,
  isActive: true,
} satisfies CollectionConfig
```

```typescript
// src/index.ts — register before createSonicJSApp
import { registerCollections, createSonicJSApp } from '@sonicjs-cms/core'
import blogPostsCollection from './collections/blog-posts.collection'

registerCollections([blogPostsCollection])
export default createSonicJSApp({ plugins: { register: [] } })
```

### Field Types
- **string**: Single-line text with validation
- **lexical**: Rich text editor
- **number**: Numeric input with min/max constraints
- **boolean**: Checkbox with custom labels
- **datetime**: Date/time picker
- **select**: Dropdown with single/multi-select
- **slug**: URL slug with auto-generation
- **user**: User reference picker
- **media**: File picker with preview

## 🌐 API Endpoints

### Content Management
- `GET /admin/content/new?collection=id` - Create new content form
- `GET /admin/content/:id/edit` - Edit content form
- `POST /admin/content/` - Create content
- `PUT /admin/content/:id` - Update content with versioning
- `DELETE /admin/content/:id` - Delete content

### Advanced Features
- `POST /admin/content/preview` - Preview before publishing
- `POST /admin/content/duplicate` - Duplicate content
- `GET /admin/content/:id/versions` - Version history
- `POST /admin/content/:id/restore/:version` - Restore version

### Public API
- `GET /api/content` - Get published content (paginated)
- `GET /api/collections/:collection/content` - Get content by collection
- `GET /api/collections` - List all collections

## 🚀 Deployment

```bash
# 1. Update wrangler.toml with your project settings

# 2. Create production database
wrangler d1 create my-app-db

# 3. Apply migrations
npm run db:migrate:prod

# 4. Deploy
npm run deploy
```

Your app will be live at `https://your-app.workers.dev`.

### Environment Configuration

```toml
# wrangler.toml
name = "my-sonicjs-app"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "DB"
database_name = "my-app-db"
database_id = "your-database-id"

[[r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "my-app-media"
```

## 🧪 Testing

```bash
npm test                # Unit tests
npm run test:watch      # Watch mode
npm run test:e2e        # E2E tests
npm run test:e2e:ui     # E2E with UI
```

## 🔌 Plugin Development

```typescript
// src/plugins/my-plugin/index.ts
import type { Plugin, PluginContext } from '@sonicjs-cms/core'

export default {
  name: 'my-plugin',
  version: '1.0.0',
  description: 'My custom plugin',

  async activate(context: PluginContext) {
    // Runs when the plugin is activated
  },

  async install(context: PluginContext) {
    // Runs once on install — migrations, seed data, etc.
  },
} satisfies Plugin
```

## 📚 Documentation

- [sonicjs.com](https://sonicjs.com) - Full documentation
- [AI Agents](https://sonicjs.com/ai-agents) - 12 specialized Claude Code agents
- [Self-Hosting](https://sonicjs.com/self-hosting) - Docker, VPS, production hardening
- [Contributing](https://sonicjs.com/contributing) - Contribution guidelines

## ❤️ Sponsor

SonicJS is 100% open source and free forever. If you find it useful, consider sponsoring:

[![Sponsor on GitHub](https://img.shields.io/badge/Sponsor_on_GitHub-%E2%9D%A4-pink?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/lane711)
[![Support on Open Collective](https://img.shields.io/badge/Open_Collective-Support-7FADF2?style=for-the-badge&logo=opencollective)](https://opencollective.com/sonicjs)

100% of sponsorship funds go to marketing — spreading the word about SonicJS to grow the community.

> SonicJS is a member of [Open Source Collective](https://opencollective.com/sonicjs), a 501(c)(3) nonprofit. Donations are tax-deductible for US contributors.

### Thank You to Our Sponsors

<a href="https://github.com/mmcintosh"><img src="https://github.com/mmcintosh.png" width="60" alt="@mmcintosh" /></a>

## 📞 Support

- [GitHub Issues](https://github.com/lane711/sonicjs/issues)
- [Community Discussions](https://github.com/lane711/sonicjs/discussions)
- [Discord](https://discord.gg/8bMy6bv3sZ)

---

Built with ❤️ for the Cloudflare ecosystem · [sonicjs.com](https://sonicjs.com)
