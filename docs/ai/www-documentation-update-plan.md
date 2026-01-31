# SonicJS Documentation Site Update Plan

**Date**: October 24, 2025
**Purpose**: Update the www documentation site to reflect the current state of the SonicJS AI repository
**Location**: `/Users/lane/Dev/refs/sonicjs-ai/www/`

## Executive Summary

The SonicJS documentation site (www folder) needs a comprehensive update to align with the current repository structure, completed development stages, and new features. This plan outlines a systematic approach to updating all documentation pages, creating new content, and ensuring the documentation site accurately represents SonicJS AI v2.0.

## Current State Analysis

### Existing Documentation Site (www/)
- **Tech Stack**: Next.js 15, MDX, Tailwind CSS, deployed to Cloudflare Pages
- **Structure**: `/www/src/app/` contains MDX pages organized by topic
- **Features**: Full-text search (FlexSearch), dark mode, syntax highlighting, responsive design
- **Current Pages**: Homepage, quickstart, architecture, authentication, collections, API, deployment, caching, and various placeholder pages

### Current Repository State
- **Version**: 2.0.0-alpha.8
- **Monorepo Structure**: Main app + packages/core + www documentation site
- **Completed Stages**: 1-7 (Foundation through Workflow & Automation)
- **Core Features**:
  - Edge-first CMS on Cloudflare Workers
  - Plugin system with core and demo plugins
  - Content management with versioning
  - Media management with R2 storage
  - Workflow system with scheduling
  - Three-tiered caching
  - Session-based authentication (Better Auth) with RBAC

### Gap Analysis
1. **Outdated Content**: Many www pages reference old API patterns or missing features
2. **Missing Documentation**: New features from Stages 5-7 not documented in www
3. **Placeholder Pages**: Some pages have minimal or outdated content
4. **Navigation Structure**: Needs reorganization to match current feature set
5. **Code Examples**: Need updating to reflect current API patterns
6. **Package Documentation**: Core package (published to npm) needs dedicated documentation

## Documentation Update Strategy

### Phase 1: Content Audit & Planning
**Duration**: Planning phase
**Deliverables**: Comprehensive content map and update priorities

#### Tasks:
1. ✅ Audit all existing MDX pages in `/www/src/app/`
2. ✅ Identify outdated, missing, or placeholder content
3. ✅ Map docs/ markdown files to www/ pages
4. ✅ Create content migration checklist
5. ✅ Define new documentation structure

### Phase 2: Core Documentation Updates
**Priority**: High
**Estimated Effort**: 8-12 hours

#### 2.1 Homepage (`/www/src/app/page.mdx`)
**Current State**: Generic placeholder content
**Updates Needed**:
- ✅ Update hero section with accurate tagline and value proposition
- Update feature grid with current capabilities:
  - Edge-first deployment (Cloudflare Workers)
  - Plugin system with extensibility
  - Three-tiered caching
  - Content workflow & scheduling
  - Media management with R2
  - TypeScript-first development
- Update quick start code examples
- Add "What's New in v2.0" section highlighting major features
- Update testimonials/showcases if available

#### 2.2 Getting Started / Quickstart (`/www/src/app/quickstart/page.mdx`)
**Current State**: Basic setup instructions
**Updates Needed**:
- Expand installation steps with prerequisites (Node 20+, Wrangler)
- Add monorepo-specific instructions
- Update database migration commands
- Add "Using npm package" section for @sonicjs-cms/core
- Include troubleshooting for common setup issues
- Add links to example projects and templates
- Update screenshots of admin interface

#### 2.3 Architecture (`/www/src/app/architecture/page.mdx`)
**Current State**: Basic overview
**Updates Needed**:
- Migrate comprehensive architecture.md content from docs/
- Add detailed system architecture diagrams
- Explain Cloudflare Workers V8 isolate model
- Document request lifecycle and middleware pipeline
- Explain three-tiered caching system (Memory → KV → D1)
- Add plugin system architecture section
- Include data flow diagrams
- Add performance benchmarks and optimization strategies

### Phase 3: Feature Documentation
**Priority**: High
**Estimated Effort**: 12-16 hours

#### 3.1 Plugin System (`/www/src/app/plugins/page.mdx`)
**Current State**: Missing or minimal
**Updates Needed**:
- Create comprehensive plugin system documentation
- Explain plugin architecture and lifecycle
- Document Plugin Builder SDK
- Show examples of creating custom plugins
- List all core plugins with descriptions:
  - core-auth: Authentication & user management
  - core-media: Media upload & R2 storage
  - core-cache: Three-tiered caching
  - database-tools: DB management utilities
  - seed-data: Test data generation
- Document demo plugins:
  - workflow: Content workflow & scheduling
  - faq-plugin: FAQ management
  - demo-login-plugin: Pre-filled login
- Add plugin development tutorial
- Include hook system documentation
- Add plugin configuration examples

#### 3.2 Collections (`/www/src/app/collections/page.mdx`)
**Current State**: Basic collection info
**Updates Needed**:
- Update collection schema format (TypeScript-based)
- Add collection configuration examples
- Document field types and validation
- Explain managed vs. user-created collections
- Show collection sync process
- Add relationship and reference documentation
- Include search and filtering capabilities
- Update with current API endpoints

#### 3.3 Content Management (NEW: `/www/src/app/content-management/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Create new page for content management features
- Document content creation workflow
- Explain draft/review/published states
- Show content versioning and history
- Document bulk operations
- Add rich text editor documentation (TinyMCE)
- Include content scheduling features
- Show preview and duplication features

#### 3.4 Media Management (NEW: `/www/src/app/media/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Create comprehensive media management documentation
- Document R2 integration and storage
- Explain Cloudflare Images optimization
- Show file upload API and UI
- Document folder organization
- Add CDN delivery documentation
- Include supported file types and limits
- Show bulk operations and media library features

#### 3.5 Workflow & Automation (NEW: `/www/src/app/workflow/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document content approval workflows
- Explain scheduled publishing system
- Show automation engine and rules
- Document webhook integration
- Add email notification system
- Include workflow history and audit trails
- Show admin dashboard features
- Add configuration examples

### Phase 4: API Documentation
**Priority**: High
**Estimated Effort**: 8-10 hours

#### 4.1 API Overview (`/www/src/app/api/page.mdx`)
**Current State**: Basic API info
**Updates Needed**:
- Update with current API structure
- Document REST endpoints by category:
  - Authentication: `/auth/*`
  - Content: `/api/content/*`, `/admin/content/*`
  - Collections: `/api/collections/*`
  - Media: `/api/media/*`, `/admin/media/*`
  - Plugins: `/admin/plugins/*`
  - Workflow: `/admin/workflow/*`
- Add request/response examples
- Document authentication headers (JWT)
- Show pagination and filtering
- Include error response formats
- Add rate limiting information

#### 4.2 API Filtering (NEW: `/www/src/app/api/filtering/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document filtering capabilities
- Show query parameter examples
- Explain search functionality
- Add sorting and pagination
- Include field selection
- Show advanced filtering patterns

### Phase 5: Authentication & Security
**Priority**: High
**Estimated Effort**: 6-8 hours

#### 5.1 Authentication (`/www/src/app/authentication/page.mdx`)
**Current State**: Basic auth info
**Updates Needed**:
- Migrate content from docs/authentication.md
- Document session-based authentication (Better Auth)
- Explain token management (cookies + headers)
- Show login/logout/register flows
- Document password reset functionality
- Add token refresh strategies
- Include security best practices
- Show code examples for auth implementation

#### 5.2 Authorization & RBAC (NEW: `/www/src/app/authorization/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document role-based access control
- Explain user roles (admin, editor, author, viewer)
- Show permission middleware
- Document requireAuth, requireRole, requirePermission
- Add custom permission examples
- Include permission management in admin UI

### Phase 6: Deployment & Operations
**Priority**: Medium
**Estimated Effort**: 6-8 hours

#### 6.1 Deployment (`/www/src/app/deployment/page.mdx`)
**Current State**: Basic deployment info
**Updates Needed**:
- Migrate content from docs/deployment.md
- Update Cloudflare Workers deployment guide
- Document D1 database deployment
- Explain R2 bucket setup
- Show KV namespace configuration
- Add CI/CD pipeline examples (GitHub Actions)
- Include environment configuration
- Add production checklist
- Document monitoring and logging

#### 6.2 Configuration (NEW: `/www/src/app/configuration/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document wrangler.toml configuration
- Explain environment variables
- Show binding configurations (D1, R2, KV)
- Add development vs. production configs
- Include secrets management
- Document feature flags

### Phase 7: Caching & Performance
**Priority**: Medium
**Estimated Effort**: 4-6 hours

#### 7.1 Caching (`/www/src/app/caching/page.mdx`)
**Current State**: Minimal content
**Updates Needed**:
- Migrate content from docs/caching.md
- Document three-tiered caching strategy
- Explain Memory → KV → D1 flow
- Show cache configuration per route
- Add invalidation strategies
- Document cache headers and TTLs
- Include performance benchmarks
- Show cache debugging tools

### Phase 8: Developer Guides
**Priority**: Medium
**Estimated Effort**: 8-10 hours

#### 8.1 Templating System (NEW: `/www/src/app/templating/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Migrate content from docs/templating.md
- Document template architecture
- Show admin layout templates
- Explain component system
- Document Handlebars-like syntax
- Add HTMX integration examples
- Show template rendering engine

#### 8.2 Testing Guide (NEW: `/www/src/app/testing/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Migrate content from docs/testing.md
- Document Vitest unit testing
- Explain Playwright E2E testing
- Show testing best practices
- Add test examples for routes, services, plugins
- Document test coverage goals
- Include CI/CD testing

#### 8.3 Database & Schema (NEW: `/www/src/app/database/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document Drizzle ORM usage
- Explain D1 database features
- Show migration system
- Document schema changes workflow
- Add database best practices
- Include query optimization tips

### Phase 9: Package Documentation
**Priority**: High
**Estimated Effort**: 6-8 hours

#### 9.1 Core Package (NEW: `/www/src/app/packages/core/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document @sonicjs-cms/core npm package
- Show installation and setup
- Explain package exports structure
- Document services, middleware, routes, templates
- Add usage examples for each module
- Show integration with existing projects
- Include TypeScript type documentation
- Add migration guide from v1 to v2

#### 9.2 Create App CLI (NEW: `/www/src/app/packages/create-app/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Document create-sonicjs-app CLI tool
- Show scaffolding options
- Explain project templates
- Add customization options
- Include best practices for new projects

### Phase 10: Troubleshooting & Reference
**Priority**: Medium
**Estimated Effort**: 4-6 hours

#### 10.1 Troubleshooting (NEW: `/www/src/app/troubleshooting/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Migrate content from docs/troubleshooting.md
- Add common errors and solutions
- Document debugging techniques
- Include development tips
- Add performance troubleshooting
- Show logging and monitoring tools

#### 10.2 FAQ (NEW: `/www/src/app/faq/page.mdx`)
**Current State**: Doesn't exist
**Updates Needed**:
- Create comprehensive FAQ
- Cover common questions about:
  - Cloudflare Workers limitations
  - Plugin development
  - Performance optimization
  - Migration from other CMSs
  - Scaling and production usage

### Phase 11: Remove Outdated Content
**Priority**: Low
**Estimated Effort**: 2-4 hours

#### Pages to Remove or Repurpose:
- `/www/src/app/messages/page.mdx` - Unrelated to current CMS
- `/www/src/app/contacts/page.mdx` - Unrelated to current CMS
- `/www/src/app/groups/page.mdx` - Unrelated to current CMS
- `/www/src/app/conversations/page.mdx` - Unrelated to current CMS
- `/www/src/app/errors/page.mdx` - Outdated or irrelevant
- `/www/src/app/attachments/page.mdx` - Covered by Media docs
- `/www/src/app/webhooks/page.mdx` - Move to Workflow section
- `/www/src/app/pagination/page.mdx` - Move to API docs
- `/www/src/app/sdks/page.mdx` - Repurpose for Packages section

## Navigation Structure Update

### Proposed New Navigation (www/src/app/layout.tsx)

```typescript
const navigation = [
  {
    title: 'Getting Started',
    links: [
      { title: 'Introduction', href: '/' },
      { title: 'Quickstart', href: '/quickstart' },
      { title: 'Installation', href: '/installation' },
      { title: 'First Steps', href: '/first-steps' },
    ],
  },
  {
    title: 'Core Concepts',
    links: [
      { title: 'Architecture', href: '/architecture' },
      { title: 'Collections', href: '/collections' },
      { title: 'Content Management', href: '/content-management' },
      { title: 'Plugin System', href: '/plugins' },
      { title: 'Templating', href: '/templating' },
    ],
  },
  {
    title: 'Features',
    links: [
      { title: 'Media Management', href: '/media' },
      { title: 'Workflow & Automation', href: '/workflow' },
      { title: 'Caching', href: '/caching' },
      { title: 'Authentication', href: '/authentication' },
      { title: 'Authorization', href: '/authorization' },
    ],
  },
  {
    title: 'API Reference',
    links: [
      { title: 'API Overview', href: '/api' },
      { title: 'Content API', href: '/api/content' },
      { title: 'Media API', href: '/api/media' },
      { title: 'Filtering & Search', href: '/api/filtering' },
    ],
  },
  {
    title: 'Packages',
    links: [
      { title: 'Core Package', href: '/packages/core' },
      { title: 'Create App CLI', href: '/packages/create-app' },
    ],
  },
  {
    title: 'Development',
    links: [
      { title: 'Database & Schema', href: '/database' },
      { title: 'Testing', href: '/testing' },
      { title: 'Plugin Development', href: '/plugin-development' },
      { title: 'Deployment', href: '/deployment' },
      { title: 'Configuration', href: '/configuration' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { title: 'Troubleshooting', href: '/troubleshooting' },
      { title: 'FAQ', href: '/faq' },
      { title: 'Changelog', href: '/changelog' },
      { title: 'Contributing', href: '/contributing' },
    ],
  },
]
```

## Content Migration Checklist

### From `docs/` to `www/src/app/`

| Source File | Target Page | Status | Priority |
|-------------|-------------|--------|----------|
| docs/getting-started.md | /quickstart/page.mdx | 📝 Update | High |
| docs/architecture.md | /architecture/page.mdx | 📝 Update | High |
| docs/authentication.md | /authentication/page.mdx | 📝 Update | High |
| docs/deployment.md | /deployment/page.mdx | 📝 Update | High |
| docs/caching.md | /caching/page.mdx | 📝 Update | Medium |
| docs/templating.md | /templating/page.mdx | ✨ Create | Medium |
| docs/testing.md | /testing/page.mdx | ✨ Create | Medium |
| docs/collections-config.md | /collections/page.mdx | 📝 Update | High |
| docs/plugins/plugin-development-guide.md | /plugin-development/page.mdx | ✨ Create | Medium |
| docs/api-filtering.md | /api/filtering/page.mdx | ✨ Create | Medium |
| docs/workflow-plugin-migration.md | /workflow/page.mdx | ✨ Create | High |
| README.md | /page.mdx | 📝 Update | High |
| packages/core/README.md | /packages/core/page.mdx | ✨ Create | High |

### New Documentation to Create

| Page | Purpose | Priority |
|------|---------|----------|
| /content-management/page.mdx | Content creation, versioning, bulk ops | High |
| /media/page.mdx | R2 integration, file uploads, CDN | High |
| /workflow/page.mdx | Workflows, scheduling, automation | High |
| /authorization/page.mdx | RBAC, permissions, roles | High |
| /configuration/page.mdx | Environment config, bindings | Medium |
| /database/page.mdx | D1, Drizzle ORM, migrations | Medium |
| /troubleshooting/page.mdx | Common issues, debugging | Medium |
| /faq/page.mdx | Frequently asked questions | Low |
| /packages/create-app/page.mdx | CLI tool documentation | Medium |

## Code Example Standards

All code examples in documentation should follow these standards:

### Example Format
```typescript
// Always include context comments
// Show imports when relevant
// Include error handling
// Demonstrate TypeScript types

// Example: Creating a custom plugin
import { PluginBuilder } from '@sonicjs-cms/core/plugins'

const myPlugin = PluginBuilder.create('my-plugin')
  .version('1.0.0')
  .description('Custom plugin example')
  .addRoute('GET', '/my-route', async (c) => {
    return c.json({ message: 'Hello from plugin!' })
  })
  .addHook('content:beforeSave', async (content) => {
    // Transform content before saving
    return content
  })
  .build()

export default myPlugin
```

### API Request Examples
```bash
# Always show full curl commands
# Include authentication headers
# Show expected responses

# Get all content
curl -X GET https://your-app.workers.dev/api/content \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"

# Response
{
  "data": [...],
  "meta": {
    "count": 10,
    "cache": { "hit": true, "source": "memory" },
    "timing": { "total": 15, "unit": "ms" }
  }
}
```

## Documentation Style Guide

### Writing Guidelines
1. **Clarity**: Use simple, direct language
2. **Conciseness**: Avoid unnecessary words
3. **Completeness**: Cover all necessary details
4. **Code-First**: Show examples before explaining
5. **Consistency**: Maintain uniform tone and structure

### MDX Component Usage
- Use `<Callout>` for important notes and warnings
- Use `<CodeGroup>` for multi-language examples
- Use `<Properties>` for API parameter documentation
- Use code blocks with language syntax highlighting

### Metadata Standards
Every page should include:
```typescript
export const metadata = {
  title: 'Page Title - SonicJS',
  description: 'Concise description (150-160 chars)',
}

export const sections = [
  { title: 'Section 1', id: 'section-1' },
  { title: 'Section 2', id: 'section-2' },
]
```

## Search Indexing

### Update Search Configuration
- Ensure all new pages are indexed by FlexSearch
- Update search weights for important content
- Test search functionality after major updates
- Add relevant keywords to page metadata

## Visual Assets

### Images & Diagrams Needed
1. Architecture diagrams (system overview, request flow)
2. Plugin system architecture diagram
3. Caching flow diagram
4. Workflow state machine diagram
5. Admin interface screenshots
6. Installation process screenshots

### Diagram Tools
- Use Mermaid for diagrams in MDX
- Export SVG for complex diagrams
- Store images in `/www/public/images/docs/`

## Testing & Validation

### Pre-Deployment Checklist
- [ ] All internal links work correctly
- [ ] Code examples are tested and accurate
- [ ] Search functionality includes new content
- [ ] Navigation structure is intuitive
- [ ] Mobile responsiveness verified
- [ ] Dark mode works correctly
- [ ] Page load performance is acceptable
- [ ] SEO metadata is complete
- [ ] Accessibility standards met

### Review Process
1. **Content Review**: Verify accuracy and completeness
2. **Technical Review**: Test all code examples
3. **UX Review**: Ensure navigation and structure are intuitive
4. **SEO Review**: Check metadata and search optimization
5. **Final Review**: Comprehensive check before deployment

## Deployment Strategy

### Deployment Steps
1. **Development**: Work in `/www/` directory
2. **Local Testing**: `npm run dev:www` for local preview
3. **Build**: `npm run build:www` to verify build
4. **Deploy**: `npm run deploy:www` to Cloudflare Pages
5. **Verify**: Test live site after deployment

### Rollback Plan
- Keep previous version accessible
- Monitor analytics for user issues
- Quick rollback capability via Cloudflare Pages

## Success Metrics

### Documentation Quality Metrics
- **Coverage**: 100% of features documented
- **Accuracy**: All code examples tested
- **Completeness**: No placeholder content
- **Usability**: Average time to find information < 2 minutes
- **Engagement**: Increased docs page views and time on page

### Performance Metrics
- **Page Load**: < 2s initial load
- **Search Speed**: < 100ms for search queries
- **Build Time**: < 60s for full site build

## Timeline & Milestones

### Phase Completion Targets
- **Phase 1** (Audit & Planning): Complete ✅
- **Phase 2** (Core Docs): 2-3 days
- **Phase 3** (Features): 3-4 days
- **Phase 4** (API): 2 days
- **Phase 5** (Auth/Security): 2 days
- **Phase 6** (Deployment): 2 days
- **Phase 7** (Caching): 1-2 days
- **Phase 8** (Dev Guides): 2-3 days
- **Phase 9** (Packages): 2 days
- **Phase 10** (Troubleshooting): 1-2 days
- **Phase 11** (Cleanup): 1 day

**Total Estimated Time**: 18-26 days (with parallelization: 10-14 days)

## Priority Execution Order

### Week 1: High-Priority Updates
1. Homepage and Quickstart (Phase 2.1, 2.2)
2. Architecture and Collections (Phase 2.3, 3.2)
3. Core Package documentation (Phase 9.1)
4. Plugin System (Phase 3.1)

### Week 2: Feature Documentation
5. Content Management (Phase 3.3)
6. Media Management (Phase 3.4)
7. Workflow & Automation (Phase 3.5)
8. API Documentation (Phase 4)

### Week 3: Development & Operations
9. Authentication & Authorization (Phase 5)
10. Deployment & Configuration (Phase 6)
11. Testing & Database (Phase 8.2, 8.3)
12. Troubleshooting (Phase 10)

### Week 4: Polish & Deploy
13. Caching & Performance (Phase 7)
14. Templating System (Phase 8.1)
15. Navigation updates and cleanup (Phase 11)
16. Final review, testing, and deployment

## Notes & Considerations

### AI Assistant Guidelines
- Use this plan as a reference when updating documentation
- Verify all code examples against current codebase
- Maintain consistency with existing documentation style
- Update this plan as documentation evolves

### Future Enhancements
- Interactive API playground
- Video tutorials
- Plugin marketplace documentation
- Community showcase
- Translation support (i18n)

## Appendix

### Key Repository Files
- Main README: `/README.md`
- Core package: `/packages/core/`
- Documentation source: `/docs/`
- Website source: `/www/`
- Plugin examples: `/src/plugins/`

### Reference Documentation
- Cloudflare Workers: https://developers.cloudflare.com/workers/
- Hono.js: https://hono.dev/
- Drizzle ORM: https://orm.drizzle.team/
- HTMX: https://htmx.org/

### Contact & Support
- GitHub Issues: https://github.com/lane711/sonicjs-ai/issues
- Discussions: https://github.com/lane711/sonicjs-ai/discussions

---

**Plan Version**: 1.0
**Last Updated**: October 24, 2025
**Status**: Ready for Review
