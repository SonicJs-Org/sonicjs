# SonicJS v3 Beta: A New Foundation for Edge-Native Content

*June 2026*

---

We're releasing SonicJS v3 as a public beta today. This is the biggest release we've shipped — not because we added more features on top of the old architecture, but because we replaced the architecture itself.

Here's what changed and why it matters.

---

## The Problem with v2

SonicJS v2 worked. Teams shipped real products with it. But as plugins multiplied, a pattern emerged that didn't scale: every feature owned its own database table. Testimonials had a `testimonials` table. The redirect plugin had a `redirects` table. Analytics had its own rows. Media had `media`.

Each table meant its own query path, its own pagination logic, its own auth checks. Adding a new content type meant writing a migration, a schema definition, a route handler, and usually a new admin UI from scratch. The duplication was real and compounding.

v3 fixes this at the foundation level.

---

## The Document Model

The centerpiece of v3 is a unified document repository. Every piece of content — blog posts, media files, redirects, audit logs, custom plugin data — lives in the same five-table structure:

- **`document_types`** — registered content schemas (defined in code, not in the database)
- **`documents`** — every record, every version, queryable via indexed virtual columns
- **`document_references`** — typed edges between documents (powers "where used" and safe deletes)
- **`document_facets`** — indexed rows for multi-valued fields like tags
- **`document_permissions`** — per-document ACL overrides on top of type-level base grants

The payoff: one read API, one write API, one permission system, one versioning model — across every content type in your app.

---

## What's New in v3

### Code-Defined Collections

Content types in v3 are defined in TypeScript, not in a database table. You write a `CollectionConfig`, call `registerCollections()` in your app entry point, and the type is live. No migration, no sync, no drift between your code and your schema.

```typescript
export const blogPosts: CollectionConfig = {
  name: 'blog_posts',
  label: 'Blog Posts',
  fields: [
    { name: 'title', type: 'text', required: true },
    { name: 'body', type: 'richtext' },
    { name: 'author', type: 'user-autocomplete' },
    { name: 'published_at', type: 'date' },
  ],
}
```

### Better Auth + RBAC

v3 ships with Better Auth for session management and a role-based access control system that's wired into the document layer. Every document mutation checks ACL — deny wins, then explicit allow, then base grants. Roles are assigned at registration and flow through to every permission check without extra wiring on your part.

### Opt-In Versioning

Document versioning is now a per-type opt-in. Types that need a full edit history get it. Types that don't skip the overhead entirely. Version conflicts are resolved at the database level via a partial unique index — no JS-side race conditions.

### Media on the Document Model

The media library is now backed by the document repository. Your uploads, your metadata, and your references to other content all flow through the same query and permission layer as everything else.

### Email Provider Selector

v3 supports Resend and Cloudflare Email out of the box. Provider selection is driven by environment variables — swap providers in your `wrangler.toml` without touching application code.

### Leaner Plugin Footprint

We removed several legacy plugins from core that belonged in user-space: testimonials, code examples, the old design system plugin, and seed data tooling. Core plugins (cache, redirects, security audit, analytics, activity log, user profiles) have all been migrated to run on the document model.

### URL-Driven Admin Filters

The plugin list and content views now support URL-driven category and status filters. Deep-links and bookmarked admin views actually work now.

---

## Upgrading from v2

We'll be direct: **there is no automated migration tool from v2 to v3.**

The document model is a fundamentally different data layer. It is not a table rename or a schema migration. Your v2 content lives in feature tables (`content`, `media`, etc.); v3 reads from the document repository. Moving between them requires a data migration that understands your specific content types and field shapes.

The best approach right now: use an AI coding assistant — Claude, Codex, or similar — to read your v2 database schema and generate a migration script that maps your content into the v3 document format. The document model's structure is clean and well-documented, so this is a well-scoped task for an LLM with your schema as context.

We'll publish a reference migration script as the beta matures. If you've written one for your own project, we'd love a PR.

**If you're starting a new project, v3 is the right choice today.**

---

## What's Still in Progress

v3 is a beta. Here's what we're still working on before stable:

- The `content` and `media` legacy tables are still present in the schema (they'll be dropped after the media read-flip is complete)
- The workflow plugin is disabled (not on the critical path; will return in a future release)
- A reference v2→v3 data migration script

---

## Getting Started

```bash
npm create sonicjs my-app
cd my-app
npm run setup:db
npm run dev
```

Docs: [sonicjs.com/docs](https://sonicjs.com/docs)
GitHub: [github.com/SonicJs-Org/sonicjs](https://github.com/SonicJs-Org/sonicjs)
Community: [Discord](https://discord.gg/sonicjs)

---

We shipped v3 on Cloudflare Workers with Hono.js, Cloudflare D1, and Better Auth — the same stack as v2, rebuilt on a foundation that scales with you.

Try it, break it, tell us what you find.
