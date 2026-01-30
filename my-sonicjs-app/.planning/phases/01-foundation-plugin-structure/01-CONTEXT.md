# Phase 1: Foundation & Plugin Structure - Context

**Gathered:** 2026-01-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Setting up the redirect plugin infrastructure — creating the plugin scaffold, defining the collection schema for storing redirects, and establishing database migrations. This is pure infrastructure that all other phases depend on.

</domain>

<decisions>
## Implementation Decisions

### Collection Schema Design
- **All standard fields included**: source URL, destination URL, match type, HTTP status code, active toggle, hit count, audit fields (created/updated timestamps, user)
- **Match type storage**: Enum/integer format (0=exact, 1=partial, 2=regex) for efficiency and type safety
- **Hit count storage**: Separate analytics table (not in main redirects table) for cleaner separation of concerns
- **Database indexes**: Claude's discretion — create indexes based on query patterns and performance needs

### Reference Points
- **Plugin naming**: 'redirect-management' (descriptive, follows SonicJS patterns)
- **Collection naming**: 'redirects' (plural, matches typical database table conventions)
- **Contact-form patterns**: Claude's discretion — use contact-form as guide, adapt patterns where they make sense for redirects

### Database Strategy
- **Migration approach**: Claude's discretion — follow D1/Drizzle best practices
- **Seed data**: Include sample redirects for testing
  - Basic exact matches (/old-page → /new-page with 301)
  - Different status codes (301, 302, 307, 308, 410 examples)
  - Active/inactive examples (mix of enabled and disabled)
- **Schema evolution**: Claude's discretion — follow standard migration practices for future changes

### Plugin Structure
- **Folder organization**: Claude's discretion — follow contact-form folder structure pattern
- **Type organization**: Claude's discretion — use TypeScript best practices for type definitions
- **Plugin exports**: Claude's discretion — export what's needed for integration with SonicJS and other plugins
- **Configuration/settings**: Include basic settings structure in Phase 1 (even if empty) for future use

### Claude's Discretion
- Database index strategy (source URL is obviously required, but others based on performance)
- Exact folder structure and file organization
- Type definition location (dedicated file vs inline)
- Plugin exports (registration, services, types as needed)
- Migration organization (single vs multiple migrations)
- Schema version handling

</decisions>

<specifics>
## Specific Ideas

- Use contact-form plugin as architectural reference
- Hit count in separate analytics table enables future expansion without modifying main schema
- Match type as enum (not string) for query performance and type safety

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-foundation-plugin-structure*
*Context gathered: 2026-01-30*
