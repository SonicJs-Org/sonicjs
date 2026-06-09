# SonicJS AI Development Guidelines

This project is a Cloudflare-native headless CMS built with **Hono.js** and TypeScript.

## Core Technology Stack
- **Framework**: Hono.js (ultrafast web framework)
- **Runtime**: Cloudflare Workers
- **Database**: Cloudflare D1 (SQLite) with Drizzle ORM
- **Validation**: Zod schemas
- **Testing**: Vitest (unit tests) + Playwright (E2E)
- **Frontend**: HTMX + HTML for admin interface
- **Deployment**: Wrangler CLI

## Token-Efficient Tooling (REQUIRED before grep/Read sprees)

Repo indexed by **codegraph**. Bash auto-proxied by **rtk**. Default reply mode **caveman**.

- **Code lookup**: call `mcp__codegraph__codegraph_explore` FIRST for any "how does X work / trace flow / where is X used" question. ONE call returns verbatim source grouped by file — replaces 5-20 Grep/Read calls.
- **Symbol location only**: `codegraph_search`.
- **Call graph / impact**: `codegraph_callers`, `codegraph_callees`, `codegraph_impact`.
- **Bash**: hook rewrites to `rtk <cmd>` automatically. `rtk gain` to audit savings.
- **Replies**: caveman mode (full) — drop articles/filler. Code/commits/security warnings stay normal. Toggle `/caveman` or "stop caveman".
- **Subagent delegation** (compressed output, ~60% smaller results): `cavecrew-investigator` (locate), `cavecrew-builder` (1-2 file edit), `cavecrew-reviewer` (diff review).

Anti-patterns: `grep -r` across repo when codegraph answers; reading 5+ files to learn a flow; spawning subagent for a known file; verbose narration.

## Development Workflow

1. **Plan First**: Read the codebase, understand the problem, and write a plan to project-plan.md
2. **Todo Management**: Create specific todo items that can be checked off as you complete them
3. **Get Approval**: Before starting work, check in with me to verify the plan
4. **Iterative Development**: Work through todo items, marking them complete as you go
5. **High-Level Updates**: Give brief explanations of changes made at each step
6. **Simplicity Focus**: Make minimal, targeted changes. Avoid complex refactoring.
7. **Documentation**: Add a review section to project-plan.md summarizing changes

## Key Principles
- **Edge-First**: Leverage Cloudflare's global edge network
- **TypeScript-First**: Strong typing throughout the application
- **Configuration over UI**: Developer-centric approach
- **AI-Friendly**: Clean, structured codebase for AI assistance

## Claude AI Memory Setup

This project uses Claude's memory MCP server to maintain context across sessions. The memory is stored in a shared file so all developers benefit from accumulated project knowledge.

### Setup for New Developers

1. **Copy shared settings**:
   ```bash
   cp .claude/settings.shared.json .claude/settings.local.json
   ```

2. **Install memory MCP server**:
   ```bash
   npm install -g @modelcontextprotocol/server-memory
   ```

3. **Restart Claude Desktop** to load the MCP server

### Memory Storage

- **Location**: `docs/ai/claude-memory.json`
- **Tracked in Git**: Yes, so all developers share the same context
- **Contains**: Project facts, user preferences, development patterns, and accumulated knowledge

### Benefits

- **Persistent Context**: Claude remembers project details across sessions
- **Team Knowledge**: Shared memory means consistent AI assistance for all developers
- **Learning**: Memory improves over time as more context is added

## Admin UI

Glass morphism design system. Reference existing admin templates for patterns:
- Pages: `packages/core/src/templates/pages/admin-*.template.ts`
- Layout: `packages/core/src/templates/layouts/admin-layout-v2.template.ts`
- Components: `packages/core/src/templates/components/`
- Routes: `packages/core/src/routes/admin.ts`

Use `codegraph_explore` to inspect current patterns before building new pages.