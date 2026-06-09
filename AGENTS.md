# SonicJS Agent Guidelines

These instructions mirror the workflow Claude Code already follows in Conductor so every coding agent behaves consistently.

## Token-Efficient Tooling (use FIRST, before grep/Read sprees)

This repo is indexed by **codegraph** (684 files, 5693 nodes). Use it as the default code-lookup tool. Hook also rewrites shell commands via **rtk** for 60-90% bash savings. Default response mode is **caveman** for terse output.

### Decision tree — code exploration

| Intent | Tool | Why |
|--------|------|-----|
| "How does X work / where does X live / trace flow X→Y" | `mcp__codegraph__codegraph_explore` | ONE call returns verbatim source grouped by file. Replaces many Read/Grep. |
| "Just the location of symbol named X" | `mcp__codegraph__codegraph_search` | Cheapest — name + path only. |
| "What calls this / what does this call / blast radius" | `codegraph_callers` / `codegraph_callees` / `codegraph_impact` | Edges already indexed; grep can't follow dynamic dispatch. |
| Pinpoint known file edit | `Read` + `Edit` | Codegraph not needed for known path. |
| Truly open-ended cross-cutting search | `Agent` w/ `Explore` or `cavecrew-investigator` | Compressed output, protects main context. |

**Rule:** Before any 3+ Grep/Read combo for "where is X", call `codegraph_explore` first. Treat codegraph as a pre-built index — don't re-run searches it already answers.

### rtk (Rust Token Killer)

- Bash commands auto-rewritten by hook — transparent, 0 overhead. No action needed.
- `rtk gain` to audit savings; `rtk discover` to find missed opportunities.
- Don't bypass rtk with raw shell unless debugging.

### caveman mode

- Active by default (full). Drops articles/filler. Code blocks, commits, security warnings stay normal.
- Toggle: `/caveman lite|full|ultra`, off via "stop caveman".

### Delegation — cavecrew subagents

Use when scope is bounded AND output would bloat main context:
- `cavecrew-investigator` — read-only locator ("where is X / what calls Y / map this dir"). ~60% smaller tool result vs vanilla Explore.
- `cavecrew-builder` — surgical 1-2 file edit (typo, single-fn rewrite, mechanical rename). Refuses 3+ files.
- `cavecrew-reviewer` — diff/PR review, one line per finding.

Skip cavecrew for: known-path edits, multi-file features, anything codegraph answers in one call.

### Anti-patterns (token waste)

- ❌ Running `grep -r` across the repo when `codegraph_search` would answer.
- ❌ Reading 5+ files to understand a flow — `codegraph_explore` returns the relevant slice.
- ❌ Spawning a subagent just to read one known file.
- ❌ Verbose narration. Caveman mode handles that — keep updates to one sentence.

## Project Structure & Stack
- Monorepo managed with npm workspaces. Core Hono + Workers code, routes, middleware, templates, plugins, utils, and DB lives in `packages/core/src`.
- Shared templates/components: `packages/templates/`. CLI scaffolder: `packages/create-app/`. Helper scripts: `packages/scripts/`.
- Marketing/docs site is `www/` (Next.js + MDX). Long-form docs, AI plans, and architecture notes live in `docs/`.
- E2E specs use Playwright in `tests/e2e/` (configs in `tests/playwright*.config.ts`). Postman and smoke docs sit under `tests/`.
- `my-sonicjs-app/` is the sand-boxed sample install; recreate freely and use it to exercise migrations (`npm run setup:db` produces a fresh branch-specific D1 DB).

## Preferred Workflow (Claude Code parity)
1. **Understand & Plan** – Read the issue and affected modules, skim relevant docs, and outline a plan/todo list before heavy editing. Keep changes minimal and targeted.
2. **Prep Environment** – From `my-sonicjs-app/`, run `npm run setup:db` for a clean Cloudflare D1 database tied to the worktree. Run `npm install` at repo root if dependencies changed.
3. **Implement** – Match existing TypeScript/Hono patterns (server templates, plugins, Drizzle schema, HTMX UI). Keep types explicit and favor async/await.
4. **Add Tests** – Unit tests go beside the feature in `packages/core/src/__tests__`. Every change also needs an accompanying Playwright spec under `tests/e2e/##-description.spec.ts`.
5. **Verify** – Run `npm run type-check`, `npm test`, and `npm run e2e` locally. Use `npm run e2e:smoke` or `npm run e2e:ui` only for debugging, but ensure the full suite passes before sign-off.
6. **Document** – Update README/docs or AI plans when APIs, migrations, or workflows change. Mention any fixtures or DB prep needed in the PR/test plan.

## Build & Test Commands
- Install deps: `npm install`
- Build core only: `npm run build:core`; full build + sample app: `npm run build`
- Dev servers: `npm run dev` (proxies to `my-sonicjs-app`), `npm run dev:www` (marketing)
- Type safety: `npm run type-check`
- Unit tests: `npm test` or `npm run test:watch`
- Playwright E2E: `npm run e2e`, smoke subset via `npm run e2e:smoke`, headed/UI via `npm run e2e:ui`
- Sample-app DB reset: `npm run db:reset` (or `npm run setup:db` inside `my-sonicjs-app`)

## Coding Style & Patterns
- TypeScript-first ES modules. Keep exported/public signatures fully typed; lean on Zod validation where applicable.
- Use established folder conventions for routes (`packages/core/src/routes`), templates (`packages/core/src/templates`), plugins (`packages/core/src/plugins`), and Drizzle schema (`packages/core/src/db`).
- Naming: `camelCase` variables/functions, `PascalCase` classes/components, dash-case filenames and migrations (`NNN_description.sql`).
- Tests end with `.test.ts` or `.integration.test.ts`; Playwright specs are numerically prefixed (`##-flow-name.spec.ts`).
- Favor small, composable functions and glass-morphism UI patterns already defined in admin templates.

## Testing Expectations (Non-Negotiable)
- **Unit coverage**: Write explicit assertions (avoid brittle snapshots) in `packages/core/src/__tests__`. Cover both success and edge cases.
- **E2E coverage**: Every feature/fix must add or update a Playwright spec in `tests/e2e/`. Include happy path + critical error handling. Use helpers like `tests/e2e/utils/test-helpers.ts` for login/setup.
- **Regression focus**: When fixing bugs, first reproduce with a failing test (unit or e2e) before applying the fix.
- Document any required seed data or setup in the PR/test plan so reviewers and CI know how to run it.

## Commit, PR, and CI Workflow
- Branches are created by Conductor; keep names descriptive (`fix-auth-timeout`, `feat-media-upload`).
- Follow the Claude Code commit template:
  ```
  <type>: <short description>

  - Bullet summary of key changes

  Fixes #<issue-number>

  Generated with Claude Code
  Co-Authored-By: Claude <noreply@anthropic.com>
  ```
  Types: `fix`, `feat`, `refactor`, `test`, `docs`, `chore`.
- Before creating a PR run: `npm run type-check && npm test && npm run e2e`. CI repeats these plus deploys a Workers preview with a fresh D1 instance.
- PR body should mirror `.github/pull_request_template.md`: include summary, linked issue, detailed change bullets, and explicit test commands + outcomes (unit + E2E).
- Keep docs in sync (`docs/`, `www/src/app/*.mdx`, READMEs). Mention any migrations or plugin contract changes.

## Available Agents

Specialized agents are defined in `.claude/commands/`. All agents are prefixed with `sonicjs-` for namespacing.

For detailed documentation, see [docs/ai/claude-agents.md](docs/ai/claude-agents.md).

### Development Agents
| Agent | Purpose |
|-------|---------|
| `/sonicjs-fullstack-dev` | Full stack development with planning, testing, and documentation |
| `/sonicjs-pr-fixer` | Fix PRs: cherry-pick forks, enable Dependabot e2e, fix conflicts/tests |
| `/sonicjs-pr-maker` | Create PRs, monitor CI/CD, analyze failures, auto-fix issues |
| `/sonicjs-release-engineer` | Manage releases and versioning |

### Marketing & Content Agents
| Agent | Purpose |
|-------|---------|
| `/sonicjs-release-announcement` | Generate release announcements |
| `/sonicjs-seo` | SEO expert for optimization recommendations |
| `/sonicjs-seo-blog` | Generate SEO-optimized blog posts |
| `/sonicjs-seo-audit` | Audit website for SEO improvements |
| `/sonicjs-seo-keywords` | Keyword research for content |
| `/sonicjs-seo-sitemap` | Generate/update sitemaps |
| `/sonicjs-seo-discord-sync` | Sync Discord content for searchability |
| `/sonicjs-social-post` | Generate social media posts |
| `/sonicjs-blog-image` | Generate blog images via DALL-E |

## AI/Tooling Notes
- Claude Desktop memory is shared via `docs/ai/claude-memory.json`. Copy `.claude/settings.shared.json` to `.claude/settings.local.json` and install the `@modelcontextprotocol/server-memory` MCP server if you need consistent AI context.
- Graphiti MCP integration is documented in `docs/graphiti-setup.md`; update API keys there and restart Claude Desktop when tooling changes.
- Maintain `docs/ai/project-plan.md` and related AI plans as living documents—log new strategies or testing insights there when relevant.
