# Discord Announcement — SonicJS v3 Beta

---

🚀 **SonicJS v3 Beta is here!**

We've been heads-down rebuilding SonicJS from the ground up and we're ready to share what's next. v3 is a major architectural leap — same edge-native philosophy, way more powerful foundation.

**What's new in v3:**

- 📄 **Unified Document Model** — all content (posts, media, plugins, custom types) lives in a single document repository instead of scattered per-feature tables. One API, one query layer, consistent ACL everywhere.
- 🔐 **Better Auth + RBAC** — full session management and role-based access control baked in from the start. Roles assigned on registration, deny-wins ACL precedence across the board.
- 🗂️ **Code-defined Collections** — define your content types in code, register with `registerCollections()`, and they're live. No DB table, no migration file — just a TypeScript config object.
- 🕒 **Opt-in Versioning** — document versioning is now opt-in per content type. Enable it for the types that need history, skip it for the ones that don't.
- 🖼️ **Media on the Document Model** — media library is migrated to the unified document repository, same read API as everything else.
- 📧 **Email Provider Selector** — Resend and Cloudflare Email now supported with env-var-driven provider selection. Switch providers without changing code.
- 🔌 **Plugins migrated to Document Model** — cache plugin, redirect management, security audit, analytics, activity log, and user profiles all running on the new document layer.
- 🧹 **Leaner plugin footprint** — removed legacy plugins (testimonials, code examples, design system, seed data) that belonged in user-space, not core.
- 🔍 **URL-driven admin filters** — plugin list and content views support URL-driven category/status filters, making deep-links and bookmarks actually work.
- 🌍 **Off-Cloudflare portability** — documented deployment targets beyond Cloudflare Workers for teams that need flexibility.

---

**⚠️ Upgrade path from v2 → v3**

There is no automated migration tool from v2 to v3 at this time. v3's document model is a fundamentally different data layer — it is not a table rename.

The best path today: use an AI coding assistant (Claude, Codex, etc.) to help you read your v2 schema and write a data migration script that maps your existing content into the new document model format. We'll share a reference migration script as the beta matures.

If you're starting a new project, v3 is the way to go right now.

---

**Get started:** `npm create sonicjs`
**Docs:** sonicjs.com/docs
**Feedback:** drop it in #v3-beta or open an issue on GitHub

Let us know what you build! 🏗️
