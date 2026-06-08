# Better Auth Migration Plan

Plan to replace SonicJS's hand-rolled JWT + PBKDF2 auth with **Better Auth**, integrated through the **[`@zpg6/better-auth-cloudflare`](https://github.com/zpg6/better-auth-cloudflare)** shim (not `better-auth` directly). Reference prior art: [PR #620 (ivoilic)](https://github.com/SonicJs-Org/sonicjs/pull/620).

> **Status: NOT scheduled for execution.** This is a contingency plan. The current recommended direction is to port the hardened JWT + table-driven RBAC work validated in the Infowall fork (see §0). Execute this plan only if the trigger conditions in §0 are met. The shim is what we adopt; `better-auth` is a transitive dependency.

---

## 0. When to execute this plan (and how lightly)

This plan was written before the Infowall RBAC work was known. That work invalidated the plan's original headline justification ("SonicJS has no permission engine, building RBAC ourselves is months of work") — table-driven RBAC with an admin UI now exists and is production-validated. So Better Auth is held as a contingency, not a default.

**Trigger conditions — execute only if one becomes a concrete, near-term requirement from real users:**

- **Enterprise SSO** — generic OIDC and/or SAML (issue #382). SonicJS has nothing here; Better Auth has maintained plugins.
- **Passkeys / WebAuthn** — no SonicJS implementation exists.
- **Official client SDK** (issue #585) — framework-adapter SDK for headless consumers.
- **Instant session revocation as a hard requirement** — the one day-to-day security area where stateless JWT is genuinely weaker. (Cheaper alternative exists: `jti` + KV revocation blocklist, ~150 LOC, no migration.)
- **Maintained social-provider breadth** — the long tail beyond Google/GitHub (which already work via the `oauth-providers` plugin). This is a *convenience*, not a capability gap, and is not sufficient on its own.

**Market context:** Payload — the obvious comparison — sells SAML/OAuth SSO as a *paid enterprise* feature and pushes OIDC/passkey to community plugins (which themselves wrap Auth.js / Better-Auth-class libraries). So lacking SAML in free core does not put SonicJS behind Payload's free tier. This argues for the **plugin-mode variant** below over a core rewrite.

### Plugin-mode variant (preferred if triggered)

If a trigger lands, strongly prefer wiring the shim in **as an optional plugin alongside** the existing auth, rather than the full core rip-out described in §3–§4:

- Mount Better Auth at `/auth/better/*` (or behind a config flag) as an additive plugin.
- Use it to serve *only* the capability that triggered adoption (e.g. SAML/OIDC/passkey), federating identities back into the existing `users`/`users_roles` tables via a `signIn.after` hook.
- Keep the hardened JWT + RBAC system as the primary path. No breaking change, no FK rewrite, no forced cutover.

The full-replacement plan (§1–§9) remains the reference for a true v4 core migration if the project ever commits to making Better Auth the sole auth system.

---

## 1. Why the shim, not raw better-auth

Calling `better-auth` directly on Cloudflare Workers forces the consumer to solve four things itself; the shim solves them for us:

1. **Per-request instance lifecycle.** Workers must not share a singleton `auth` instance across requests (D1 binding, request-scoped `ExecutionContext`). The shim instantiates per request via `withCloudflare()`.
2. **D1 + Drizzle adapter wiring.** Ships a vetted D1/Drizzle config (Kysely `transaction: false` workaround for #4732 baked in; correct WAL handling).
3. **KV / R2 / Hyperdrive bindings.** Idiomatic configs for secondary storage (rate-limit counters in KV, avatar uploads to R2).
4. **`waitUntil` hooks.** Session refresh, audit logs, and cleanup run through `ctx.waitUntil` via shim helpers.

We pin the shim and ride its upstream better-auth bump cadence.

---

## 2. Current auth surface (what this would replace)

- `packages/core/src/middleware/auth.ts` (519 LOC) — `AuthManager` (sign/verify JWT, PBKDF2 hash/verify, legacy SHA-256 verify), `requireAuth()`, `requireRole()`, `optionalAuth()`. KV-cached JWT verification.
- `packages/core/src/routes/auth.ts` (1376 LOC) — 16 endpoints under `/auth/*`: `/login`, `/register`, `/logout`, `/me`, `/refresh`, `/login/form`, `/register/form`, `/seed-admin`, `/accept-invitation` (GET+POST), `/request-password-reset`, `/reset-password` (GET+POST).
- `packages/core/src/plugins/core-plugins/auth/` — `core-auth` plugin manifest.
- `packages/core/src/plugins/core-plugins/oauth-providers/` — Google + GitHub OAuth (custom, generic provider config).
- `packages/core/src/plugins/core-plugins/user-profiles/` — `defineUserProfile()` registry for custom fields (issue #803).
- `packages/core/src/plugins/available/magic-link-auth/` — magic-link plugin.
- `packages/core/src/db/schema.ts` — `users` (`role` text column; `passwordHash` nullable), `apiTokens` (permissions JSON, no enforcement).

Touchpoints: `index.ts` re-exports `requireAuth`/`requireRole`/`optionalAuth`/`authRoutes`; templates and admin routes call `c.get('user')` expecting `{ userId, email, role }`.

---

## 3. Target architecture

```
Hono app (worker)
  app.use('*', sessionMiddleware())        ← per-request, sets c.set('user')
  app.route('/auth', betterAuthHandler)
       └─ withCloudflare({ d1, kv, r2, env, ctx })   ← shim factory
            └─ betterAuth({
                 database: drizzleAdapter(db, { provider: 'sqlite' }),
                 emailAndPassword, socialProviders,
                 plugins: [ magicLink, emailOTP, jwt, apiKey, admin,
                            organization?, twoFactor?, passkey? ],  ← phased
                 user: { additionalFields: <from defineUserProfile()> },
                 hooks: { registration-gating, legacy-PBKDF2 verify-and-rehash }
               })
```

Invariants kept:
- `c.get('user')` still returns `{ id, email, role, ... }` (mapped from BA session).
- `requireAuth()` / `requireRole()` / `optionalAuth()` keep public signatures.
- Mount path stays `/auth/*`.
- `JWT_SECRET` retired; `BETTER_AUTH_SECRET` + `BETTER_AUTH_URL` take over.

---

## 4. Phased rollout (full-replacement path)

### Phase 0 — Pre-work
- Spike `@zpg6/better-auth-cloudflare` against D1 + Drizzle under Hono. Confirm the Drizzle/SQLite double-stringify bug (#8655) does not hit our JSON columns; add a regression test. Confirm `additionalFields: string[]` quirk (#7440) is off our hot path. Cross-origin cookie (#7657) is N/A (single Worker) — document.
- **Pin a known-good stable minor** (latest `1.6.x` stable, NOT a beta). Pin shim at `^0.3.x`.
- Benchmark D1 session-lookup latency per request. Target < 5 ms p99 warm. If too high, plan a KV cache layer (shim supports it).
- Decide hard-cut vs. flag. **Recommendation: hard-cut at the target major** — dual adapters double the test surface and make the user schema ambiguous.

### Phase 1 — Schema
- **Migration A:** create BA tables — `user`, `session`, `account`, `verification` (match BA's required shape; BA-Drizzle adapter owns them).
- **Migration B:** extend `user` with domain fields — `username`, `firstName`, `lastName`, `role`, `avatar`, `isActive`, `lastLoginAt`. Backfill from existing `users`.
- **Migration C:** copy `passwordHash` → `user.legacyPasswordHash` (column we own). Existing PBKDF2 hashes stay verifiable; BA's password field stays NULL until first re-auth.
- **Migration D (deferred to Phase 4):** drop old `users`, `magic_link`, `otp_codes` once cutover is proven.

Notes: BA generates its own `user.id`; add `user.legacyId` for FK back-compat during transition. `apiTokens` replaced by BA `apiKey` plugin tables (migrate existing rows).

### Phase 2 — Handler + middleware swap
- `packages/core/src/auth/index.ts` — `createAuth(env, ctx)` factory calling `withCloudflare({ d1: env.DB, kv: env.KV, r2: env.MEDIA_BUCKET, env, ctx })`; passes plugins, hooks, `additionalFields` from `getUserProfileConfig()`.
- `packages/core/src/auth/middleware.ts` — `sessionMiddleware()` calls `auth.api.getSession({ headers })`, sets `c.set('user')`/`c.set('session')`. Rewrite `requireAuth`/`requireRole`/`optionalAuth` against BA session, same signatures.
- Mount `app.route('/auth', betterAuthHandler)` in `packages/core/src/app.ts`. Remove JWT handlers in `routes/auth.ts` except thin shims for: `GET /auth/login`, `GET /auth/register` (render admin pages; form actions now POST to BA `/auth/sign-in/email`, `/auth/sign-up/email`), and `POST /auth/seed-admin` (calls `auth.api.signUpEmail` then promotes role).
- Delete `AuthManager.signToken` + KV JWT cache. Keep `AuthManager.verifyPassword` temporarily for the rehash hook.
- **Hook — legacy-password verify-and-rehash:** `signIn.before` — if user has `legacyPasswordHash` and BA verify fails, verify against legacy hash; on success set BA password and clear `legacyPasswordHash`. No mass-rehash, no forced reset.
- **Hook — registration gating:** `signUp.before` throws when registration disabled (mirrors existing setting).
- Update `c.get('user')` consumers to read `{ id, email, role }` via the mapping helper in `auth/middleware.ts`.

### Phase 3 — RBAC, plugins, profile fields
- **RBAC via `createAccessControl`:** resources `content`/`collection`/`media`/`user`/`plugin`/`settings`/`form` × verbs `read`/`create`/`update`/`delete`/`publish`/`manage`. Roles bundle statements (`admin = manage:*`, etc.). `requireRole('admin')` becomes a deprecated alias for `requirePermission(...)`.
- **OAuth:** retire custom `oauth-service.ts`; use BA `socialProviders`. Keep the admin-settings UI for client IDs (now writes BA config).
- **Magic link / OTP:** replace `magic-link-auth` and `otp-login-plugin` with BA `magicLink` / `emailOTP`, wired to our email service.
- **API tokens:** replace `apiTokens` with BA `apiKey` plugin; migrate rows; gain verb-based scope enforcement.
- **Custom profile fields:** `defineUserProfile({ fields })` feeds BA `user.additionalFields` — fixes #803. `defineUserProfile()` must run **before** the first `createAuth()` call; document in the plugin-loader contract.
- **Admin plugin:** enable BA `admin` (impersonate, ban, set-role) for `/admin/users`.
- **2FA / passkeys:** defer to a follow-up minor.

### Phase 4 — Cleanup + cutover
- Drop `users` (old), `magic_link`, `otp_codes`, `api_tokens`; repoint FKs (`content.authorId`, `media.uploadedBy`, `workflowHistory.userId`).
- Remove `AuthManager`; remove legacy `routes/auth.ts` handlers; remove `JWT_SECRET`/`JWT_EXPIRES_IN`/`JWT_REFRESH_GRACE_SECONDS`.
- Bump major; write migration guide.

---

## 5. Open questions before Phase 2
1. **Session lookup cost** on D1 per request — ship KV cache by default or opt-in?
2. **Per-request `auth` instance** — confirm no Drizzle connection-state leak under load (soak test).
3. **Email backend** — which existing email plugin (Resend/SMTP) becomes the default wiring for BA's `sendVerificationEmail`/`sendResetPassword`?
4. **`user.id` shape change** — dual-ID side-by-side until Phase 4, or rewrite FKs in Phase 1? (Riskiest item.)
5. **Test strategy** — every BA endpoint gets E2E + miniflare-D1 integration coverage. (PR #620 shipped with E2E unchecked; not acceptable for a real cutover.)
6. **Plugin loader contract** — enforce `defineUserProfile()` before first auth request (synchronous boot-time call preferred).
7. **Role → permission mapping** — preserve today's sets, or tighten to also fix #783? (Preference: tighten, documented in migration guide.)
8. **Pin policy** — manual smoke gate on minor bumps (the 1.4.x cross-origin regression taught this).

---

## 6. File-level change inventory

New: `auth/index.ts`, `auth/middleware.ts`, `auth/access-control.ts`, `auth/hooks.ts`, `db/auth-schema.ts`, migrations A–D.

Modified: `middleware/auth.ts` (shrink to legacy PBKDF2 verify only), `routes/auth.ts` (page renderers + `seed-admin`), `app.ts` (mount handler + session middleware), `index.ts` (re-export new middleware), `db/schema.ts` (augment user; deprecate `apiTokens`), `oauth-providers/index.ts` (back manifest with BA social providers), `user-profiles/*` (bridge to `additionalFields`), `auth/manifest.json` (rev version, verb-form permissions).

Removed: `oauth-providers/oauth-service.ts`, `plugins/available/magic-link-auth/*`, `otp-login-plugin/*`.

---

## 7. Env / config delta
Removed: `JWT_SECRET`, `JWT_EXPIRES_IN`, `JWT_REFRESH_GRACE_SECONDS`.
Added (required): `BETTER_AUTH_SECRET`, `BETTER_AUTH_URL`.
Added (optional): `BETTER_AUTH_TRUSTED_ORIGINS`, `BETTER_AUTH_DISABLE_SIGN_UP`.
KV/R2 bindings already exist; shim consumes the same names.

---

## 8. Explicitly out of scope for a first cutover
- Organizations / multi-tenancy (plugin wired, disabled by default).
- Replacing admin login HTML pages (they keep rendering; only form actions change).
- Shipping the BA client SDK distribution (#585) — document consumer self-add first.
- SAML/SSO (#382) — plugin available, not enabled by default.

---

## 9. Risks (ranked)
1. **FK rewrite on `content.authorId` etc.** — botched migration orphans content from authors. Mitigation: dual-ID through Phase 3, validation script, rollback migration.
2. **Session-lookup latency on D1.** Mitigation: benchmark Phase 0; KV cache ready before Phase 2.
3. **BA upstream breakage.** Mitigation: pin exact minor; subscribe to releases; upstream-bump CI runs full E2E.
4. **Legacy-password rehash hook misfires** → lockouts. Mitigation: integration test every hash format (`pbkdf2:*`, legacy SHA-256); telemetry on hook success/failure.
5. **Plugin-order assumption** — `defineUserProfile()` after `createAuth()` silently drops fields. Mitigation: boot-time contract + warning on post-init registry mutation.
