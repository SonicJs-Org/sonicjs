# Auth & RBAC Convergence Plan

> Status: **active plan**. Produced from a deep, file-level comparison of two
> SonicJS auth/RBAC implementations: this branch (`feature/better-auth-poc`,
> "branch") and Mark's hardened fork at `infowall-ai-main` ("mark"). The
> architecture decision is settled; the work is execution sequencing.

## TL;DR

**Adopt the branch's architecture — Better Auth as the single identity engine +
the dynamic RBAC matrix as the single authorization engine — and port Mark's
production discipline (broad enforcement, caching, atomic token flows, hardening,
tests, migration governance) onto it.** Both an independent risk-first architect
and a future-proof architect reached this conclusion; an adversarial critic
verified the load-bearing claims against the code.

One-liner: **branch has the right architecture; Mark has the right craftsmanship.**

The real risk is *sequencing*: the branch currently ships a **guaranteed
password-reset lockout**, so credential-write-through and the `users.role`
single-source-of-truth must land before any feature work.

## Comparison chart

| Dimension | Branch (dakar-v2) | Mark (infowall) | Winner |
|---|---|---|---|
| Identity engine / extensibility | Better Auth 1.6.13 via CF shim, reuses `users` table | Hand-rolled HS256 JWT + AuthManager | **branch** |
| SSO / OIDC / SAML | One BA plugin away (`extendBetterAuth` seam) | None (`enableOAuthLogin` is an unused field) | **branch** |
| Passkeys / 2FA | BA passkey + two-factor plugins | "Coming soon" UI stub; no WebAuthn | **branch** |
| Social login | BA `socialProviders` (config) | None shipped | **branch** |
| Multi-tenant / orgs | BA org plugin + multi-role users | Global-per-role only; invasive surgery needed | **branch** |
| RBAC model & UI-editability | Dynamic runtime matrix: roles × verbs × computed `collection:<name>` × `none/own/any`; wildcards; live "Can I?" | Editable roles + perm-string matrix, but `subject/fields/conditions` scoping is **dead schema** | **branch** |
| Enforcement coverage (defense-in-depth) | Strong perimeter; several admin **GET** handlers gated only by `portal:access` + nav-hiding | ~123 `require('res:action')` across 22 files + global `onError`→403 | **mark** |
| Password hashing & migration | scrypt + transparent PBKDF2→scrypt upgrade on login | PBKDF2-100k-SHA256 (below OWASP 600k); no upgrade path | **branch** |
| Session revocation | BA cookie sessions + KV; revocation **unverified** under secondaryStorage | Explicit D1 session rows + KV, but **fails open** (missing row/D1 error/unindexed `token_hash`) | **tie** |
| Authz caching/perf | **None** — up to 3 D1 RBAC queries/request + per-collection loops | KV-cached, load-once-per-request + cache-bust on edits | **mark** |
| Aux flows (verify/reset/invite/magic-link/OTP) | Present but broken by half-migration (write legacy `users.password_hash`, mint dead JWT cookies) | Fully shipped: atomic single-consume, anti-enumeration, rate-limited, threat-tested | **mark** |
| Test coverage of the *shipped* path | RBAC engine tested; **zero** tests for BA sign-in/session/upgrade; `auth.test.ts` stale | ~3,400 lines auth route tests + threat-model + e2e | **mark** |
| Secrets / hygiene | `BETTER_AUTH_SECRET` committed; `/seed-admin` returned a hash | Hardcoded `JWT_SECRET` fallback in 3 files (forgeable) | **tie (both must-fix)** |
| Migration governance | Two migration dirs; smaller history | `MIGRATIONS.md`, FK-safe renames, idempotent backfills (but `schema.ts` drifted) | **mark** |
| Evaluator perception (2–3 yr) | Recognized library + live matrix = modern, demoable | Solid but bespoke JWT; no SSO/passkeys reads as "dated" | **branch** |

## Keep from each

**From branch (the spine):** Better Auth (reuse `users` table, no FK rewrite);
the dynamic RBAC tables + computed per-collection resources; `none/own/any` scope
with `author_id` enforcement + SQL row-filtering; `grantMatches` wildcard/`manage`
semantics (incl. the tested guard that `collection:*` ≠ system `collections`); the
matrix UI + `portal:access` gate; scrypt + lazy upgrade; server-side nav stripping
(as presentation only); multi-role-per-user.

**From mark (the discipline):** broad per-handler `require()` enforcement + global
`onError`→403; KV-cached load-once-per-request permission resolution with
cache-busting; atomic single-consume token flows (`UPDATE ... WHERE used_at IS NULL`
+ `changes===1`); anti-enumeration + account lockout + rate-limiting + timing
equalization; password-history reuse + full session invalidation; signed
double-submit CSRF; the threat-model test suite; migration governance + the
unbuilt CI drift checks (`drizzle-kit check`, bundle staleness, fresh-DB boot).

## Target end-state architecture

1. **Identity = Better Auth, single source.** All login methods route through BA:
   email+password, social (`socialProviders`), SSO/OIDC + passkeys + 2FA (plugins),
   and magic-link/OTP rewritten to issue BA sessions. Delete the bespoke
   `oauth-providers` plugin and all legacy-JWT cookie minting. Keep only the
   PBKDF2→scrypt verify hook until legacy hashes drain, then retire `AuthManager`.
2. **Authorization = the dynamic RBAC matrix, single source.** `requireRbac` on
   **every** admin handler (close un-gated GETs); nav-stripping stays presentation.
   Add a per-request memoized `RbacService` + KV-cached grant matrix with
   cache-busting on matrix edits (mark's `PermissionsManager` pattern).
3. **Sessions = BA + KV, with revocation explicitly configured and tested.**
4. **Aux flows = mark's implementations, rewritten to write through BA's
   credential/verification tables.**
5. **Hardening = secret validated at startup (hard-fail), `/seed-admin`
   deleted/gated, single migration dir, `schema.ts` reconciled + CI checks.**

## Path forward (reordered so it cannot ship a lockout)

### Phase 0 — Guardrails  *(DONE in this PR)*
- Move `BETTER_AUTH_SECRET` out of `wrangler.toml` → gitignored `.dev.vars` (local)
  + `wrangler secret put` (preview/prod). **Rotate the previously-committed value.**
- Hard-fail in `createAuth` if the secret is missing/short.
- Stop `/seed-admin` returning the password hash; gate it out of `production`.
- (Follow-up) consolidate the two migration directories; reconcile `schema.ts`.

### Phase 1 — Credential correctness (BLOCKERS)  *(partially DONE in this PR)*
1. **Reset lockout fix (DONE):** `/auth/reset-password` and `/auth/invite/accept`
   now write through `ensureCredentialAccount` to `account.password`, not just
   `users.password_hash`. (BA verifies `account.password`; the login self-heal only
   fires when *no* account row exists, so without this every reset was a guaranteed
   lockout for any user who had logged in once.)
2. **Upgrade-by-hash fix (mitigated):** the PBKDF2→scrypt `UPDATE` in
   `auth/config.ts` is scoped to `provider_id='credential'`. Full fix (key on
   `cred-<userId>`) is blocked by BA's `password.verify` hook not exposing the user
   id — tracked as a follow-up to move the upgrade to an identity-aware hook. Random
   16-byte salts make cross-account collision practically impossible today.
3. **Tests (follow-up):** add BA-path integration tests — sign-in, getSession
   projection, KV session cache, upgrade hook, credential self-heal, reset
   round-trip, revocation on logout/role-change — and delete stale `auth.test.ts`
   assertions.

### Phase 2 — Single source of truth for roles
Collapse the live `users.role` double-write (still present on branch: `schema.ts`,
the BA create hook, and `seed-admin` all write it while authz reads only
`rbac_user_roles`). Backfill once, then make `users.role` read-through or drop it
(mark's migration-117 model). Stop the session carrying a stale role string.

### Phase 3 — Close authz gaps + add caching
- Apply `requireRbac(resource, verb)` to every un-gated admin handler (settings,
  plugins, collections-GET, forms, logs, media-GET).
- Per-request memoized + KV-cached RBAC resolution with cache-bust on matrix edits.
- Add a **server-side invariant** that blocks removing the last
  `portal:access` + `rbac:manage` grant (one-click self-lockout is currently
  unguarded; admin-by-name is a fragile mitigation).
- Gate dynamic **plugin** nav items + a plugin contract requiring `requireRbac` on
  plugin admin routes (current gap: plugin menu items and routes are unfiltered).
- e2e proving a non-admin (portal-access-only) user is actually denied each section.

### Phase 4 — Retire legacy auth safely
Replace `oauth-providers` with BA `socialProviders`; reimplement magic-link/OTP as
BA sessions **behind a flag, verified before deleting the old path** (they are real
shipped login methods — deleting cookie-minting before a replacement = lockout).
Remove dead JWT/JSON `/auth/login,/register,/refresh` paths and `AuthManager` once
legacy hashes drain.

### Phase 5 — Port mark's hardening + tests
Account lockout, per-route + per-identifier rate limiting, anti-enumeration,
password-history reuse, atomic single-consume token semantics, threat-model suite.
**Re-decide the CSRF seam:** mark's signed double-submit CSRF is keyed on
`JWT_SECRET`, which is being deleted — it cannot be lifted unchanged; use BA's
cookie/CSRF handling or re-key on the BA secret. Implement the migration CI checks.

### Phase 6 — Future features (as product demands)
BA plugins: passkeys/WebAuthn, 2FA/TOTP, SSO/OIDC/SAML, organization (multi-tenant).
Extend RBAC grants with an optional org/tenant dimension. Ship a client SDK wrapping
the BA client.

## Verified must-fix bugs (from the critic's code-level pass)

1. **Reset = hard lockout** (`routes/auth.ts` reset/invite wrote only
   `users.password_hash`). — *fixed in this PR.*
2. **Upgrade-by-hash** (`auth/config.ts` `UPDATE ... WHERE password=oldHash`). —
   *mitigated (scoped); identity-aware follow-up tracked.*
3. **`users.role` double-write** still live on branch — no single source of truth
   (Phase 2).
4. **Secrets** committed + `/seed-admin` hash leak. — *fixed in this PR; rotate the
   leaked secret.*
5. **Perimeter-only authz** on several admin GET handlers (Phase 3).
6. **No RBAC caching** — 3 D1 queries/request (Phase 3).
7. **Self-lockout** — last admin can remove their own access (Phase 3).
8. **Per-request `createAuth()`** on every route incl. public/static; memoize +
   short-circuit for unauthenticated/static paths (Phase 3/5).

## Coordination & credit with Mark

We are not porting Mark's *code* wholesale (his RBAC scoping is dead schema; his JWT
stack is being replaced). We are porting his **patterns and tests**. Credit Mark as
`Co-Authored-By:` on the PRs that adapt those mechanisms (lockout, rate-limiting,
anti-enumeration, atomic token consume, threat-model suite, migration governance).

## Source

9-agent deep-dive (6 parallel code readers across both repos → 2 independent
architects → adversarial critic). Branch: `feature/better-auth-poc` (PR #848).
Mark: `/Users/lane/Dev/refs/infowall-ai-main` (a SonicJS fork, migrations through
116; RBAC at mig 110; drops `users.role` at 117).
