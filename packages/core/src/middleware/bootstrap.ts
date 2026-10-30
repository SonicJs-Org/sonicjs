import { Context, Next } from "hono";
import { loadCollectionConfigs } from "../services/collection-loader";
import { getCollectionRegistry } from "../services/collection-registry";
import { MigrationService } from "../services/migrations";
import { PluginBootstrapService } from "../services/plugin-bootstrap";
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes, bootstrapDefaultContent } from "../services/document-types-seed";
import { getHookSystem, hasHookSystem } from "../plugins/hooks/hook-system-singleton";
import { getTelemetryService } from "../services/telemetry-service"
import { SONICJS_VERSION } from "../utils/version";
import { settlesWithin } from "../utils/shared-promise";
import type { SonicJSConfig } from "../app";
import { setBranchLabel } from "../templates/layouts/admin-layout-catalyst.template";

type Bindings = {
  DB: D1Database;
  KV?: KVNamespace;
  CACHE_KV?: KVNamespace;
  JWT_SECRET?: string;
  CORS_ORIGINS?: string;
  ENVIRONMENT?: string;
};

// Track if bootstrap has been run in this worker instance
let bootstrapComplete = false;
// When the last full bootstrap finished WITH ERRORS (ms epoch), or 0. Drives the retry
// backoff so a persistent failure doesn't re-run the whole bootstrap on every request.
let lastBootstrapFailureAt = 0;

/**
 * The bootstrap currently running on this isolate, if any.
 *
 * `bootstrapComplete` is only set at the *end* of the work, so it cannot keep a second request
 * out while the first is still going. Every request that arrived on a cold isolate before the
 * first one finished therefore saw `false` and ran the whole bootstrap again — concurrently, on a
 * single-threaded isolate, against the same D1. The cost is not N parallel bootstraps but N
 * interleaved ones: each copy's serial D1 round trips queue behind every other copy's, so all N
 * requests take roughly N times the ~3-9s a cold bootstrap costs on its own.
 *
 * That is reachable from ordinary traffic — a dashboard load fires five fragment requests at once
 * — and it is what a four-worker Playwright run hitting a freshly spawned isolate does on every
 * cold start. It showed up as whole batches of unrelated requests, browser and API client alike,
 * stalling past 30s on preview deployments with nothing in the logs: no errors, no 429s, just an
 * isolate spending its time redoing work it had already started.
 *
 * So hold the first caller's promise and let everyone else wait on it. One bootstrap per isolate,
 * and the requests that would have duplicated it now cost a single `await`.
 */
let bootstrapInFlight: Promise<void> | null = null;

/** When the current holder took the gate, for the deadline below. */
let bootstrapStartedAt = 0;

/**
 * How long a follower will wait on the holder before giving up and bootstrapping itself.
 *
 * The gate above is an optimisation — it exists to stop N concurrent bootstraps, not to make a
 * follower correct — so waiting on it must never be able to outlive the thing it waits for.
 * `bootstrapInFlight` is created inside *another request's* execution context, and Cloudflare
 * cancels a request's pending work the moment its client disconnects. A follower that signed up
 * for a holder whose request was torn down before the `finally` ran would wait on a promise
 * nobody is left to resolve: not slow, never. Every later request on that isolate inherits the
 * same dead promise, so one timed-out client silently wedges the isolate for every client after
 * it — which is exactly the reported signature, a request that leaves the test runner and never
 * produces a first byte.
 *
 * 20s is chosen against the two numbers either side of it: a cold bootstrap is ~90 serial D1
 * round trips, so ~3s local and well under 10s even on a slow remote D1, while the E2E suite's
 * action timeout is 30s. A follower that is still waiting at 20s is not waiting on a bootstrap
 * that is about to finish.
 */
let BOOTSTRAP_DEADLINE_MS = 20_000;
let BOOTSTRAP_BACKOFF_MS = 30_000;

// KV key for cross-isolate bootstrap state. Version-keyed so a code deployment
// (SONICJS_VERSION bump) automatically invalidates the cached flag and forces a fresh full
// bootstrap on the next cold start.
//
// Also HOST-keyed, because the flag describes one D1 database and the KV namespace is shared by
// everything deployed from the same wrangler.toml. CI makes that concrete: `pr-tests.yml` deletes
// and recreates the D1 for every PR run but leaves `kv_namespaces.id` alone, so each preview read
// a `'1'` written by a sibling preview against a database it has never seen. The stale-flag guard
// below then deleted the key — out from under the preview that legitimately owned it — and both
// deployments fell back to the full cold bootstrap, concurrently, on a brand-new D1. That is the
// shape behind the 90s hangs on `GET /api/collections`.
//
// The host is the cheapest discriminator that is already per-deployment (`sonicjs-pr-<branch>.…`
// vs the demo's own hostname). A worker reachable on two hostnames simply bootstraps once per
// hostname, which costs one extra cold start and never serves stale state.
//
// A forged Host cannot be used to force repeated bootstraps: `bootstrapComplete` short-circuits
// above this, without reading KV at all, so an isolate that has bootstrapped once never consults
// the key again whatever Host arrives. The worst a junk Host can do is what a missing flag
// already does today — one bootstrap on one cold isolate.
const BOOTSTRAP_KV_KEY = (host?: string) =>
  `_sonicjs_bootstrap_v${SONICJS_VERSION}${host ? `:${host}` : ''}`

/**
 * Throttle key for the fast path's background document-type sync.
 *
 * Moving that sync off the critical path (see the `runInBackground` call below) stopped the
 * *request* waiting for it, but every cold isolate still issued the whole batch of D1 statements
 * — and D1 serialises writes per database. Under a four-worker Playwright run the platform churns
 * isolates for twenty minutes straight, so the aggregate is a sustained write storm against the
 * one preview database, which is the shape behind the 30s HTTP timeouts on requests that have
 * nothing to do with bootstrap.
 *
 * The sync only needs to run often enough to pick up a code collection added without a version
 * bump — the local-dev case. A deploy still invalidates BOOTSTRAP_KV_KEY and runs the full awaited
 * bootstrap, so correctness never rests on this. Gating on a short-lived marker turns "once per
 * cold isolate" into "at most once per minute per deployment" and costs one KV read, issued in
 * parallel with the one already being made.
 */
const BOOTSTRAP_SYNC_KV_KEY = (host?: string) => `${BOOTSTRAP_KV_KEY(host)}:synced`

/** KV's floor for `expirationTtl`. Also about the longest a dev wants to wait for a new collection. */
const BOOTSTRAP_SYNC_THROTTLE_SECONDS = 60

/**
 * Hand a promise to the runtime so it outlives the response.
 *
 * `c.executionCtx` throws outside a real Workers fetch handler — the Vitest harness and
 * `app.request()` both hit that — so the access has to be guarded. Without the ctx the promise
 * still runs; it just loses its keep-alive, which for idempotent background work means the next
 * cold isolate redoes it. Never await the result: the whole point is to be off the hot path.
 */
function runInBackground(c: Context, work: Promise<unknown>): void {
  const settled = work.catch(() => {})
  try {
    c.executionCtx.waitUntil(settled)
  } catch {
    /* no execution context (tests, direct app.request) — let it run unsupervised */
  }
}

/**
 * Verify security-critical environment configuration at startup.
 * Logs warnings in development, throws in production to prevent
 * insecure deployments from silently running.
 */
export function verifySecurityConfig(env: Bindings): void {
  const warnings: string[] = [];

  // Check JWT secret
  if (!env.JWT_SECRET) {
    warnings.push(
      "JWT_SECRET is not set — using hardcoded fallback. Set via `wrangler secret put JWT_SECRET`"
    );
  } else if (env.JWT_SECRET.includes("change-in-production")) {
    warnings.push(
      "JWT_SECRET contains the default value — tokens are forgeable. Generate a strong random secret"
    );
  }

  // Check CORS origins
  if (!env.CORS_ORIGINS) {
    warnings.push(
      "CORS_ORIGINS is not set — all cross-origin API requests will be rejected"
    );
  }

  // Check environment designation
  if (!env.ENVIRONMENT) {
    warnings.push(
      "ENVIRONMENT is not set — HSTS header will not be applied. Set to \"production\" or \"development\""
    );
  }

  if (warnings.length === 0) {
    return;
  }

  const isProduction = env.ENVIRONMENT === "production";

  for (const warning of warnings) {
    console.warn(`[SonicJS Security] ${warning}`);
  }

  if (isProduction) {
    // In production, a missing or default JWT_SECRET is a hard failure —
    // every token issued would be forgeable by anyone reading the source code.
    const hasCritical =
      !env.JWT_SECRET || env.JWT_SECRET.includes("change-in-production");
    if (hasCritical) {
      throw new Error(
        "[SonicJS Security] CRITICAL: Production deployment is missing a secure JWT_SECRET. " +
          "Set it via `wrangler secret put JWT_SECRET` before deploying."
      );
    }
  }
}

// Better Auth stateless session/auth API paths that must never carry the
// cold-start bootstrap tax (they only touch auth_* migration tables). Matched
// as `/auth/<seg>` prefixes so `/auth/sign-in/email`, `/auth/callback/github`,
// etc. are all covered. Deliberately excludes `/auth/login` (page render) and
// `/auth/seed-admin` (self-seeds its own prerequisites).
const BETTER_AUTH_SESSION_SEGMENTS = [
  "sign-in",
  "sign-up",
  "sign-out",
  "get-session",
  "callback",
  "token",
] as const;

export function isBetterAuthSessionPath(path: string): boolean {
  return BETTER_AUTH_SESSION_SEGMENTS.some(
    (seg) => path === `/auth/${seg}` || path.startsWith(`/auth/${seg}/`)
  );
}

// Per-isolate memo so verifySecurityConfig logs warnings once but throws on
// every production request with a bad JWT_SECRET.
let lastSecurityBindings: string | null = null
let lastSecurityError: Error | null = null
let securityWarned = false

function verifySecurityConfigMemoized(env: Bindings): void {
  const sig = `${env.JWT_SECRET ?? ''}|${env.CORS_ORIGINS ?? ''}|${env.ENVIRONMENT ?? ''}`
  if (sig !== lastSecurityBindings) {
    lastSecurityBindings = sig
    lastSecurityError = null
    securityWarned = false
  }
  if (lastSecurityError) throw lastSecurityError
  if (securityWarned) return
  try {
    verifySecurityConfig(env)
    securityWarned = true
  } catch (e) {
    lastSecurityError = e instanceof Error ? e : new Error(String(e))
    throw lastSecurityError
  }
}

/**
 * Bootstrap middleware that ensures system initialization
 * Runs once per worker instance
 */
export function bootstrapMiddleware(config: SonicJSConfig = {}, allPlugins?: Array<{ name?: string; id?: string }>) {
  return async (c: Context<{ Bindings: Bindings; Variables: { hookSystem?: unknown } }>, next: Next) => {
    // Attach the hook system to the request BEFORE any heavy bootstrap work
    // runs, so anything that emits a hook during bootstrap (cron cold starts,
    // RBAC seed, document-type registration, plugin onBoot via createPluginWirer)
    // sees a live bus instead of a no-op. The process singleton was published at
    // app-factory time (app.ts); we only forward it onto the request here.
    if (hasHookSystem()) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Variables typed loosely here; concrete type lives in app.ts
      (c as any).set("hookSystem", getHookSystem());
    }

    // Security check runs on EVERY request — before any short-circuit.
    // Production with a bad/missing JWT_SECRET must fail closed.
    verifySecurityConfigMemoized(c.env as Bindings);

    // Skip if already bootstrapped in this worker instance
    if (bootstrapComplete) {
      return next();
    }

    // Path-based short-circuits come FIRST — above the KV fast-path below, not under it.
    //
    // The "fast" path is only fast relative to a cold full bootstrap: it still costs a KV read,
    // a `SELECT COUNT(*) FROM document_types`, a collection-config load and three serial D1
    // bootstrap calls. Sitting underneath it, these two skips were dead in the steady state —
    // the KV flag is present on any deployment that has served one request, so every health
    // check, every .js/.css/.png and every Better Auth sign-in paid the whole thing on a cold
    // isolate. Measured on a preview deployment: ~9s cold vs ~0.5s warm, and a Playwright run
    // spreads over enough isolates that this stacks into 90s test timeouts.
    //
    // Both blocks must stay below verifySecurityConfigMemoized — a bad JWT_SECRET still has to
    // fail closed on every request — and below the bootstrapComplete check, which is cheaper.

    // Skip bootstrap for static assets and health checks
    const path = c.req.path;
    if (
      path.startsWith("/images/") ||
      path.startsWith("/assets/") ||
      path === "/health" ||
      path.endsWith(".js") ||
      path.endsWith(".css") ||
      path.endsWith(".png") ||
      path.endsWith(".jpg") ||
      path.endsWith(".ico")
    ) {
      return next();
    }

    // Skip the heavy D1 bootstrap for Better Auth's stateless session API. These
    // endpoints only read/write the auth_* tables (created by migration 0001) —
    // they never need the collection registry, document types, or RBAC seed. On
    // a cold isolate the ~10s bootstrap otherwise runs on the same request as
    // Better Auth's scrypt password verify, exhausting the Worker's CPU/time
    // budget and returning a bare 500. Login is the first request in most flows,
    // so this is exactly the request that must not carry the bootstrap tax.
    // (Not /auth/login or /auth/seed-admin: the former is a page render, the
    // latter self-seeds its own prerequisites — neither is a hot cold-start path
    // that 500s.) The full bootstrap still runs on the next non-auth request.
    if (isBetterAuthSessionPath(path)) {
      return next();
    }

    // Somebody else is already doing this. Wait for them rather than starting a second copy —
    // but only up to a deadline, because the holder's request can be cancelled out from under
    // this one. See BOOTSTRAP_DEADLINE_MS.
    if (bootstrapInFlight) {
      const remaining = bootstrapStartedAt + BOOTSTRAP_DEADLINE_MS - Date.now();
      if (remaining > 0 && (await settlesWithin(bootstrapInFlight, remaining))) {
        return next();
      }
      // Either the holder blew the deadline or its request was torn down before the `finally`
      // could release the gate. Drop the dead promise and bootstrap here instead of inheriting
      // it. Worst case this is one duplicate bootstrap after a 20s stall — the operations are
      // all idempotent — against an isolate that would otherwise never answer again.
      console.warn("[Bootstrap] in-flight bootstrap exceeded its deadline; taking over");
      bootstrapInFlight = null;
    }

    // Backoff: the last full run finished with errors less than 30s ago. Serve without
    // re-running — every attempt is ~10s of D1 work, and a failure that persists would
    // otherwise make every request pay it. The next request after the window retries.
    if (lastBootstrapFailureAt && Date.now() - lastBootstrapFailureAt < BOOTSTRAP_BACKOFF_MS) {
      return next();
    }

    let releaseBootstrap: () => void = () => {};
    const ownGate = new Promise<void>((resolve) => {
      releaseBootstrap = resolve;
    });
    bootstrapInFlight = ownGate;
    bootstrapStartedAt = Date.now();

    // `try` so that the gate is released on *every* exit, including a throw from somewhere that
    // is not already wrapped. Leaking it would park every later request on this isolate forever.
    try {
    const host = c.req.header('host') || '';

    // Fast KV check: if a previous isolate already ran the full bootstrap for this app version
    // AND this hostname, skip the expensive D1 operations entirely. KV reads are ~10ms vs 5-10s
    // for cold D1. Version- and host-keyed so deployments auto-invalidate the flag — see
    // BOOTSTRAP_KV_KEY for why the host matters.
    try {
      const cacheKv = (c.env as any).CACHE_KV as KVNamespace | undefined
      if (cacheKv) {
        // Both reads in one round trip's worth of wall clock: the throttle marker is only
        // consulted when the flag says "already bootstrapped", but fetching it eagerly keeps the
        // fast path at a single KV latency instead of two serial ones.
        const [kvDone, syncedRecently] = await Promise.all([
          cacheKv.get(BOOTSTRAP_KV_KEY(host)),
          cacheKv.get(BOOTSTRAP_SYNC_KV_KEY(host)),
        ])
        if (kvDone === '1') {
          // The KV marker is keyed by version+host, not by database, so it can be lying:
          // CI re-creates D1 per run but every PR preview shares one KV namespace, and a
          // marker written over one DB says nothing about another. Trust it only when
          // THIS database has the seed the marker vouches for — the admin role and, unless
          // plugins are disabled, the core-auth plugin document.
          const seeded = await isSystemSeedPresent(c.env.DB as D1Database, !config.plugins?.disableAll)
          if (seeded) {
            // D1 has the system seed — fast-path is valid.
            try {
              const kv = (c.env as any).CACHE_KV as KVNamespace
              const { setGlobalKVNamespace } = await import("../plugins/cache/services/cache")
              setGlobalKVNamespace(kv)
              const { setGlobalCatalogKv, loadKvCatalog } = await import("../plugins/cache/services/catalog")
              setGlobalCatalogKv(kv)
              c.executionCtx.waitUntil(loadKvCatalog())
            } catch { /* KV wiring optional */ }
            try {
              const configs = await loadCollectionConfigs()
              getCollectionRegistry().register(configs)
            } catch { /* registry optional in fast-path */ }
            // Sync document types to D1 even on KV fast-path — idempotent no-ops when
            // nothing changed, but ensures newly added code collections reach D1 without
            // requiring a version bump or full cold-start bootstrap.
            //
            // Deliberately NOT awaited. These are three sequential D1 round trips, and on
            // Cloudflare that is ~15-150ms of network the first request on every cold isolate
            // would otherwise pay before it is even routed — on a single-threaded isolate that
            // stalls every request co-located with it. Nothing downstream reads what they
            // write: BOOTSTRAP_KV_KEY embeds SONICJS_VERSION, so a deploy invalidates the flag
            // and the first request of a new version runs the full awaited bootstrap anyway.
            // What is left for the fast path to cover is purely the local-dev case of adding a
            // code collection without bumping the version, and that can land a beat late.
            // waitUntil keeps them alive past the response instead of being cancelled with it.
            // Throttled, not per-isolate: see BOOTSTRAP_SYNC_KV_KEY. A cold isolate inside an
            // already-synced window skips the batch entirely, which is what keeps four
            // Playwright workers from turning isolate churn into sustained D1 write pressure.
            if (syncedRecently !== '1') {
              // Claim the window before doing the work rather than after. Nothing here is a
              // correctness guarantee -- it all repeats next window, and a deploy runs the full
              // awaited bootstrap -- so narrowing the burst of isolates that start concurrently
              // is worth more than confirming completion.
              runInBackground(
                c,
                cacheKv
                  .put(BOOTSTRAP_SYNC_KV_KEY(host), '1', {
                    expirationTtl: BOOTSTRAP_SYNC_THROTTLE_SECONDS,
                  })
                  .catch(() => {})
              )
              runInBackground(
                c,
                (async () => {
                  await bootstrapDocumentTypes(c.env.DB).catch((e) =>
                    console.error("[Bootstrap] KV fast-path: error syncing document types:", e)
                  )
                  await autoRegisterCollectionDocumentTypes(c.env.DB).catch((e) =>
                    console.error("[Bootstrap] KV fast-path: error auto-registering collection types:", e)
                  )
                  await bootstrapDefaultContent(c.env.DB).catch((e) =>
                    console.error("[Bootstrap] KV fast-path: error seeding default content:", e)
                  )
                  // Plugin bootstrap is the one piece of the full path that has no other way to
                  // self-heal. If the isolate that set the KV flag was torn down partway through
                  // its install loop, a plugin can be left uninstalled with the flag already
                  // saying "done" — and from then on every isolate takes this fast path and never
                  // looks. isBootstrapNeeded() is a single COUNT, and this whole block is off the
                  // request's critical path, so checking costs one query on a cold isolate.
                  if (!config.plugins?.disableAll) {
                    await (async () => {
                      const bootstrapService = new PluginBootstrapService(c.env.DB)
                      if (await bootstrapService.isBootstrapNeeded()) {
                        console.log("[Bootstrap] KV fast-path: repairing core plugin install")
                        const failed = await bootstrapService.bootstrapCorePlugins()
                        if (failed.length) {
                          console.warn(`[Bootstrap] KV fast-path: core plugin(s) failed to install: ${failed.join(", ")}`)
                        }
                      }
                    })().catch((e) =>
                      console.error("[Bootstrap] KV fast-path: error bootstrapping plugins:", e)
                    )
                  }
                })()
              )
            }
            bootstrapComplete = true
            lastBootstrapFailureAt = 0
            return next()
          }
          // D1 is fresh — delete the stale KV key so the next cold start also re-bootstraps.
          // Host-keyed, so this only ever discards this deployment's own flag.
          cacheKv.delete(BOOTSTRAP_KV_KEY(host)).catch(() => {})
        }
      }
    } catch { /* KV unavailable — fall through to full bootstrap */ }

    // Show branch label automatically on localhost — no env var needed
    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
    const gitBranch = (c.env as any).GIT_BRANCH as string | undefined;
    setBranchLabel(isLocalhost && gitBranch ? gitBranch : undefined);

    try {
      console.log("[Bootstrap] Starting system initialization...");

      // 1. Run idempotent schema compatibility repairs. Migration state and
      // migration execution are owned by Cloudflare D1/Wrangler.
      console.log("[Bootstrap] Checking schema compatibility...");
      const migrationService = new MigrationService(c.env.DB);
      await migrationService.ensureSchemaCompatibility();

      // 1a. Wire the CACHE_KV binding into the cache plugin's singleton store so
      // cache writes survive isolate evictions. Memory-only cache is per-isolate
      // and ephemeral, which makes /admin/cache appear "empty" after restarts.
      try {
        const kv = (c.env as any).CACHE_KV;
        if (kv) {
          const { setGlobalKVNamespace } = await import(
            "../plugins/cache/services/cache"
          );
          setGlobalKVNamespace(kv);
          const { setGlobalCatalogKv, loadKvCatalog } = await import(
            "../plugins/cache/services/catalog"
          );
          setGlobalCatalogKv(kv);
          c.executionCtx.waitUntil(loadKvCatalog());
        }
      } catch (error) {
        console.error("[Bootstrap] Error wiring CACHE_KV namespace:", error);
      }

      // 2. Populate the in-memory collection registry from code-defined configs.
      // This is the source of truth going forward; the DB `collections` table is
      // being decommissioned (see docs/ai/plans/drop-db-collections-plan.md).
      console.log("[Bootstrap] Populating collection registry...");
      try {
        const configs = await loadCollectionConfigs();
        getCollectionRegistry().register(configs);
        console.log(`[Bootstrap] Registry populated with ${configs.length} collection(s)`);
      } catch (error) {
        console.error("[Bootstrap] Error populating collection registry:", error);
      }

      // 3–4. System-data seeding. Ordered in two phases because of a foreign-key
      // dependency that a flat parallel batch violates on a fresh DB:
      //   - PRODUCERS create `document_types` rows.
      //   - CONSUMERS `INSERT INTO documents`, whose `type_id` FK-references those rows.
      // Running all five in one Promise.all let a consumer insert win the race against
      // its producer on a cold DB → `FOREIGN KEY constraint failed`, caught+swallowed
      // per step, leaving RBAC roles / core plugins unseeded (issue #1017).
      console.log("[Bootstrap] Registering document types and seeding system data...");
      const { RbacService } = await import("../services/rbac");
      const rbacService = new RbacService(c.env.DB, (c.env as any).CACHE_KV);

      // Track step failures so we never cache a PARTIAL bootstrap as "done" (below).
      let bootstrapOk = true;
      const runStep = async (label: string, fn: () => Promise<unknown>) => {
        try {
          await fn();
        } catch (e) {
          bootstrapOk = false;
          console.error(`[Bootstrap] Error ${label}:`, e);
        }
      };

      // Phase A — PRODUCERS: register every document type FIRST and await them, so the
      // `document_types` rows are committed before any `documents` insert references them.
      await runStep("registering document types", () => bootstrapDocumentTypes(c.env.DB));
      await runStep("auto-registering collection document types", async () => {
        const auto = await autoRegisterCollectionDocumentTypes(c.env.DB);
        if (auto.length) console.log(`[Bootstrap] Document-backed collections registered: ${auto.join(", ")}`);
      });

      // If Phase A failed, skip Phase B entirely — consumers would hit the same FK
      // constraint this two-phase split exists to prevent.
      if (!bootstrapOk) {
        console.warn("[Bootstrap] Phase A (document type registration) failed — skipping Phase B consumers.");
      } else await Promise.all([
        runStep("repairing credential accounts", () => repairMissingCredentialAccounts(c.env.DB)),

        runStep("seeding RBAC documents", () => rbacService.ensureSystemRbacSeed()),

        runStep("bootstrapping plugins", async () => {
          if (config.plugins?.disableAll) return;
          const bootstrapService = new PluginBootstrapService(c.env.DB);
          if (await bootstrapService.isBootstrapNeeded()) {
            console.log("[Bootstrap] Bootstrapping core plugins...");
            const failed = await bootstrapService.bootstrapCorePlugins();
            if (failed.length) throw new Error(`core plugin(s) not installed: ${failed.join(", ")}`);
          }
        }),
      ]);

      // Seed starter content after types are registered (idempotent no-op when present).
      // Deliberately NOT run through runStep/bootstrapOk: this is a decorative demo post,
      // not a security-critical step like RBAC or plugin seeding.
      await bootstrapDefaultContent(c.env.DB).catch((e) =>
        console.error("[Bootstrap] Error seeding default content:", e)
      );

      // Mark bootstrap complete ONLY when every step succeeded. A partial bootstrap must
      // not latch the in-memory flag or persist the KV skip marker: doing so would cache
      // the broken state for the isolate's lifetime AND for the KV TTL (24h), so every
      // later request/isolate skips the D1 work while roles/plugins stay missing.
      if (bootstrapOk) {
        bootstrapComplete = true;
        console.log("[Bootstrap] System initialization completed");
        try {
          const cacheKv = (c.env as any).CACHE_KV as KVNamespace | undefined
          if (cacheKv) {
            await cacheKv.put(BOOTSTRAP_KV_KEY(host), '1', { expirationTtl: 86400 })
          }
        } catch { /* KV write failure is non-fatal */ }
      } else {
        console.warn("[Bootstrap] System initialization completed WITH ERRORS — not caching the skip marker; the next request will retry.");
      }

      // Project snapshot telemetry — successful runs only.
      if (bootstrapOk) try {
        const registry = getCollectionRegistry();
        const collections = registry.listActive();

        // Count docs per collection type from D1
        const countResult = await c.env.DB.prepare(
          `SELECT type_id, COUNT(*) AS cnt FROM documents
           WHERE is_current_draft = 1 AND deleted_at IS NULL GROUP BY type_id`
        ).all<{ type_id: string; cnt: number }>();
        const countMap: Record<string, number> = {};
        let docTotal = 0;
        for (const row of (countResult.results ?? [])) {
          countMap[row.type_id] = row.cnt;
          docTotal += row.cnt;
        }

        // Field type histogram across all collection schemas
        const fieldTypeHistogram: Record<string, number> = {};
        for (const col of collections) {
          const props = (col.schema as any)?.properties ?? {};
          for (const field of Object.values(props) as any[]) {
            const ft: string = field?.type ?? 'unknown';
            fieldTypeHistogram[ft] = (fieldTypeHistogram[ft] ?? 0) + 1;
          }
        }

        // Plugin names — use allPlugins (all registered, including core) when available
        const pluginSource = allPlugins ?? (config.plugins?.register ?? []) as Array<{ name?: string; id?: string }>;
        const activePlugins = pluginSource.map((p) => p.name ?? String(p.id ?? 'unknown'));

        // Stable installation ID via KV (generated once, persisted)
        let installationId = 'unknown';
        try {
          const kv = (c.env.CACHE_KV ?? c.env.KV) as KVNamespace | undefined;
          if (kv) {
            installationId = (await kv.get('_sonicjs_installation_id')) ?? '';
            if (!installationId) {
              installationId = crypto.randomUUID();
              await kv.put('_sonicjs_installation_id', installationId);
            }
          }
        } catch { /* KV not available */ }

        // Extract deploy origin (scheme + host only — no path, no query, no PII)
        let deployUrl: string | undefined;
        try {
          const u = new URL(c.req.url);
          deployUrl = u.origin; // e.g. "https://example.com"
        } catch { /* malformed URL — skip */ }

        const telemetry = getTelemetryService();
        await telemetry.trackProjectSnapshot({
          installation_id: installationId,
          collection_names: collections.map(c => c.name),
          collection_counts: countMap,
          active_plugins: activePlugins,
          field_type_histogram: fieldTypeHistogram,
          doc_total: docTotal,
          sonicjs_version: SONICJS_VERSION,
          deploy_url: deployUrl,
        });
      } catch { /* silent — telemetry must never break boot */ }
    } catch (error) {
      console.error("[Bootstrap] Error during system initialization:", error);
      // Don't prevent the app from starting, but log the error
    } finally {
      if (!bootstrapComplete) lastBootstrapFailureAt = Date.now();
    }
    } finally {
      // Clear the holder too: on success `bootstrapComplete` keeps everyone out, and on failure
      // the next request should be free to try again rather than inherit a settled promise.
      //
      // Only if the gate is still ours. A request that blew the deadline above and was taken
      // over by a follower must not null out the follower's gate on its way out — that would
      // reopen the stampede it was holding shut.
      releaseBootstrap();
      if (bootstrapInFlight === ownGate) {
        bootstrapInFlight = null;
      }
    }

    return next();
  };
}

/**
 * True when this database carries the system seed a KV bootstrap marker vouches for:
 * the `role-admin` RBAC document and, when plugins are enabled, the `core-auth` plugin
 * document. Any query error counts as "not seeded".
 */
async function isSystemSeedPresent(db: D1Database, requirePlugins: boolean): Promise<boolean> {
  try {
    const row = await db
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM documents WHERE type_id = 'rbac_role' AND slug = 'role-admin'
              AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL) AS roles,
           (SELECT COUNT(*) FROM documents WHERE type_id = 'plugin' AND slug = 'core-auth'
              AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL) AS auth`,
      )
      .first<{ roles: number; auth: number }>();
    if (!row || !row.roles) return false;
    return !requirePlugins || row.auth > 0;
  } catch {
    return false;
  }
}

/**
 * Reset bootstrap flag (useful for testing)
 */
export function resetBootstrap(complete?: boolean) {
  bootstrapComplete = complete ?? false;
  bootstrapInFlight = null;
  bootstrapStartedAt = 0;
  lastBootstrapFailureAt = 0;
  BOOTSTRAP_DEADLINE_MS = 20_000;
  BOOTSTRAP_BACKOFF_MS = 30_000;
  lastSecurityBindings = null
  lastSecurityError = null
  securityWarned = false
}

/** Test-only: override bootstrap timing windows. Undone by resetBootstrap(). */
export function _setBootstrapTimingForTests(timing: { waitMs?: number; retryBackoffMs?: number }) {
  if (timing.waitMs !== undefined) BOOTSTRAP_DEADLINE_MS = timing.waitMs;
  if (timing.retryBackoffMs !== undefined) BOOTSTRAP_BACKOFF_MS = timing.retryBackoffMs;
}

/**
 * Find auth_user rows that have a password_hash but no auth_account credential
 * row (created before Better Auth migration) and repair them. Idempotent —
 * INSERT OR IGNORE means re-runs are safe.
 */
async function repairMissingCredentialAccounts(db: D1Database): Promise<void> {
  const { results } = await db.prepare(`
    SELECT u.id, u.password_hash
    FROM auth_user u
    WHERE u.password_hash IS NOT NULL AND u.password_hash != ''
    AND NOT EXISTS (
      SELECT 1 FROM auth_account a
      WHERE a.user_id = u.id AND a.provider_id = 'credential'
    )
  `).all()

  if (!results.length) return

  console.log(`[Bootstrap] Repairing ${results.length} user(s) missing credential auth_account rows`)
  const nowSec = Math.floor(Date.now() / 1000)
  for (const user of results as Array<{ id: string; password_hash: string }>) {
    await db.prepare(`
      INSERT OR IGNORE INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
      VALUES (?, ?, ?, 'credential', ?, ?, ?)
    `).bind(`cred-${user.id}`, user.id, user.id, user.password_hash, nowSec, nowSec).run()
  }
  console.log(`[Bootstrap] Credential account repair complete (${results.length} repaired)`)
}
