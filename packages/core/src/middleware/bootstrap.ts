import { Context, Next } from "hono";
import { loadCollectionConfigs } from "../services/collection-loader";
import { getCollectionRegistry } from "../services/collection-registry";
import { MigrationService } from "../services/migrations";
import { PluginBootstrapService } from "../services/plugin-bootstrap";
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from "../services/document-types-seed";
import { getHookSystem, hasHookSystem } from "../plugins/hooks/hook-system-singleton";
import { getTelemetryService } from "../services/telemetry-service"
import { SONICJS_VERSION } from "../utils/version";
import type { SonicJSConfig } from "../app";
import { setBranchLabel } from "../templates/layouts/admin-layout-catalyst.template";

type Bindings = {
  DB: D1Database;
  KV: KVNamespace;
  JWT_SECRET?: string;
  CORS_ORIGINS?: string;
  ENVIRONMENT?: string;
};

// Track if bootstrap has been run in this worker instance
let bootstrapComplete = false;

// KV key for cross-isolate bootstrap state. Version-keyed so a code deployment
// (SONICJS_VERSION bump) automatically invalidates the cached flag and forces
// a fresh full bootstrap on the next cold start.
const BOOTSTRAP_KV_KEY = () => `_sonicjs_bootstrap_v${SONICJS_VERSION}`

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

    // Skip if already bootstrapped in this worker instance
    if (bootstrapComplete) {
      return next();
    }

    // Fast KV check: if a previous isolate already ran the full bootstrap for this
    // app version, skip the expensive D1 operations entirely. KV reads are ~10ms
    // vs 5-10s for cold D1. Version-keyed so deployments auto-invalidate the flag.
    try {
      const cacheKv = (c.env as any).CACHE_KV as KVNamespace | undefined
      if (cacheKv) {
        const kvDone = await cacheKv.get(BOOTSTRAP_KV_KEY())
        if (kvDone === '1') {
          // Hydrate in-memory state without touching D1.
          try {
            const kv = (c.env as any).CACHE_KV as KVNamespace
            const { setGlobalKVNamespace } = await import("../plugins/cache/services/cache")
            setGlobalKVNamespace(kv)
            const { setGlobalCatalogKv, loadKvCatalog } = await import("../plugins/cache/services/catalog")
            setGlobalCatalogKv(kv)
            c.executionCtx.waitUntil(loadKvCatalog())
            const { setGlobalTagKv } = await import("../plugins/cache/services/tag-index")
            setGlobalTagKv(kv)
          } catch { /* KV wiring optional */ }
          try {
            const configs = await loadCollectionConfigs()
            getCollectionRegistry().register(configs)
          } catch { /* registry optional in fast-path */ }
          bootstrapComplete = true
          return next()
        }
      }
    } catch { /* KV unavailable — fall through to full bootstrap */ }

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

    // Show branch label automatically on localhost — no env var needed
    const host = c.req.header('host') || '';
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
          const { setGlobalTagKv } = await import("../plugins/cache/services/tag-index");
          setGlobalTagKv(kv);
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

      // 3–4. Independent D1 operations — run in parallel to minimise cold-start latency.
      // Each step has its own error handling so one failure doesn't block the others.
      console.log("[Bootstrap] Registering document types and seeding system data...");
      const { RbacService } = await import("../services/rbac");
      const rbacService = new RbacService(c.env.DB, (c.env as any).CACHE_KV);

      await Promise.all([
        // 3. Register document types (idempotent)
        bootstrapDocumentTypes(c.env.DB).catch((e) =>
          console.error("[Bootstrap] Error registering document types:", e)
        ),

        // 3b. Make every content collection document-backed.
        autoRegisterCollectionDocumentTypes(c.env.DB)
          .then((auto) => {
            if (auto.length) console.log(`[Bootstrap] Document-backed collections registered: ${auto.join(", ")}`)
          })
          .catch((e) => console.error("[Bootstrap] Error auto-registering collection document types:", e)),

        // 2c. Repair legacy credential accounts.
        repairMissingCredentialAccounts(c.env.DB).catch((e) =>
          console.error("[Bootstrap] Error repairing credential accounts:", e)
        ),

        // 3a. Seed system RBAC roles/verbs/grants.
        rbacService.ensureSystemRbacSeed().catch((e) =>
          console.error("[Bootstrap] Error seeding RBAC documents:", e)
        ),

        // 4. Bootstrap core plugins.
        config.plugins?.disableAll
          ? Promise.resolve()
          : (async () => {
              const bootstrapService = new PluginBootstrapService(c.env.DB)
              const needsBootstrap = await bootstrapService.isBootstrapNeeded()
              if (needsBootstrap) {
                console.log("[Bootstrap] Bootstrapping core plugins...")
                await bootstrapService.bootstrapCorePlugins()
              }
            })().catch((e) => console.error("[Bootstrap] Error bootstrapping plugins:", e)),
      ])

      // Mark bootstrap as complete for this worker instance and persist to KV
      // so subsequent cold-start isolates can skip the D1 work entirely.
      bootstrapComplete = true;
      console.log("[Bootstrap] System initialization completed");
      try {
        const cacheKv = (c.env as any).CACHE_KV as KVNamespace | undefined
        if (cacheKv) {
          // 24h TTL — long enough that hot instances never re-bootstrap, short
          // enough that a DB reset auto-heals within a day.
          await cacheKv.put(BOOTSTRAP_KV_KEY(), '1', { expirationTtl: 86400 })
        }
      } catch { /* KV write failure is non-fatal */ }

      // Fire project snapshot telemetry (fire-and-forget, never blocks boot)
      try {
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
          const kv = c.env.KV as KVNamespace | undefined;
          if (kv) {
            installationId = (await kv.get('_sonicjs_installation_id')) ?? '';
            if (!installationId) {
              installationId = crypto.randomUUID();
              await kv.put('_sonicjs_installation_id', installationId);
            }
          }
        } catch { /* KV not available */ }

        const telemetry = getTelemetryService();
        await telemetry.trackProjectSnapshot({
          installation_id: installationId,
          collection_names: collections.map(c => c.name),
          collection_counts: countMap,
          active_plugins: activePlugins,
          field_type_histogram: fieldTypeHistogram,
          doc_total: docTotal,
          sonicjs_version: SONICJS_VERSION,
        });
      } catch { /* silent — telemetry must never break boot */ }
    } catch (error) {
      console.error("[Bootstrap] Error during system initialization:", error);
      // Don't prevent the app from starting, but log the error
    }

    // 4. Verify security configuration (outside try/catch so critical
    // errors in production propagate and prevent insecure deployments)
    verifySecurityConfig(c.env as Bindings);

    return next();
  };
}

/**
 * Reset bootstrap flag (useful for testing)
 */
export function resetBootstrap() {
  bootstrapComplete = false;
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
