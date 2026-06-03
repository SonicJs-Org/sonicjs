/**
 * Compat shim for a transitive bundling incompatibility:
 *   @better-auth/kysely-adapter imports DEFAULT_MIGRATION_TABLE /
 *   DEFAULT_MIGRATION_LOCK_TABLE (and friends) from "kysely", but kysely 0.29
 *   relocated those to "kysely/migration". The main entry now only has a
 *   type-error stub, so esbuild (wrangler) fails with "No matching export".
 *
 * We alias the bare "kysely" specifier to this file (see wrangler.toml [alias]).
 * kysely's package `exports` map blocks subpath specifiers, so we reach the real
 * files via relative node_modules paths (which bypass the exports map). kysely
 * is hoisted to the workspace root, hence the ../node_modules path.
 *
 * Remove when better-auth's kysely adapter is patched (watch better-auth 1.7.x).
 */
export * from '../node_modules/kysely/dist/index.js'
export {
  DEFAULT_MIGRATION_TABLE,
  DEFAULT_MIGRATION_LOCK_TABLE,
  DEFAULT_ALLOW_UNORDERED_MIGRATIONS,
  MIGRATION_LOCK_ID,
  NO_MIGRATIONS,
} from '../node_modules/kysely/dist/migration/migrator.js'
