import { isFirstUserRegistration, isRegistrationEnabled } from './chunk-F2IDJF3K.js';
import { verification, account, session, users } from './chunk-4LLMM7J6.js';
import { betterAuth } from 'better-auth';
import { withCloudflare } from 'better-auth-cloudflare';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { APIError } from 'better-auth/api';
import { drizzle } from 'drizzle-orm/d1';

async function verifyLegacyPbkdf2(password, stored) {
  const parts = stored.split(":");
  if (parts.length !== 4) return false;
  const iterations = parseInt(parts[1], 10);
  const saltBytes = parts[2].match(/.{2}/g);
  if (!saltBytes || !Number.isFinite(iterations)) return false;
  const salt = new Uint8Array(saltBytes.map((b) => parseInt(b, 16)));
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, km, 256);
  const actual = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const expected = parts[3];
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
function getDefaultAuthOptions(env) {
  const db = drizzle(env.DB);
  return {
    secret: env.BETTER_AUTH_SECRET,
    baseURL: env.BETTER_AUTH_URL,
    appName: "SonicJS",
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: false,
        cf: {},
        d1: {
          db,
          options: {
            // Map Better Auth models to the existing SonicJS tables. Keys must
            // match each model's resolved table name (modelName below): the user
            // model resolves to the `users` table.
            schema: { users, session, account, verification }
          }
        },
        kv: env.CACHE_KV
        // session secondary storage → getSession skips D1
      },
      {
        basePath: "/auth",
        emailAndPassword: {
          enabled: true,
          autoSignIn: true,
          // Transparent migration of SonicJS legacy PBKDF2 hashes: verify against
          // the old format on login, then re-hash to scrypt and persist. No
          // mass-rehash, no forced password resets.
          password: {
            verify: async ({ hash, password }) => {
              if (hash.startsWith("pbkdf2:")) {
                const ok = await verifyLegacyPbkdf2(password, hash);
                if (ok) {
                  const upgraded = await hashPassword(password);
                  await env.DB.prepare("UPDATE account SET password = ?, updated_at = ? WHERE password = ?").bind(upgraded, Math.floor(Date.now() / 1e3), hash).run();
                }
                return ok;
              }
              return verifyPassword({ hash, password });
            }
          }
        },
        user: {
          modelName: "users",
          // Field-mapping values are Drizzle *property keys* (camelCase), which
          // already match Better Auth's defaults for emailVerified/createdAt/
          // updatedAt. Only `image` differs (SonicJS uses `avatar`).
          fields: {
            image: "avatar"
          },
          additionalFields: {
            role: { type: "string", required: false, defaultValue: "viewer", input: false },
            username: { type: "string", required: false, defaultValue: "", input: true },
            firstName: { type: "string", required: false, defaultValue: "", input: true },
            lastName: { type: "string", required: false, defaultValue: "", input: true }
          }
        },
        session: {
          modelName: "session",
          // Drizzle property keys already match Better Auth defaults (userId,
          // expiresAt, ipAddress, …) — no field overrides needed.
          expiresIn: 60 * 60 * 24 * 7,
          // 7 days
          updateAge: 60 * 60 * 24
          // refresh once per day
        },
        account: { modelName: "account" },
        verification: { modelName: "verification" },
        databaseHooks: {
          user: {
            create: {
              before: async (userData) => {
                const isFirst = await isFirstUserRegistration(env.DB);
                if (!isFirst) {
                  const enabled = await isRegistrationEnabled(env.DB);
                  if (!enabled) {
                    throw new APIError("BAD_REQUEST", { message: "Registration is currently disabled." });
                  }
                }
                const d = userData;
                const name = (d.name ?? "User").toString();
                const parts = name.trim().split(/\s+/);
                const email = d.email ?? "";
                const firstName = d.firstName || parts[0] || "User";
                const lastName = d.lastName || parts.slice(1).join(" ") || firstName;
                const username = d.username || (email ? email.split("@")[0] : `user${Math.floor(Date.now() / 1e3)}`);
                return { data: { ...userData, name, firstName, lastName, username, role: "viewer" } };
              },
              after: async (user) => {
                const result = await env.DB.prepare(
                  "SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND id != ?"
                ).bind(user.id).first();
                if ((result?.count ?? 0) === 0) {
                  await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(user.id).run();
                }
                try {
                  const row = await env.DB.prepare("SELECT role FROM users WHERE id = ?").bind(user.id).first();
                  const roleName = row?.role ?? "viewer";
                  await env.DB.prepare(
                    "INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) SELECT ?, id FROM rbac_roles WHERE name = ?"
                  ).bind(user.id, roleName).run();
                } catch {
                }
              }
            }
          }
        }
      }
    )
  };
}
function createAuth(env, extendBetterAuth) {
  const defaults = getDefaultAuthOptions(env);
  const options = extendBetterAuth ? extendBetterAuth(defaults) : defaults;
  return betterAuth(options);
}

export { createAuth, getDefaultAuthOptions };
//# sourceMappingURL=chunk-FCOOEYJ2.js.map
//# sourceMappingURL=chunk-FCOOEYJ2.js.map