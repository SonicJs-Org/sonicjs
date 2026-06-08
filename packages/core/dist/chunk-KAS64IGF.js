import { isFirstUserRegistration, isRegistrationEnabled } from './chunk-F2IDJF3K.js';
import { verification, account, session, users } from './chunk-REZQ3JKD.js';
import { betterAuth } from 'better-auth';
import { withCloudflare } from 'better-auth-cloudflare';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { APIError } from 'better-auth/api';
import { magicLink } from 'better-auth/plugins/magic-link';
import { emailOTP } from 'better-auth/plugins/email-otp';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { organization } from 'better-auth/plugins/organization';
import { drizzle } from 'drizzle-orm/d1';

async function sendViaEmailPlugin(db, to, subject, html) {
  try {
    const row = await db.prepare("SELECT settings FROM plugins WHERE id = 'email'").first();
    if (row?.settings) {
      const { apiKey, fromEmail, fromName } = JSON.parse(row.settings);
      if (apiKey && fromEmail) {
        await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            from: `${fromName ?? "SonicJS"} <${fromEmail}>`,
            to: [to],
            subject,
            html
          })
        });
        return;
      }
    }
  } catch {
  }
  console.log(`[email-dev] To:${to} | Subject:${subject}`);
}
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
                  await env.DB.prepare(
                    "UPDATE account SET password = ?, updated_at = ? WHERE password = ? AND provider_id = 'credential'"
                  ).bind(upgraded, Math.floor(Date.now() / 1e3), hash).run();
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
                try {
                  const result = await env.DB.prepare(
                    `SELECT COUNT(*) as count FROM rbac_user_roles ur
                     JOIN rbac_roles r ON r.id = ur.role_id
                     WHERE r.name = 'admin' AND ur.user_id != ?`
                  ).bind(user.id).first();
                  const roleName = (result?.count ?? 0) === 0 ? "admin" : "viewer";
                  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(roleName, user.id).run();
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
    ),
    // ── Phase 4: BA-native login methods ─────────────────────────────────────
    // Magic-link and Email-OTP replace the standalone SonicJS plugins that
    // minted JWT cookies. Social providers replace the bespoke oauth-providers
    // plugin. All are gated on the relevant env vars / email service config
    // so they activate only when configured.
    plugins: [
      // Magic-link passwordless auth. Sends a one-time link to the user's inbox;
      // the link resolves to a BA session. Requires a working email service.
      magicLink({
        sendMagicLink: async ({ email, url }, _request) => {
          await sendViaEmailPlugin(
            env.DB,
            email,
            "Your sign-in link",
            `<div style="font-family:sans-serif;max-width:600px">
              <h2>Sign in to SonicJS</h2>
              <p>Click the link below to sign in. Expires in 15 minutes.</p>
              <p><a href="${url}" style="background:#465FFF;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none">Sign in</a></p>
              <p style="color:#666;font-size:12px">Or copy: ${url}</p>
            </div>`
          );
        },
        expiresIn: 15 * 60
      }),
      // Email OTP — 6-digit code sent to inbox. Replaces the otp-login-plugin.
      emailOTP({
        sendVerificationOTP: async (params, _request) => {
          await sendViaEmailPlugin(
            env.DB,
            params.email,
            "Your sign-in code",
            `<div style="font-family:sans-serif;max-width:600px">
              <h2>Your one-time code</h2>
              <p style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#465FFF">${params.otp}</p>
              <p style="color:#666">Expires in 10 minutes. Do not share this code.</p>
            </div>`
          );
        },
        otpLength: 6,
        expiresIn: 10 * 60
      }),
      // ── Phase 6: 2FA / TOTP ────────────────────────────────────────────────
      // twoFactor adds /auth/two-factor/* endpoints for TOTP enrollment +
      // verification. Requires migration 042 to create the `twoFactor` table.
      twoFactor({
        issuer: "SonicJS",
        totpOptions: {
          digits: 6,
          period: 30
        }
      }),
      // ── Phase 6: Multi-tenant organizations ───────────────────────────────
      // organization adds /auth/organization/* endpoints for team management.
      // Requires migration 042 (organization tables).
      organization()
    ],
    // ── Phase 4: Social providers ─────────────────────────────────────────
    // Activated when the relevant env vars are set. Replaces the bespoke
    // oauth-providers SonicJS plugin. Set via wrangler secret put / .dev.vars.
    socialProviders: {
      ...env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET ? { github: { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET } } : {},
      ...env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET ? { google: { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET } } : {}
    }
  };
}
function createAuth(env, extendBetterAuth) {
  if (!env.BETTER_AUTH_SECRET || env.BETTER_AUTH_SECRET.length < 16) {
    throw new Error(
      "BETTER_AUTH_SECRET is missing or too short. Set it as a Wrangler secret (wrangler secret put BETTER_AUTH_SECRET) or in a gitignored .dev.vars for local dev. Refusing to initialize auth without a strong signing secret."
    );
  }
  const defaults = getDefaultAuthOptions(env);
  const options = extendBetterAuth ? extendBetterAuth(defaults) : defaults;
  return betterAuth(options);
}

export { createAuth, getDefaultAuthOptions };
//# sourceMappingURL=chunk-KAS64IGF.js.map
//# sourceMappingURL=chunk-KAS64IGF.js.map