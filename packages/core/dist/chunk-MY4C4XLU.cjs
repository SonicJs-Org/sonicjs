'use strict';

var chunkBI3XUVJ7_cjs = require('./chunk-BI3XUVJ7.cjs');
var chunkLYRRV5HB_cjs = require('./chunk-LYRRV5HB.cjs');
var chunkOCVYREFQ_cjs = require('./chunk-OCVYREFQ.cjs');
var chunkRCQ2HIQD_cjs = require('./chunk-RCQ2HIQD.cjs');
var jwt = require('hono/jwt');
var cookie = require('hono/cookie');

// src/middleware/bootstrap.ts
var bootstrapComplete = false;
function verifySecurityConfig(env) {
  const warnings = [];
  if (!env.JWT_SECRET) {
    warnings.push(
      "JWT_SECRET is not set \u2014 using hardcoded fallback. Set via `wrangler secret put JWT_SECRET`"
    );
  } else if (env.JWT_SECRET.includes("change-in-production")) {
    warnings.push(
      "JWT_SECRET contains the default value \u2014 tokens are forgeable. Generate a strong random secret"
    );
  }
  if (!env.CORS_ORIGINS) {
    warnings.push(
      "CORS_ORIGINS is not set \u2014 all cross-origin API requests will be rejected"
    );
  }
  if (!env.ENVIRONMENT) {
    warnings.push(
      'ENVIRONMENT is not set \u2014 HSTS header will not be applied. Set to "production" or "development"'
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
    const hasCritical = !env.JWT_SECRET || env.JWT_SECRET.includes("change-in-production");
    if (hasCritical) {
      throw new Error(
        "[SonicJS Security] CRITICAL: Production deployment is missing a secure JWT_SECRET. Set it via `wrangler secret put JWT_SECRET` before deploying."
      );
    }
  }
}
function bootstrapMiddleware(config = {}) {
  return async (c, next) => {
    if (bootstrapComplete) {
      return next();
    }
    const path = c.req.path;
    if (path.startsWith("/images/") || path.startsWith("/assets/") || path === "/health" || path.endsWith(".js") || path.endsWith(".css") || path.endsWith(".png") || path.endsWith(".jpg") || path.endsWith(".ico")) {
      return next();
    }
    try {
      console.log("[Bootstrap] Starting system initialization...");
      console.log("[Bootstrap] Running database migrations...");
      const migrationService = new chunkOCVYREFQ_cjs.MigrationService(c.env.DB);
      await migrationService.runPendingMigrations();
      console.log("[Bootstrap] Syncing collection configurations...");
      try {
        await chunkLYRRV5HB_cjs.syncCollections(c.env.DB);
      } catch (error) {
        console.error("[Bootstrap] Error syncing collections:", error);
      }
      console.log("[Bootstrap] Syncing form collections...");
      try {
        await chunkLYRRV5HB_cjs.syncAllFormCollections(c.env.DB);
      } catch (error) {
        console.error("[Bootstrap] Error syncing form collections:", error);
      }
      if (!config.plugins?.disableAll) {
        console.log("[Bootstrap] Bootstrapping core plugins...");
        const bootstrapService = new chunkLYRRV5HB_cjs.PluginBootstrapService(c.env.DB);
        const needsBootstrap = await bootstrapService.isBootstrapNeeded();
        if (needsBootstrap) {
          await bootstrapService.bootstrapCorePlugins();
        }
      } else {
        console.log("[Bootstrap] Plugin bootstrap skipped (disableAll is true)");
      }
      bootstrapComplete = true;
      console.log("[Bootstrap] System initialization completed");
    } catch (error) {
      console.error("[Bootstrap] Error during system initialization:", error);
    }
    verifySecurityConfig(c.env);
    return next();
  };
}
var JWT_SECRET_FALLBACK = "your-super-secret-jwt-key-change-in-production";
var DEFAULT_JWT_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 30;
function parseDuration(input) {
  if (input === void 0 || input === null || input === "") return null;
  if (typeof input === "number" && Number.isFinite(input) && input > 0) {
    return Math.floor(input);
  }
  const raw = String(input).trim();
  if (/^\d+$/.test(raw)) {
    const n = parseInt(raw, 10);
    return n > 0 ? n : null;
  }
  const match = raw.match(/^(\d+)\s*(s|sec|secs|seconds|m|min|mins|minutes|h|hr|hrs|hours|d|day|days)$/i);
  if (!match) return null;
  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  if (unit.startsWith("s")) return value;
  if (unit.startsWith("m")) return value * 60;
  if (unit.startsWith("h")) return value * 60 * 60;
  if (unit.startsWith("d")) return value * 60 * 60 * 24;
  return null;
}
function getJwtExpirySeconds(env) {
  const configured = parseDuration(env?.JWT_EXPIRES_IN);
  return configured ?? DEFAULT_JWT_EXPIRES_IN_SECONDS;
}
async function getJwtExpirySecondsFromDb(db, env) {
  const envParsed = parseDuration(env?.JWT_EXPIRES_IN);
  if (envParsed) return envParsed;
  if (db) {
    try {
      const row = await db.prepare("SELECT value FROM settings WHERE category = 'security' AND key = 'jwtExpiresIn'").first();
      if (row?.value) {
        let stored = row.value;
        try {
          stored = JSON.parse(row.value);
        } catch {
        }
        const parsed = parseDuration(stored);
        if (parsed) return parsed;
      }
    } catch (err) {
      console.warn("Failed to read jwtExpiresIn from settings, falling back to default:", err);
    }
  }
  return DEFAULT_JWT_EXPIRES_IN_SECONDS;
}
async function getJwtRefreshGraceSecondsFromDb(db, env) {
  const DEFAULT_GRACE = 60 * 60 * 24 * 7;
  const envParsed = parseDuration(env?.JWT_REFRESH_GRACE_SECONDS);
  if (envParsed) return envParsed;
  if (db) {
    try {
      const row = await db.prepare("SELECT value FROM settings WHERE category = 'security' AND key = 'jwtRefreshGraceSeconds'").first();
      if (row?.value) {
        let stored = row.value;
        try {
          stored = JSON.parse(row.value);
        } catch {
        }
        const parsed = parseDuration(stored);
        if (parsed) return parsed;
      }
    } catch (err) {
      console.warn("Failed to read jwtRefreshGraceSeconds from settings:", err);
    }
  }
  return DEFAULT_GRACE;
}
function decodeJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
    const json = atob(padded);
    const obj = JSON.parse(json);
    if (!obj || typeof obj.exp !== "number") return null;
    return obj;
  } catch {
    return null;
  }
}
function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function verifyHs256Signature(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = base64UrlToBytes(parts[2]);
    const message = encoder.encode(`${parts[0]}.${parts[1]}`);
    return await crypto.subtle.verify("HMAC", key, signature, message);
  } catch {
    return false;
  }
}
var AuthManager = class _AuthManager {
  static async generateToken(userId, email, role, secret, expiresInSeconds) {
    const ttl = expiresInSeconds && expiresInSeconds > 0 ? Math.floor(expiresInSeconds) : DEFAULT_JWT_EXPIRES_IN_SECONDS;
    const now = Math.floor(Date.now() / 1e3);
    const payload = {
      userId,
      email,
      role,
      exp: now + ttl,
      iat: now
    };
    return await jwt.sign(payload, secret || JWT_SECRET_FALLBACK, "HS256");
  }
  /**
   * Verify a token's signature and expiration.
   *
   * IMPORTANT: pass the `JWT_SECRET` binding (e.g. `c.env.JWT_SECRET`) as the
   * `secret` argument. If omitted, this falls back to a development-only
   * placeholder secret — tokens signed with the real `JWT_SECRET` will then
   * silently fail verification. From inside a Hono handler prefer
   * `AuthManager.verifyAuthRequest(c)`, which handles header/cookie extraction
   * and pulls the secret from `c.env` for you.
   *
   * If `graceSeconds` > 0, tokens whose `exp` is within the grace window
   * (i.e. expired by no more than `graceSeconds`) are still returned. This
   * supports a sliding-session refresh endpoint that accepts recently-expired
   * tokens. Signature failures always return null.
   */
  static async verifyToken(token, secret, graceSeconds = 0) {
    const effectiveSecret = secret || JWT_SECRET_FALLBACK;
    try {
      let payload = null;
      try {
        payload = await jwt.verify(token, effectiveSecret, "HS256");
      } catch (verifyError) {
        const name = verifyError?.name || "";
        const message = String(verifyError?.message || "");
        const isExpired = name === "JwtTokenExpired" || message.includes("expired");
        if (!isExpired || graceSeconds <= 0) {
          throw verifyError;
        }
        const signatureValid = await verifyHs256Signature(token, effectiveSecret);
        if (!signatureValid) return null;
        const decoded = decodeJwtPayload(token);
        if (!decoded) return null;
        payload = decoded;
      }
      if (!payload) return null;
      const now = Math.floor(Date.now() / 1e3);
      if (payload.exp < now - Math.max(0, Math.floor(graceSeconds))) {
        return null;
      }
      return payload;
    } catch (error) {
      console.error("Token verification failed:", error);
      return null;
    }
  }
  /**
   * Verify the JWT on an incoming Hono request using the `JWT_SECRET`
   * binding from `c.env`. Reads the token from the `Authorization: Bearer …`
   * header first, then falls back to the `auth_token` cookie. Returns the
   * decoded payload, or null when the token is missing, malformed, expired,
   * or signed with a different secret.
   *
   * Use this from custom Hono routes mounted alongside SonicJS — it
   * resolves the secret the same way `requireAuth()` does, without forcing
   * the caller to plumb it through manually.
   */
  static async verifyAuthRequest(c) {
    let token = c.req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      token = cookie.getCookie(c, "auth_token");
    }
    if (!token) return null;
    const secret = c.env?.JWT_SECRET;
    return await _AuthManager.verifyToken(token, secret);
  }
  static async hashPassword(password) {
    const iterations = 1e5;
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return `pbkdf2:${iterations}:${saltHex}:${hashHex}`;
  }
  static async hashPasswordLegacy(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + "salt-change-in-production");
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  static async verifyPassword(password, storedHash) {
    if (storedHash.startsWith("pbkdf2:")) {
      const parts = storedHash.split(":");
      if (parts.length !== 4) return false;
      const iterationsStr = parts[1];
      const saltHex = parts[2];
      const expectedHashHex = parts[3];
      const iterations = parseInt(iterationsStr, 10);
      const saltBytes = saltHex.match(/.{2}/g);
      if (!saltBytes) return false;
      const salt = new Uint8Array(saltBytes.map((byte) => parseInt(byte, 16)));
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );
      const hashBuffer = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations,
          hash: "SHA-256"
        },
        keyMaterial,
        256
      );
      const actualHashHex = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
      if (actualHashHex.length !== expectedHashHex.length) return false;
      let result2 = 0;
      for (let i = 0; i < actualHashHex.length; i++) {
        result2 |= actualHashHex.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
      }
      return result2 === 0;
    }
    const legacyHash = await this.hashPasswordLegacy(password);
    if (legacyHash.length !== storedHash.length) return false;
    let result = 0;
    for (let i = 0; i < legacyHash.length; i++) {
      result |= legacyHash.charCodeAt(i) ^ storedHash.charCodeAt(i);
    }
    return result === 0;
  }
  static isLegacyHash(storedHash) {
    return !storedHash.startsWith("pbkdf2:");
  }
  /**
   * Set authentication cookie - useful for plugins implementing alternative auth methods
   * @param c - Hono context
   * @param token - JWT token to set in cookie
   * @param options - Optional cookie configuration
   */
  static setAuthCookie(c, token, options) {
    cookie.setCookie(c, "auth_token", token, {
      httpOnly: options?.httpOnly ?? true,
      secure: options?.secure ?? true,
      sameSite: options?.sameSite ?? "Strict",
      maxAge: options?.maxAge ?? getJwtExpirySeconds(c?.env)
    });
  }
};
var requireAuth = () => {
  return async (c, next) => {
    const user = c.get("user");
    if (!user) {
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=Please login to access the admin area");
      }
      return c.json({ error: "Authentication required" }, 401);
    }
    return await next();
  };
};
var requireRole = (requiredRole) => {
  return async (c, next) => {
    const user = c.get("user");
    if (!user) {
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=Please login to access the admin area");
      }
      return c.json({ error: "Authentication required" }, 401);
    }
    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    if (!roles.includes(user.role)) {
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=You do not have permission to access this area");
      }
      return c.json({ error: "Insufficient permissions" }, 403);
    }
    return await next();
  };
};
var requireRbac = (resource, verb) => {
  return async (c, next) => {
    const user = c.get("user");
    if (!user) {
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=Please login to access the admin area");
      }
      return c.json({ error: "Authentication required" }, 401);
    }
    const allowed = await new chunkBI3XUVJ7_cjs.RbacService(c.env.DB).can(user.userId, resource, verb);
    if (!allowed) {
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=You do not have permission to access this area");
      }
      return c.json({ error: "Insufficient permissions" }, 403);
    }
    return await next();
  };
};
var optionalAuth = () => {
  return async (_c, next) => {
    return await next();
  };
};

// src/middleware/metrics.ts
var metricsMiddleware = () => {
  return async (c, next) => {
    const path = new URL(c.req.url).pathname;
    if (path !== "/admin/dashboard/api/metrics") {
      chunkRCQ2HIQD_cjs.metricsTracker.recordRequest();
    }
    await next();
  };
};
var JWT_SECRET_FALLBACK2 = "your-super-secret-jwt-key-change-in-production";
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function getHmacKey(secret) {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
async function generateCsrfToken(secret) {
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = arrayBufferToBase64Url(nonceBytes.buffer);
  const key = await getHmacKey(secret);
  const encoder = new TextEncoder();
  const signatureBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(nonce));
  const signature = arrayBufferToBase64Url(signatureBuffer);
  return `${nonce}.${signature}`;
}
async function validateCsrfToken(token, secret) {
  if (!token || typeof token !== "string") return false;
  const dotIndex = token.indexOf(".");
  if (dotIndex === -1) return false;
  const nonce = token.substring(0, dotIndex);
  const signature = token.substring(dotIndex + 1);
  if (!nonce || !signature) return false;
  try {
    const key = await getHmacKey(secret);
    const encoder = new TextEncoder();
    const sigPadded = signature.replace(/-/g, "+").replace(/_/g, "/");
    const sigBinary = atob(sigPadded);
    const sigBytes = new Uint8Array(sigBinary.length);
    for (let i = 0; i < sigBinary.length; i++) {
      sigBytes[i] = sigBinary.charCodeAt(i);
    }
    return await crypto.subtle.verify("HMAC", key, sigBytes.buffer, encoder.encode(nonce));
  } catch {
    return false;
  }
}
var DEFAULT_EXEMPT_PATHS = [
  "/auth/login",
  "/auth/register",
  "/auth/seed-admin",
  "/auth/accept-invitation",
  "/auth/reset-password",
  "/auth/request-password-reset",
  "/auth/otp",
  "/auth/magic-link",
  "/auth/verify",
  // Better Auth API endpoints — Better Auth enforces its own CSRF via trusted
  // origins, so they are exempt from SonicJS's token check (startsWith match).
  "/auth/sign-in",
  "/auth/sign-up",
  "/auth/sign-out",
  "/auth/callback",
  "/auth/get-session",
  "/api/stripe/webhook",
  "/api/events"
];
function isExemptPath(path, extraExemptPaths = []) {
  if (path.startsWith("/forms/") || path.startsWith("/api/forms/") || path === "/forms" || path === "/api/forms") {
    return true;
  }
  if (path.startsWith("/api/search")) {
    return true;
  }
  const allExempt = [...DEFAULT_EXEMPT_PATHS, ...extraExemptPaths];
  for (const exempt of allExempt) {
    if (path === exempt || path.startsWith(exempt + "/")) {
      return true;
    }
  }
  return false;
}
function csrfProtection(options = {}) {
  return async (c, next) => {
    const method = c.req.method.toUpperCase();
    const path = new URL(c.req.url).pathname;
    const secret = c.env?.JWT_SECRET || JWT_SECRET_FALLBACK2;
    if (c.env?.ENVIRONMENT === "production" && !c.env?.JWT_SECRET) {
      console.warn(
        "[CSRF] WARNING: JWT_SECRET is not set in production. CSRF tokens are signed with the fallback key, which is insecure."
      );
    }
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      await ensureCsrfCookie(c, secret);
      await next();
      return;
    }
    if (isExemptPath(path, options.exemptPaths)) {
      await next();
      return;
    }
    const authCookie = cookie.getCookie(c, "auth_token");
    if (!authCookie) {
      await next();
      return;
    }
    const baSession = cookie.getCookie(c, "better-auth.session_token") || cookie.getCookie(c, "__Secure-better-auth.session_token");
    if (baSession) {
      await next();
      return;
    }
    const authHeader = c.req.header("Authorization");
    if (authHeader) {
      await next();
      return;
    }
    const cookieToken = cookie.getCookie(c, "csrf_token");
    let headerToken = c.req.header("X-CSRF-Token");
    if (!headerToken) {
      const contentType = c.req.header("Content-Type") || "";
      if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
        try {
          const body = await c.req.parseBody();
          headerToken = body["_csrf"];
        } catch {
        }
      }
    }
    if (!cookieToken || !headerToken) {
      return csrfError(c, "CSRF token missing");
    }
    if (cookieToken !== headerToken) {
      return csrfError(c, "CSRF token mismatch");
    }
    const isValid = await validateCsrfToken(cookieToken, secret);
    if (!isValid) {
      return csrfError(c, "CSRF token invalid");
    }
    await next();
  };
}
async function ensureCsrfCookie(c, secret) {
  const existing = cookie.getCookie(c, "csrf_token");
  if (existing) {
    const isValid = await validateCsrfToken(existing, secret);
    if (isValid) {
      c.set("csrfToken", existing);
      return;
    }
  }
  const token = await generateCsrfToken(secret);
  c.set("csrfToken", token);
  const isDev = c.env?.ENVIRONMENT === "development" || !c.env?.ENVIRONMENT;
  cookie.setCookie(c, "csrf_token", token, {
    httpOnly: false,
    // JS must read this cookie
    secure: !isDev,
    sameSite: "Strict",
    path: "/",
    maxAge: 86400
    // 24 hours — browser-side expiry
  });
}
function csrfError(c, message) {
  const accept = c.req.header("Accept") || "";
  if (accept.includes("text/html")) {
    return c.html(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>${message}</p></body></html>`,
      403
    );
  }
  return c.json({ error: message, status: 403 }, 403);
}

// src/middleware/rate-limit.ts
function rateLimit(options) {
  const { max, windowMs, keyPrefix } = options;
  return async (c, next) => {
    const kv = c.env?.CACHE_KV;
    if (!kv) {
      return await next();
    }
    const ip = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown";
    const key = `ratelimit:${keyPrefix}:${ip}`;
    try {
      const now = Date.now();
      const stored = await kv.get(key, "json");
      let entry;
      if (stored && stored.resetAt > now) {
        entry = stored;
      } else {
        entry = { count: 0, resetAt: now + windowMs };
      }
      entry.count++;
      const ttlSeconds = Math.ceil((entry.resetAt - now) / 1e3);
      if (entry.count > max) {
        await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 60) });
        const retryAfter = Math.ceil((entry.resetAt - now) / 1e3);
        c.header("Retry-After", String(retryAfter));
        c.header("X-RateLimit-Limit", String(max));
        c.header("X-RateLimit-Remaining", "0");
        c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1e3)));
        return c.json({ error: "Too many requests. Please try again later." }, 429);
      }
      await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 60) });
      c.header("X-RateLimit-Limit", String(max));
      c.header("X-RateLimit-Remaining", String(max - entry.count));
      c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1e3)));
      return await next();
    } catch (error) {
      console.error("Rate limiter error (non-fatal):", error);
      return await next();
    }
  };
}

// src/middleware/security-headers.ts
var securityHeadersMiddleware = () => {
  return async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "SAMEORIGIN");
    c.header("Referrer-Policy", "strict-origin-when-cross-origin");
    c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    const environment = c.env?.ENVIRONMENT;
    if (environment !== "development") {
      c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
  };
};

// src/middleware/index.ts
var loggingMiddleware = () => async (_c, next) => await next();
var detailedLoggingMiddleware = () => async (_c, next) => await next();
var securityLoggingMiddleware = () => async (_c, next) => await next();
var performanceLoggingMiddleware = () => async (_c, next) => await next();
var cacheHeaders = () => async (_c, next) => await next();
var compressionMiddleware = async (_c, next) => await next();
var PermissionManager = {};
var requirePermission = () => async (_c, next) => await next();
var requireAnyPermission = () => async (_c, next) => await next();
var logActivity = () => {
};
var requireActivePlugin = () => async (_c, next) => await next();
var requireActivePlugins = () => async (_c, next) => await next();
var getActivePlugins = () => [];
var isPluginActive = () => false;

exports.AuthManager = AuthManager;
exports.PermissionManager = PermissionManager;
exports.bootstrapMiddleware = bootstrapMiddleware;
exports.cacheHeaders = cacheHeaders;
exports.compressionMiddleware = compressionMiddleware;
exports.csrfProtection = csrfProtection;
exports.detailedLoggingMiddleware = detailedLoggingMiddleware;
exports.generateCsrfToken = generateCsrfToken;
exports.getActivePlugins = getActivePlugins;
exports.getJwtExpirySeconds = getJwtExpirySeconds;
exports.getJwtExpirySecondsFromDb = getJwtExpirySecondsFromDb;
exports.getJwtRefreshGraceSecondsFromDb = getJwtRefreshGraceSecondsFromDb;
exports.isPluginActive = isPluginActive;
exports.logActivity = logActivity;
exports.loggingMiddleware = loggingMiddleware;
exports.metricsMiddleware = metricsMiddleware;
exports.optionalAuth = optionalAuth;
exports.performanceLoggingMiddleware = performanceLoggingMiddleware;
exports.rateLimit = rateLimit;
exports.requireActivePlugin = requireActivePlugin;
exports.requireActivePlugins = requireActivePlugins;
exports.requireAnyPermission = requireAnyPermission;
exports.requireAuth = requireAuth;
exports.requirePermission = requirePermission;
exports.requireRbac = requireRbac;
exports.requireRole = requireRole;
exports.securityHeadersMiddleware = securityHeadersMiddleware;
exports.securityLoggingMiddleware = securityLoggingMiddleware;
exports.validateCsrfToken = validateCsrfToken;
exports.verifySecurityConfig = verifySecurityConfig;
//# sourceMappingURL=chunk-MY4C4XLU.cjs.map
//# sourceMappingURL=chunk-MY4C4XLU.cjs.map