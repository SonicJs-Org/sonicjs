'use strict';

var chunkXEITDGR3_cjs = require('./chunk-XEITDGR3.cjs');
var chunk2FZKSSOF_cjs = require('./chunk-2FZKSSOF.cjs');
var chunkRCQ2HIQD_cjs = require('./chunk-RCQ2HIQD.cjs');
var jwt = require('hono/jwt');
var cookie = require('hono/cookie');

// src/services/form-collection-sync.ts
var SYSTEM_FORM_USER_ID = "system-form-submission";
function mapFormioTypeToSchemaType(component) {
  switch (component.type) {
    case "textfield":
    case "textarea":
    case "password":
    case "phoneNumber":
    case "url":
      return { type: "string", title: component.label || component.key };
    case "email":
      return { type: "string", format: "email", title: component.label || component.key };
    case "number":
    case "currency":
      return { type: "number", title: component.label || component.key };
    case "checkbox":
      return { type: "boolean", title: component.label || component.key };
    case "select":
    case "radio": {
      const enumValues = (component.data?.values || component.values || []).map((v) => v.value);
      const enumLabels = (component.data?.values || component.values || []).map((v) => v.label);
      return {
        type: "select",
        title: component.label || component.key,
        enum: enumValues,
        enumLabels
      };
    }
    case "selectboxes":
      return { type: "object", title: component.label || component.key };
    case "datetime":
    case "day":
    case "time":
      return { type: "string", format: "date-time", title: component.label || component.key };
    case "file":
    case "signature":
      return { type: "string", title: component.label || component.key };
    case "address":
      return { type: "object", title: component.label || component.key };
    case "hidden":
      return { type: "string", title: component.label || component.key };
    default:
      return { type: "string", title: component.label || component.key };
  }
}
function extractFieldComponents(components) {
  const fields = [];
  if (!components) return fields;
  for (const comp of components) {
    if (comp.type === "panel" || comp.type === "fieldset" || comp.type === "well" || comp.type === "tabs") {
      if (comp.components) {
        fields.push(...extractFieldComponents(comp.components));
      }
      continue;
    }
    if (comp.type === "columns" && comp.columns) {
      for (const col of comp.columns) {
        if (col.components) {
          fields.push(...extractFieldComponents(col.components));
        }
      }
      continue;
    }
    if (comp.type === "table" && comp.rows) {
      for (const row of comp.rows) {
        if (Array.isArray(row)) {
          for (const cell of row) {
            if (cell.components) {
              fields.push(...extractFieldComponents(cell.components));
            }
          }
        }
      }
      continue;
    }
    if (comp.type === "button" || comp.type === "htmlelement" || comp.type === "content") {
      continue;
    }
    if (comp.type === "turnstile") {
      continue;
    }
    if (comp.key) {
      fields.push(comp);
    }
    if (comp.components) {
      fields.push(...extractFieldComponents(comp.components));
    }
  }
  return fields;
}
function deriveCollectionSchemaFromFormio(formioSchema) {
  const components = formioSchema?.components || [];
  const fieldComponents = extractFieldComponents(components);
  const properties = {
    // Always include a title field for the content item
    title: { type: "string", title: "Title", required: true }
  };
  const required = ["title"];
  for (const comp of fieldComponents) {
    const key = comp.key;
    if (!key || key === "submit" || key === "title") continue;
    const fieldDef = mapFormioTypeToSchemaType(comp);
    if (comp.validate?.required) {
      fieldDef.required = true;
      required.push(key);
    }
    properties[key] = fieldDef;
  }
  return { type: "object", properties, required };
}
function deriveSubmissionTitle(data, formDisplayName) {
  const candidates = ["name", "fullName", "full_name", "firstName", "first_name"];
  for (const key of candidates) {
    if (data[key] && typeof data[key] === "string" && data[key].trim()) {
      if (key === "firstName" || key === "first_name") {
        const last = data["lastName"] || data["last_name"] || data["lastname"] || "";
        if (last) return `${data[key].trim()} ${last.trim()}`;
      }
      return data[key].trim();
    }
  }
  if (data.email && typeof data.email === "string" && data.email.trim()) {
    return data.email.trim();
  }
  if (data.subject && typeof data.subject === "string" && data.subject.trim()) {
    return data.subject.trim();
  }
  const dateStr = (/* @__PURE__ */ new Date()).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
  return `${formDisplayName} - ${dateStr}`;
}
async function syncFormCollection(db, form) {
  const collectionName = `form_${form.name}`;
  const displayName = `${form.display_name} (Form)`;
  const formioSchema = typeof form.formio_schema === "string" ? JSON.parse(form.formio_schema) : form.formio_schema;
  const schema = deriveCollectionSchemaFromFormio(formioSchema);
  const schemaJson = JSON.stringify(schema);
  const now = Date.now();
  const isActive = form.is_active ? 1 : 0;
  const existing = await db.prepare(
    "SELECT id, schema, display_name, description, is_active FROM collections WHERE source_type = ? AND source_id = ?"
  ).bind("form", form.id).first();
  if (!existing) {
    const collectionId = `col-form-${form.name}-${crypto.randomUUID().slice(0, 8)}`;
    await db.prepare(`
      INSERT INTO collections (id, name, display_name, description, schema, is_active, managed, source_type, source_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, 'form', ?, ?, ?)
    `).bind(
      collectionId,
      collectionName,
      displayName,
      form.description || null,
      schemaJson,
      isActive,
      form.id,
      now,
      now
    ).run();
    console.log(`[FormSync] Created shadow collection: ${collectionName}`);
    return { collectionId, status: "created" };
  }
  const existingSchema = existing.schema ? JSON.stringify(typeof existing.schema === "string" ? JSON.parse(existing.schema) : existing.schema) : "{}";
  const needsUpdate = schemaJson !== existingSchema || displayName !== existing.display_name || (form.description || null) !== existing.description || isActive !== existing.is_active;
  if (!needsUpdate) {
    return { collectionId: existing.id, status: "unchanged" };
  }
  await db.prepare(`
    UPDATE collections SET display_name = ?, description = ?, schema = ?, is_active = ?, updated_at = ?
    WHERE id = ?
  `).bind(
    displayName,
    form.description || null,
    schemaJson,
    isActive,
    now,
    existing.id
  ).run();
  console.log(`[FormSync] Updated shadow collection: ${collectionName}`);
  return { collectionId: existing.id, status: "updated" };
}
async function syncAllFormCollections(db) {
  try {
    const tableCheck = await db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='forms'"
    ).first();
    if (!tableCheck) {
      console.log("[FormSync] Forms table does not exist, skipping form sync");
      return;
    }
    const { results: forms } = await db.prepare(
      "SELECT id, name, display_name, description, formio_schema, is_active FROM forms"
    ).all();
    if (!forms || forms.length === 0) {
      console.log("[FormSync] No forms found, skipping");
      return;
    }
    let created = 0;
    let updated = 0;
    for (const form of forms) {
      try {
        const result = await syncFormCollection(db, form);
        if (result.status === "created") created++;
        if (result.status === "updated") updated++;
        await backfillFormSubmissions(db, form.id, result.collectionId);
      } catch (error) {
        console.error(`[FormSync] Error syncing form ${form.name}:`, error);
      }
    }
    console.log(`[FormSync] Sync complete: ${created} created, ${updated} updated out of ${forms.length} forms`);
  } catch (error) {
    console.error("[FormSync] Error syncing form collections:", error);
  }
}
async function createContentFromSubmission(db, submissionData, form, submissionId, metadata = {}) {
  try {
    let collection = await db.prepare(
      "SELECT id FROM collections WHERE source_type = ? AND source_id = ?"
    ).bind("form", form.id).first();
    if (!collection) {
      console.warn(`[FormSync] No shadow collection found for form ${form.name}, attempting to create...`);
      try {
        const fullForm = await db.prepare(
          "SELECT id, name, display_name, description, formio_schema, is_active FROM forms WHERE id = ?"
        ).bind(form.id).first();
        if (fullForm) {
          const schema = typeof fullForm.formio_schema === "string" ? JSON.parse(fullForm.formio_schema) : fullForm.formio_schema;
          const result = await syncFormCollection(db, {
            id: fullForm.id,
            name: fullForm.name,
            display_name: fullForm.display_name,
            description: fullForm.description,
            formio_schema: schema,
            is_active: fullForm.is_active ?? 1
          });
          collection = await db.prepare(
            "SELECT id FROM collections WHERE source_type = ? AND source_id = ?"
          ).bind("form", form.id).first();
          console.log(`[FormSync] On-the-fly sync result: ${result.status}, collectionId: ${result.collectionId}`);
        }
      } catch (syncErr) {
        console.error("[FormSync] On-the-fly shadow collection creation failed:", syncErr);
      }
      if (!collection) {
        console.error(`[FormSync] Still no shadow collection for form ${form.name} after recovery attempt`);
        return null;
      }
    }
    const contentId = crypto.randomUUID();
    const now = Date.now();
    const title = deriveSubmissionTitle(submissionData, form.display_name);
    const slug = `submission-${submissionId.slice(0, 8)}`;
    const contentData = {
      title,
      ...submissionData,
      _submission_metadata: {
        submissionId,
        formId: form.id,
        formName: form.name,
        email: metadata.userEmail || submissionData.email || null,
        ipAddress: metadata.ipAddress || null,
        userAgent: metadata.userAgent || null,
        submittedAt: now
      }
    };
    const authorId = metadata.userId || SYSTEM_FORM_USER_ID;
    if (authorId === SYSTEM_FORM_USER_ID) {
      const systemUser = await db.prepare("SELECT id FROM users WHERE id = ?").bind(SYSTEM_FORM_USER_ID).first();
      if (!systemUser) {
        console.log("[FormSync] System form user missing, creating...");
        const sysNow = Date.now();
        await db.prepare(`
          INSERT OR IGNORE INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NULL, 'viewer', 0, ?, ?)
        `).bind(SYSTEM_FORM_USER_ID, "system-forms@sonicjs.internal", "system-forms", "Form", "Submission", sysNow, sysNow).run();
      }
    }
    console.log(`[FormSync] Inserting content: id=${contentId}, collection=${collection.id}, slug=${slug}, title=${title}, author=${authorId}`);
    await db.prepare(`
      INSERT INTO content (id, collection_id, slug, title, data, status, author_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'published', ?, ?, ?)
    `).bind(
      contentId,
      collection.id,
      slug,
      title,
      JSON.stringify(contentData),
      authorId,
      now,
      now
    ).run();
    await db.prepare(
      "UPDATE form_submissions SET content_id = ? WHERE id = ?"
    ).bind(contentId, submissionId).run();
    console.log(`[FormSync] Content created successfully: ${contentId}`);
    return contentId;
  } catch (error) {
    console.error("[FormSync] Error creating content from submission:", error);
    return null;
  }
}
async function backfillFormSubmissions(db, formId, collectionId) {
  try {
    const { results: submissions } = await db.prepare(
      "SELECT id, submission_data, user_email, ip_address, user_agent, user_id, submitted_at FROM form_submissions WHERE form_id = ? AND content_id IS NULL"
    ).bind(formId).all();
    if (!submissions || submissions.length === 0) {
      return 0;
    }
    const form = await db.prepare(
      "SELECT id, name, display_name FROM forms WHERE id = ?"
    ).bind(formId).first();
    if (!form) return 0;
    let count = 0;
    for (const sub of submissions) {
      try {
        const submissionData = typeof sub.submission_data === "string" ? JSON.parse(sub.submission_data) : sub.submission_data;
        const contentId = await createContentFromSubmission(
          db,
          submissionData,
          { id: form.id, name: form.name, display_name: form.display_name },
          sub.id,
          {
            ipAddress: sub.ip_address,
            userAgent: sub.user_agent,
            userEmail: sub.user_email,
            userId: sub.user_id
          }
        );
        if (contentId) count++;
      } catch (error) {
        console.error(`[FormSync] Error backfilling submission ${sub.id}:`, error);
      }
    }
    if (count > 0) {
      console.log(`[FormSync] Backfilled ${count} submissions for form ${formId}`);
    }
    return count;
  } catch (error) {
    console.error("[FormSync] Error backfilling submissions:", error);
    return 0;
  }
}

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
      const migrationService = new chunk2FZKSSOF_cjs.MigrationService(c.env.DB);
      await migrationService.runPendingMigrations();
      console.log("[Bootstrap] Syncing collection configurations...");
      try {
        await chunkXEITDGR3_cjs.syncCollections(c.env.DB);
      } catch (error) {
        console.error("[Bootstrap] Error syncing collections:", error);
      }
      console.log("[Bootstrap] Syncing form collections...");
      try {
        await syncAllFormCollections(c.env.DB);
      } catch (error) {
        console.error("[Bootstrap] Error syncing form collections:", error);
      }
      if (!config.plugins?.disableAll) {
        console.log("[Bootstrap] Bootstrapping core plugins...");
        const bootstrapService = new chunkXEITDGR3_cjs.PluginBootstrapService(c.env.DB);
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
var AuthManager = class {
  static async generateToken(userId, email, role, secret) {
    const payload = {
      userId,
      email,
      role,
      exp: Math.floor(Date.now() / 1e3) + 60 * 60 * 24,
      // 24 hours
      iat: Math.floor(Date.now() / 1e3)
    };
    return await jwt.sign(payload, secret || JWT_SECRET_FALLBACK, "HS256");
  }
  static async verifyToken(token, secret) {
    try {
      const payload = await jwt.verify(token, secret || JWT_SECRET_FALLBACK, "HS256");
      if (payload.exp < Math.floor(Date.now() / 1e3)) {
        return null;
      }
      return payload;
    } catch (error) {
      console.error("Token verification failed:", error);
      return null;
    }
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
      maxAge: options?.maxAge ?? 60 * 60 * 24
      // 24 hours default
    });
  }
};
var requireAuth = () => {
  return async (c, next) => {
    try {
      let token = c.req.header("Authorization")?.replace("Bearer ", "");
      if (!token) {
        token = cookie.getCookie(c, "auth_token");
      }
      if (!token) {
        const acceptHeader = c.req.header("Accept") || "";
        if (acceptHeader.includes("text/html")) {
          return c.redirect("/auth/login?error=Please login to access the admin area");
        }
        return c.json({ error: "Authentication required" }, 401);
      }
      const kv = c.env?.KV;
      let payload = null;
      if (kv) {
        const cacheKey = `auth:${token.substring(0, 20)}`;
        const cached = await kv.get(cacheKey, "json");
        if (cached) {
          payload = cached;
        }
      }
      if (!payload) {
        const jwtSecret = c.env?.JWT_SECRET;
        payload = await AuthManager.verifyToken(token, jwtSecret);
        if (payload && kv) {
          const cacheKey = `auth:${token.substring(0, 20)}`;
          await kv.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 });
        }
      }
      if (!payload) {
        const acceptHeader = c.req.header("Accept") || "";
        if (acceptHeader.includes("text/html")) {
          return c.redirect("/auth/login?error=Your session has expired, please login again");
        }
        return c.json({ error: "Invalid or expired token" }, 401);
      }
      c.set("user", payload);
      return await next();
    } catch (error) {
      console.error("Auth middleware error:", error);
      const acceptHeader = c.req.header("Accept") || "";
      if (acceptHeader.includes("text/html")) {
        return c.redirect("/auth/login?error=Authentication failed, please login again");
      }
      return c.json({ error: "Authentication failed" }, 401);
    }
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
var optionalAuth = () => {
  return async (c, next) => {
    try {
      let token = c.req.header("Authorization")?.replace("Bearer ", "");
      if (!token) {
        token = cookie.getCookie(c, "auth_token");
      }
      if (token) {
        const jwtSecret = c.env?.JWT_SECRET;
        const payload = await AuthManager.verifyToken(token, jwtSecret);
        if (payload) {
          c.set("user", payload);
        }
      }
      return await next();
    } catch (error) {
      console.error("Optional auth error:", error);
      return await next();
    }
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
  "/auth/request-password-reset"
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
        await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 1) });
        const retryAfter = Math.ceil((entry.resetAt - now) / 1e3);
        c.header("Retry-After", String(retryAfter));
        c.header("X-RateLimit-Limit", String(max));
        c.header("X-RateLimit-Remaining", "0");
        c.header("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1e3)));
        return c.json({ error: "Too many requests. Please try again later." }, 429);
      }
      await kv.put(key, JSON.stringify(entry), { expirationTtl: Math.max(ttlSeconds, 1) });
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
exports.createContentFromSubmission = createContentFromSubmission;
exports.csrfProtection = csrfProtection;
exports.detailedLoggingMiddleware = detailedLoggingMiddleware;
exports.generateCsrfToken = generateCsrfToken;
exports.getActivePlugins = getActivePlugins;
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
exports.requireRole = requireRole;
exports.securityHeadersMiddleware = securityHeadersMiddleware;
exports.securityLoggingMiddleware = securityLoggingMiddleware;
exports.syncFormCollection = syncFormCollection;
exports.validateCsrfToken = validateCsrfToken;
exports.verifySecurityConfig = verifySecurityConfig;
//# sourceMappingURL=chunk-IVZ5FU5L.cjs.map
//# sourceMappingURL=chunk-IVZ5FU5L.cjs.map