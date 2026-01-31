'use strict';

var chunkXEITDGR3_cjs = require('./chunk-XEITDGR3.cjs');
var chunkSZJ5JZ2Q_cjs = require('./chunk-SZJ5JZ2Q.cjs');
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
      const migrationService = new chunkSZJ5JZ2Q_cjs.MigrationService(c.env.DB);
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
    return next();
  };
}
var JWT_SECRET = "your-super-secret-jwt-key-change-in-production";
var AuthManager = class {
  static async generateToken(userId, email, role) {
    const payload = {
      userId,
      email,
      role,
      exp: Math.floor(Date.now() / 1e3) + 60 * 60 * 24,
      // 24 hours
      iat: Math.floor(Date.now() / 1e3)
    };
    return await jwt.sign(payload, JWT_SECRET, "HS256");
  }
  static async verifyToken(token) {
    try {
      const payload = await jwt.verify(token, JWT_SECRET, "HS256");
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
    const encoder = new TextEncoder();
    const data = encoder.encode(password + "salt-change-in-production");
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  static async verifyPassword(password, hash) {
    const passwordHash = await this.hashPassword(password);
    return passwordHash === hash;
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
        payload = await AuthManager.verifyToken(token);
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
        const payload = await AuthManager.verifyToken(token);
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

// src/middleware/index.ts
var loggingMiddleware = () => async (_c, next) => await next();
var detailedLoggingMiddleware = () => async (_c, next) => await next();
var securityLoggingMiddleware = () => async (_c, next) => await next();
var performanceLoggingMiddleware = () => async (_c, next) => await next();
var cacheHeaders = () => async (_c, next) => await next();
var compressionMiddleware = async (_c, next) => await next();
var securityHeaders = () => async (_c, next) => await next();
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
exports.detailedLoggingMiddleware = detailedLoggingMiddleware;
exports.getActivePlugins = getActivePlugins;
exports.isPluginActive = isPluginActive;
exports.logActivity = logActivity;
exports.loggingMiddleware = loggingMiddleware;
exports.metricsMiddleware = metricsMiddleware;
exports.optionalAuth = optionalAuth;
exports.performanceLoggingMiddleware = performanceLoggingMiddleware;
exports.requireActivePlugin = requireActivePlugin;
exports.requireActivePlugins = requireActivePlugins;
exports.requireAnyPermission = requireAnyPermission;
exports.requireAuth = requireAuth;
exports.requirePermission = requirePermission;
exports.requireRole = requireRole;
exports.securityHeaders = securityHeaders;
exports.securityLoggingMiddleware = securityLoggingMiddleware;
exports.syncFormCollection = syncFormCollection;
//# sourceMappingURL=chunk-3FXWPLV5.cjs.map
//# sourceMappingURL=chunk-3FXWPLV5.cjs.map