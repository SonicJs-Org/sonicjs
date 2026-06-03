'use strict';

// src/services/collection-loader.ts
var registeredCollections = [];
function registerCollections(collections) {
  for (const config of collections) {
    if (!config.name || !config.displayName || !config.schema) {
      console.error(`Invalid collection config: missing required fields`, config);
      continue;
    }
    const normalizedConfig = {
      ...config,
      managed: config.managed !== void 0 ? config.managed : true,
      isActive: config.isActive !== void 0 ? config.isActive : true
    };
    registeredCollections.push(normalizedConfig);
    console.log(`\u2713 Registered collection: ${config.name}`);
  }
}
async function loadCollectionConfigs() {
  const collections = [...registeredCollections];
  if (registeredCollections.length > 0) {
    console.log(`\u{1F4E6} Found ${registeredCollections.length} registered collection(s) from application`);
  } else {
    console.log(`\u26A0\uFE0F  No collections registered. Make sure to call registerCollections() in your app's index.ts`);
    console.log(`   Example: import myCollection from './collections/my-collection.collection'`);
    console.log(`            registerCollections([myCollection])`);
  }
  try {
    const modules = undefined?.("../collections/*.collection.ts", { eager: true }) || {};
    let coreCollectionCount = 0;
    for (const [path, module] of Object.entries(modules)) {
      try {
        const configModule = module;
        if (!configModule.default) {
          console.warn(`Collection file ${path} does not export a default config`);
          continue;
        }
        const config = configModule.default;
        if (!config.name || !config.displayName || !config.schema) {
          console.error(`Invalid collection config in ${path}: missing required fields`);
          continue;
        }
        const normalizedConfig = {
          ...config,
          managed: config.managed !== void 0 ? config.managed : true,
          isActive: config.isActive !== void 0 ? config.isActive : true
        };
        collections.push(normalizedConfig);
        coreCollectionCount++;
        console.log(`\u2713 Loaded core collection: ${config.name}`);
      } catch (error) {
        console.error(`Error loading collection from ${path}:`, error);
      }
    }
    console.log(`\u{1F4CA} Collection summary: ${collections.length} total (${registeredCollections.length} from app, ${coreCollectionCount} from core)`);
    return collections;
  } catch (error) {
    console.error("Error loading collection configurations:", error);
    return collections;
  }
}
async function loadCollectionConfig(name) {
  try {
    console.warn("loadCollectionConfig requires implementation in consuming application");
    return null;
  } catch (error) {
    console.error(`Error loading collection ${name}:`, error);
    return null;
  }
}
async function getAvailableCollectionNames() {
  try {
    const modules = undefined?.("../collections/*.collection.ts") || {};
    const names = [];
    for (const path of Object.keys(modules)) {
      const match = path.match(/\/([^/]+)\.collection\.ts$/);
      if (match && match[1]) {
        names.push(match[1]);
      }
    }
    return names;
  } catch (error) {
    console.error("Error getting collection names:", error);
    return [];
  }
}
function validateCollectionConfig(config) {
  const errors = [];
  if (!config.name) {
    errors.push("Collection name is required");
  } else if (!/^[a-z0-9_-]+$/.test(config.name)) {
    errors.push("Collection name must contain only lowercase letters, numbers, underscores, and hyphens");
  }
  if (!config.displayName) {
    errors.push("Display name is required");
  }
  if (!config.schema) {
    errors.push("Schema is required");
  } else {
    if (config.schema.type !== "object") {
      errors.push('Schema type must be "object"');
    }
    if (!config.schema.properties || typeof config.schema.properties !== "object") {
      errors.push("Schema must have properties");
    }
    for (const [fieldName, fieldConfig] of Object.entries(config.schema.properties || {})) {
      if (!fieldConfig.type) {
        errors.push(`Field "${fieldName}" is missing type`);
      }
      if (fieldConfig.type === "reference" && !fieldConfig.collection) {
        errors.push(`Reference field "${fieldName}" is missing collection property`);
      }
      const layoutValue = fieldConfig.objectLayout;
      if (layoutValue !== void 0) {
        if (fieldConfig.type !== "object") {
          errors.push(`Field "${fieldName}" uses objectLayout but is not an object field`);
        } else if (!["nested", "flat"].includes(layoutValue)) {
          errors.push(`Object field "${fieldName}" has invalid objectLayout. Use "nested" or "flat"`);
        }
      }
      if (["select", "multiselect", "radio"].includes(fieldConfig.type) && !fieldConfig.enum) {
        errors.push(`Select field "${fieldName}" is missing enum options`);
      }
    }
  }
  return {
    valid: errors.length === 0,
    errors
  };
}

// src/services/collection-sync.ts
async function syncCollections(db) {
  console.log("\u{1F504} Starting collection sync...");
  const results = [];
  const configs = await loadCollectionConfigs();
  if (configs.length === 0) {
    console.log("\u26A0\uFE0F  No collection configurations found");
    return results;
  }
  for (const config of configs) {
    const result = await syncCollection(db, config);
    results.push(result);
  }
  const created = results.filter((r) => r.status === "created").length;
  const updated = results.filter((r) => r.status === "updated").length;
  const unchanged = results.filter((r) => r.status === "unchanged").length;
  const errors = results.filter((r) => r.status === "error").length;
  console.log(`\u2705 Collection sync complete: ${created} created, ${updated} updated, ${unchanged} unchanged, ${errors} errors`);
  return results;
}
async function syncCollection(db, config) {
  try {
    const validation = validateCollectionConfig(config);
    if (!validation.valid) {
      return {
        name: config.name,
        status: "error",
        error: `Validation failed: ${validation.errors.join(", ")}`
      };
    }
    const existingStmt = db.prepare("SELECT * FROM collections WHERE name = ?");
    const existing = await existingStmt.bind(config.name).first();
    const now = Date.now();
    const collectionId = existing?.id || `col-${config.name}-${crypto.randomUUID().slice(0, 8)}`;
    const schemaJson = JSON.stringify(config.schema);
    const isActive = config.isActive !== false ? 1 : 0;
    const managed = config.managed !== false ? 1 : 0;
    if (!existing) {
      const insertStmt = db.prepare(`
        INSERT INTO collections (id, name, display_name, description, schema, is_active, managed, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      await insertStmt.bind(
        collectionId,
        config.name,
        config.displayName,
        config.description || null,
        schemaJson,
        isActive,
        managed,
        now,
        now
      ).run();
      console.log(`  \u2713 Created collection: ${config.name}`);
      return {
        name: config.name,
        status: "created",
        message: `Created collection "${config.displayName}"`
      };
    } else {
      const existingSchema = existing.schema ? JSON.stringify(existing.schema) : "{}";
      const existingDisplayName = existing.display_name;
      const existingDescription = existing.description;
      const existingIsActive = existing.is_active;
      const existingManaged = existing.managed;
      const needsUpdate = schemaJson !== existingSchema || config.displayName !== existingDisplayName || (config.description || null) !== existingDescription || isActive !== existingIsActive || managed !== existingManaged;
      if (!needsUpdate) {
        return {
          name: config.name,
          status: "unchanged",
          message: `Collection "${config.displayName}" is up to date`
        };
      }
      const updateStmt = db.prepare(`
        UPDATE collections
        SET display_name = ?, description = ?, schema = ?, is_active = ?, managed = ?, updated_at = ?
        WHERE name = ?
      `);
      await updateStmt.bind(
        config.displayName,
        config.description || null,
        schemaJson,
        isActive,
        managed,
        now,
        config.name
      ).run();
      console.log(`  \u2713 Updated collection: ${config.name}`);
      return {
        name: config.name,
        status: "updated",
        message: `Updated collection "${config.displayName}"`
      };
    }
  } catch (error) {
    console.error(`  \u2717 Error syncing collection ${config.name}:`, error);
    return {
      name: config.name,
      status: "error",
      error: error instanceof Error ? error.message : "Unknown error"
    };
  }
}
async function isCollectionManaged(db, collectionName) {
  try {
    const stmt = db.prepare("SELECT managed FROM collections WHERE name = ?");
    const result = await stmt.bind(collectionName).first();
    return result?.managed === 1;
  } catch (error) {
    console.error(`Error checking if collection is managed:`, error);
    return false;
  }
}
async function getManagedCollections(db) {
  try {
    const stmt = db.prepare("SELECT name FROM collections WHERE managed = 1");
    const { results } = await stmt.all();
    return (results || []).map((row) => row.name);
  } catch (error) {
    console.error("Error getting managed collections:", error);
    return [];
  }
}
async function cleanupRemovedCollections(db) {
  try {
    const configs = await loadCollectionConfigs();
    const configNames = new Set(configs.map((c) => c.name));
    const managedCollections = await getManagedCollections(db);
    const removed = [];
    for (const managedName of managedCollections) {
      if (!configNames.has(managedName)) {
        const updateStmt = db.prepare(`
          UPDATE collections
          SET is_active = 0, updated_at = ?
          WHERE name = ? AND managed = 1
        `);
        await updateStmt.bind(Date.now(), managedName).run();
        removed.push(managedName);
        console.log(`  \u26A0\uFE0F  Deactivated removed collection: ${managedName}`);
      }
    }
    return removed;
  } catch (error) {
    console.error("Error cleaning up removed collections:", error);
    return [];
  }
}
async function fullCollectionSync(db) {
  const results = await syncCollections(db);
  const removed = await cleanupRemovedCollections(db);
  return { results, removed };
}

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
function mapFormStatusToContentStatus(formStatus) {
  switch (formStatus) {
    case "pending":
      return "published";
    case "reviewed":
      return "published";
    case "approved":
      return "published";
    case "rejected":
      return "archived";
    case "spam":
      return "deleted";
    default:
      return "published";
  }
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

// src/services/plugin-service.ts
var PluginService = class {
  constructor(db) {
    this.db = db;
  }
  async getAllPlugins() {
    await this.ensureAllPluginsExist();
    const stmt = this.db.prepare(`
      SELECT * FROM plugins
      ORDER BY is_core DESC, display_name ASC
    `);
    const { results } = await stmt.all();
    return (results || []).map(this.mapPluginFromDb);
  }
  /**
   * Ensure all plugins from the registry exist in the database
   * Auto-installs any newly detected plugins with inactive status
   *
   * Note: This method should be overridden or configured with a plugin registry
   * in the consuming application
   */
  async ensureAllPluginsExist() {
    console.log("[PluginService] ensureAllPluginsExist - requires PLUGIN_REGISTRY configuration");
  }
  async getPlugin(pluginId) {
    const stmt = this.db.prepare("SELECT * FROM plugins WHERE id = ?");
    const plugin = await stmt.bind(pluginId).first();
    if (!plugin) return null;
    return this.mapPluginFromDb(plugin);
  }
  async getPluginByName(name) {
    const stmt = this.db.prepare("SELECT * FROM plugins WHERE name = ?");
    const plugin = await stmt.bind(name).first();
    if (!plugin) return null;
    return this.mapPluginFromDb(plugin);
  }
  async getPluginStats() {
    const stmt = this.db.prepare(`
      SELECT 
        COUNT(*) as total,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
        COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive,
        COUNT(CASE WHEN status = 'error' THEN 1 END) as errors
      FROM plugins
    `);
    const stats = await stmt.first();
    return {
      total: stats.total || 0,
      active: stats.active || 0,
      inactive: stats.inactive || 0,
      errors: stats.errors || 0,
      uninstalled: 0
    };
  }
  async installPlugin(pluginData) {
    const id = pluginData.id || `plugin-${Date.now()}`;
    const now = Math.floor(Date.now() / 1e3);
    const stmt = this.db.prepare(`
      INSERT INTO plugins (
        id, name, display_name, description, version, author, category, icon,
        status, is_core, settings, permissions, dependencies, download_count, 
        rating, installed_at, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await stmt.bind(
      id,
      pluginData.name || id,
      pluginData.display_name || "Unnamed Plugin",
      pluginData.description || "",
      pluginData.version || "1.0.0",
      pluginData.author || "Unknown",
      pluginData.category || "utilities",
      pluginData.icon || "\u{1F50C}",
      "inactive",
      pluginData.is_core || false,
      JSON.stringify(pluginData.settings || {}),
      JSON.stringify(pluginData.permissions || []),
      JSON.stringify(pluginData.dependencies || []),
      pluginData.download_count || 0,
      pluginData.rating || 0,
      now,
      now
    ).run();
    await this.logActivity(id, "installed", null, { version: pluginData.version });
    const installed = await this.getPlugin(id);
    if (!installed) throw new Error("Failed to install plugin");
    return installed;
  }
  async uninstallPlugin(pluginId) {
    const plugin = await this.getPlugin(pluginId);
    if (!plugin) throw new Error("Plugin not found");
    if (plugin.is_core) throw new Error("Cannot uninstall core plugins");
    if (plugin.status === "active") {
      await this.deactivatePlugin(pluginId);
    }
    const stmt = this.db.prepare("DELETE FROM plugins WHERE id = ?");
    await stmt.bind(pluginId).run();
    await this.logActivity(pluginId, "uninstalled", null, { name: plugin.name });
  }
  async activatePlugin(pluginId) {
    const plugin = await this.getPlugin(pluginId);
    if (!plugin) throw new Error("Plugin not found");
    if (plugin.dependencies && plugin.dependencies.length > 0) {
      await this.checkDependencies(plugin.dependencies);
    }
    const now = Math.floor(Date.now() / 1e3);
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'active', activated_at = ?, error_message = NULL 
      WHERE id = ?
    `);
    await stmt.bind(now, pluginId).run();
    await this.logActivity(pluginId, "activated", null);
  }
  async deactivatePlugin(pluginId) {
    const plugin = await this.getPlugin(pluginId);
    if (!plugin) throw new Error("Plugin not found");
    await this.checkDependents(plugin.name);
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'inactive', activated_at = NULL 
      WHERE id = ?
    `);
    await stmt.bind(pluginId).run();
    await this.logActivity(pluginId, "deactivated", null);
  }
  async updatePluginSettings(pluginId, settings) {
    const plugin = await this.getPlugin(pluginId);
    if (!plugin) throw new Error("Plugin not found");
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET settings = ?, updated_at = unixepoch() 
      WHERE id = ?
    `);
    await stmt.bind(JSON.stringify(settings), pluginId).run();
    await this.logActivity(pluginId, "settings_updated", null);
  }
  async setPluginError(pluginId, error) {
    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET status = 'error', error_message = ? 
      WHERE id = ?
    `);
    await stmt.bind(error, pluginId).run();
    await this.logActivity(pluginId, "error", null, { error });
  }
  async getPluginActivity(pluginId, limit = 10) {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_activity_log 
      WHERE plugin_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `);
    const { results } = await stmt.bind(pluginId, limit).all();
    return (results || []).map((row) => ({
      id: row.id,
      action: row.action,
      userId: row.user_id,
      details: row.details ? JSON.parse(row.details) : null,
      timestamp: row.timestamp
    }));
  }
  async registerHook(pluginId, hookName, handlerName, priority = 10) {
    const id = `hook-${Date.now()}`;
    const stmt = this.db.prepare(`
      INSERT INTO plugin_hooks (id, plugin_id, hook_name, handler_name, priority)
      VALUES (?, ?, ?, ?, ?)
    `);
    await stmt.bind(id, pluginId, hookName, handlerName, priority).run();
  }
  async registerRoute(pluginId, path, method, handlerName, middleware) {
    const id = `route-${Date.now()}`;
    const stmt = this.db.prepare(`
      INSERT INTO plugin_routes (id, plugin_id, path, method, handler_name, middleware)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    await stmt.bind(
      id,
      pluginId,
      path,
      method,
      handlerName,
      JSON.stringify(middleware || [])
    ).run();
  }
  async getPluginHooks(pluginId) {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_hooks 
      WHERE plugin_id = ? AND is_active = TRUE
      ORDER BY priority ASC
    `);
    const { results } = await stmt.bind(pluginId).all();
    return results || [];
  }
  async getPluginRoutes(pluginId) {
    const stmt = this.db.prepare(`
      SELECT * FROM plugin_routes 
      WHERE plugin_id = ? AND is_active = TRUE
    `);
    const { results } = await stmt.bind(pluginId).all();
    return results || [];
  }
  async checkDependencies(dependencies) {
    for (const dep of dependencies) {
      const plugin = await this.getPluginByName(dep);
      if (!plugin || plugin.status !== "active") {
        throw new Error(`Required dependency '${dep}' is not active`);
      }
    }
  }
  async checkDependents(pluginName) {
    const stmt = this.db.prepare(`
      SELECT id, display_name FROM plugins 
      WHERE status = 'active' 
      AND dependencies LIKE ?
    `);
    const { results } = await stmt.bind(`%"${pluginName}"%`).all();
    if (results && results.length > 0) {
      const names = results.map((p) => p.display_name).join(", ");
      throw new Error(`Cannot deactivate. The following plugins depend on this one: ${names}`);
    }
  }
  async logActivity(pluginId, action, userId, details) {
    const id = `activity-${Date.now()}`;
    const stmt = this.db.prepare(`
      INSERT INTO plugin_activity_log (id, plugin_id, action, user_id, details)
      VALUES (?, ?, ?, ?, ?)
    `);
    await stmt.bind(
      id,
      pluginId,
      action,
      userId,
      details ? JSON.stringify(details) : null
    ).run();
  }
  mapPluginFromDb(row) {
    return {
      id: row.id,
      name: row.name,
      display_name: row.display_name,
      description: row.description,
      version: row.version,
      author: row.author,
      category: row.category,
      icon: row.icon,
      status: row.status,
      is_core: row.is_core === 1,
      settings: row.settings ? JSON.parse(row.settings) : void 0,
      permissions: row.permissions ? JSON.parse(row.permissions) : void 0,
      dependencies: row.dependencies ? JSON.parse(row.dependencies) : void 0,
      download_count: row.download_count || 0,
      rating: row.rating || 0,
      installed_at: row.installed_at,
      activated_at: row.activated_at,
      last_updated: row.last_updated,
      error_message: row.error_message
    };
  }
};

// src/plugins/manifest-registry.ts
var PLUGIN_REGISTRY = {
  "ai-search": {
    "id": "ai-search",
    "codeName": "ai-search-plugin",
    "displayName": "AI Search",
    "description": "Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.",
    "version": "1.0.0",
    "author": "SonicJS",
    "category": "content",
    "iconEmoji": "\u{1F50D}",
    "is_core": true,
    "permissions": [
      "settings:write",
      "admin:access",
      "content:read"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enabled": true,
      "ai_mode_enabled": true,
      "selected_collections": [],
      "dismissed_collections": [],
      "autocomplete_enabled": true,
      "cache_duration": 1,
      "results_limit": 20,
      "index_media": false
    },
    "adminMenu": {
      "label": "AI Search",
      "icon": "magnifying-glass",
      "path": "/admin/plugins/ai-search",
      "order": 50
    }
  },
  "code-examples-plugin": {
    "id": "code-examples-plugin",
    "codeName": "code-examples-plugin",
    "displayName": "Code Examples",
    "description": "Code snippets and examples library with syntax highlighting and categorization",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "content",
    "iconEmoji": "\u{1F4BB}",
    "is_core": false,
    "permissions": [
      "code-examples:manage"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": null
  },
  "core-analytics": {
    "id": "core-analytics",
    "codeName": "core-analytics",
    "displayName": "Analytics & Insights",
    "description": "Core analytics system for tracking page views, user behavior, and content performance. Provides dashboards and reports with real-time metrics",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "seo",
    "iconEmoji": "\u{1F4CA}",
    "is_core": true,
    "permissions": [
      "analytics:view",
      "analytics:export"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": {
      "label": "Analytics",
      "icon": "chart-bar",
      "path": "/admin/analytics",
      "order": 50
    }
  },
  "core-auth": {
    "id": "core-auth",
    "codeName": "core-auth",
    "displayName": "Authentication System",
    "description": "Core authentication and user management system with role-based access control, session management, and security features",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "security",
    "iconEmoji": "\u{1F510}",
    "is_core": true,
    "permissions": [
      "manage:users",
      "manage:roles",
      "manage:permissions"
    ],
    "dependencies": [],
    "defaultSettings": {
      "requiredFields": {
        "email": {
          "required": true,
          "minLength": 5,
          "label": "Email",
          "type": "email"
        },
        "password": {
          "required": true,
          "minLength": 8,
          "label": "Password",
          "type": "password"
        },
        "username": {
          "required": true,
          "minLength": 3,
          "label": "Username",
          "type": "text"
        },
        "firstName": {
          "required": true,
          "minLength": 1,
          "label": "First Name",
          "type": "text"
        },
        "lastName": {
          "required": true,
          "minLength": 1,
          "label": "Last Name",
          "type": "text"
        }
      },
      "validation": {
        "emailFormat": true,
        "allowDuplicateUsernames": false,
        "passwordRequirements": {
          "requireUppercase": false,
          "requireLowercase": false,
          "requireNumbers": false,
          "requireSpecialChars": false
        }
      },
      "registration": {
        "enabled": true,
        "requireEmailVerification": false,
        "defaultRole": "viewer"
      }
    },
    "adminMenu": null
  },
  "core-cache": {
    "id": "core-cache",
    "codeName": "core-cache",
    "displayName": "Cache System",
    "description": "Three-tiered caching system with in-memory and KV storage. Provides automatic caching for content, users, media, and API responses with configurable TTL and invalidation patterns.",
    "version": "1.0.0-beta.1",
    "author": "SonicJS",
    "category": "system",
    "iconEmoji": "\u26A1",
    "is_core": true,
    "permissions": [
      "cache.view",
      "cache.clear",
      "cache.invalidate"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enableMemoryCache": true,
      "enableKVCache": true,
      "enableDatabaseCache": true,
      "defaultTTL": 3600
    },
    "adminMenu": null
  },
  "core-media": {
    "id": "core-media",
    "codeName": "core-media",
    "displayName": "Media Manager",
    "description": "Core media upload and management system with support for images, videos, and documents. Includes automatic optimization, thumbnail generation, and cloud storage integration",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "media",
    "iconEmoji": "\u{1F4F8}",
    "is_core": true,
    "permissions": [
      "manage:media",
      "upload:files"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": {
      "label": "Media",
      "icon": "image",
      "path": "/admin/media",
      "order": 30
    }
  },
  "database-tools": {
    "id": "database-tools",
    "codeName": "database-tools",
    "displayName": "Database Tools",
    "description": "Database management and administration tools including migrations, backups, and query execution",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "development",
    "iconEmoji": "\u{1F5C4}\uFE0F",
    "is_core": false,
    "permissions": [
      "database:admin"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enableTruncate": true,
      "enableBackup": true,
      "enableValidation": true,
      "requireConfirmation": true
    },
    "adminMenu": null
  },
  "demo-login-plugin": {
    "id": "demo-login-plugin",
    "codeName": "demo-login-plugin",
    "displayName": "Demo Login",
    "description": "Quick demo login functionality for testing and demonstrations",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "utilities",
    "iconEmoji": "\u{1F3AF}",
    "is_core": false,
    "permissions": [],
    "dependencies": [
      "core-auth"
    ],
    "defaultSettings": {
      "enableNotice": true,
      "demoEmail": "admin@sonicjs.com",
      "demoPassword": "sonicjs!"
    },
    "adminMenu": null
  },
  "design": {
    "id": "design",
    "codeName": "design",
    "displayName": "Design System",
    "description": "Design system management including themes, components, and UI customization. Provides a visual interface for managing design tokens, typography, colors, and component library.",
    "version": "1.0.0-beta.1",
    "author": "SonicJS",
    "category": "utilities",
    "iconEmoji": "\u{1F3A8}",
    "is_core": false,
    "permissions": [
      "design.view",
      "design.edit"
    ],
    "dependencies": [],
    "defaultSettings": {
      "defaultTheme": "light",
      "customCSS": ""
    },
    "adminMenu": {
      "label": "Design",
      "icon": "palette",
      "path": "/admin/design",
      "order": 80
    }
  },
  "easy-mdx": {
    "id": "easy-mdx",
    "codeName": "easy-mdx",
    "displayName": "EasyMDE Markdown Editor",
    "description": "Lightweight markdown editor with live preview. Provides a simple and efficient editor with markdown support for richtext fields.",
    "version": "1.0.0",
    "author": "SonicJS Team",
    "category": "editor",
    "iconEmoji": "\u{1F4DD}",
    "is_core": false,
    "permissions": [],
    "dependencies": [],
    "defaultSettings": {
      "defaultHeight": 400,
      "theme": "dark",
      "toolbar": "full",
      "placeholder": "Start writing your content..."
    },
    "adminMenu": null
  },
  "email": {
    "id": "email",
    "codeName": "email",
    "displayName": "Email",
    "description": "Send transactional emails using Resend",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "utilities",
    "iconEmoji": "\u{1F4E7}",
    "is_core": false,
    "permissions": [
      "email:manage",
      "email:send",
      "email:view-logs"
    ],
    "dependencies": [],
    "defaultSettings": {
      "apiKey": "",
      "fromEmail": "",
      "fromName": "",
      "replyTo": "",
      "logoUrl": ""
    },
    "adminMenu": {
      "label": "Email",
      "icon": "envelope",
      "path": "/admin/plugins/email/settings",
      "order": 80
    }
  },
  "global-variables": {
    "id": "global-variables",
    "codeName": "global-variables",
    "displayName": "Global Variables",
    "description": "Dynamic content variables with inline token support. Manage key-value variables via admin UI and use {variable_key} syntax in rich text fields for server-side resolution. Includes full CRUD admin page.",
    "version": "1.1.0",
    "author": "SonicJS Community",
    "category": "content",
    "iconEmoji": "\u{1F524}",
    "is_core": false,
    "permissions": [
      "global-variables:manage",
      "global-variables:view"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enableResolution": true,
      "cacheEnabled": true,
      "cacheTTL": 300
    },
    "adminMenu": {
      "label": "Global Variables",
      "icon": "variable",
      "path": "/admin/global-variables",
      "order": 45
    }
  },
  "hello-world": {
    "id": "hello-world",
    "codeName": "hello-world",
    "displayName": "Hello World",
    "description": "A simple Hello World plugin demonstration",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "utilities",
    "iconEmoji": "\u{1F44B}",
    "is_core": false,
    "permissions": [
      "hello-world:view"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": {
      "label": "Hello World",
      "icon": "hand-raised",
      "path": "/admin/hello-world",
      "order": 90
    }
  },
  "magic-link-auth": {
    "id": "magic-link-auth",
    "codeName": "magic-link-auth",
    "displayName": "Magic Link Authentication",
    "description": "Passwordless authentication via email magic links. Users receive a secure one-time link to sign in without entering a password.",
    "version": "1.0.0",
    "author": "SonicJS Team",
    "category": "security",
    "iconEmoji": "\u{1F517}",
    "is_core": false,
    "permissions": [],
    "dependencies": [
      "email"
    ],
    "defaultSettings": {
      "linkExpiryMinutes": 15,
      "rateLimitPerHour": 5,
      "allowNewUsers": true
    },
    "adminMenu": null
  },
  "oauth-providers": {
    "id": "oauth-providers",
    "codeName": "oauth-providers",
    "displayName": "OAuth Providers",
    "description": "OAuth2/OIDC social login with GitHub, Google, and more",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "authentication",
    "iconEmoji": "\u{1F511}",
    "is_core": true,
    "permissions": [],
    "dependencies": [],
    "defaultSettings": {
      "providers": {
        "github": {
          "clientId": "",
          "clientSecret": "",
          "enabled": false
        },
        "google": {
          "clientId": "",
          "clientSecret": "",
          "enabled": false
        }
      }
    },
    "adminMenu": null
  },
  "otp-login": {
    "id": "otp-login",
    "codeName": "otp-login",
    "displayName": "OTP Login",
    "description": "Passwordless authentication via email one-time codes",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "security",
    "iconEmoji": "\u{1F522}",
    "is_core": false,
    "permissions": [
      "otp:manage",
      "otp:request",
      "otp:verify"
    ],
    "dependencies": [
      "email"
    ],
    "defaultSettings": {
      "codeLength": 6,
      "codeExpiryMinutes": 10,
      "maxAttempts": 3,
      "rateLimitPerHour": 5,
      "allowNewUserRegistration": false,
      "logoUrl": "",
      "logoWidth": 150,
      "logoBorderWidth": 0,
      "logoBorderColor": "#ffffff",
      "loginUrl": "",
      "loginButtonText": ""
    },
    "adminMenu": {
      "label": "OTP Login",
      "icon": "key",
      "path": "/admin/plugins/otp-login/settings",
      "order": 85
    }
  },
  "quill-editor": {
    "id": "quill-editor",
    "codeName": "quill-editor",
    "displayName": "Quill Rich Text Editor",
    "description": "Quill WYSIWYG editor integration for rich text editing. Lightweight, modern editor with customizable toolbars and dark mode support.",
    "version": "1.0.0",
    "author": "SonicJS Team",
    "category": "editor",
    "iconEmoji": "\u270D\uFE0F",
    "is_core": true,
    "permissions": [],
    "dependencies": [],
    "defaultSettings": {
      "version": "2.0.2",
      "defaultHeight": 300,
      "defaultToolbar": "full",
      "theme": "snow"
    },
    "adminMenu": null
  },
  "redirect-management": {
    "id": "redirect-management",
    "codeName": "redirect-management",
    "displayName": "Redirect Management",
    "description": "URL redirect management with exact, partial, and regex matching",
    "version": "1.0.0",
    "author": "ahaas",
    "category": "utilities",
    "iconEmoji": "\u21AA\uFE0F",
    "is_core": false,
    "permissions": [
      "redirect.manage",
      "redirect.view"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enabled": true,
      "autoOffloadEnabled": false
    },
    "adminMenu": {
      "label": "Redirects",
      "icon": "arrow-right",
      "path": "/admin/redirects",
      "order": 85
    }
  },
  "security-audit": {
    "id": "security-audit",
    "codeName": "security-audit",
    "displayName": "Security Audit",
    "description": "Security event logging, brute-force detection, and analytics dashboard. Monitors login attempts, registrations, lockouts, and suspicious activity.",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "security",
    "iconEmoji": "\u{1F6E1}\uFE0F",
    "is_core": false,
    "permissions": [
      "security-audit:view",
      "security-audit:manage"
    ],
    "dependencies": [],
    "defaultSettings": {
      "retention": {
        "daysToKeep": 90,
        "maxEvents": 1e5,
        "autoPurge": true
      },
      "bruteForce": {
        "enabled": true,
        "maxFailedAttemptsPerIP": 10,
        "maxFailedAttemptsPerEmail": 5,
        "windowMinutes": 15,
        "lockoutDurationMinutes": 30,
        "alertThreshold": 20
      },
      "logging": {
        "logSuccessfulLogins": true,
        "logLogouts": true,
        "logRegistrations": true,
        "logPasswordResets": true,
        "logPermissionDenied": true
      }
    },
    "adminMenu": {
      "label": "Security Audit",
      "icon": "shield-check",
      "path": "/admin/plugins/security-audit",
      "order": 85
    }
  },
  "seed-data": {
    "id": "seed-data",
    "codeName": "seed-data",
    "displayName": "Seed Data Generator",
    "description": "Development tool for generating sample data and testing content. Useful for demos and development environments",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "development",
    "iconEmoji": "\u{1F331}",
    "is_core": false,
    "permissions": [
      "seed-data:generate"
    ],
    "dependencies": [],
    "defaultSettings": {
      "userCount": 20,
      "contentCount": 200,
      "defaultPassword": "password123"
    },
    "adminMenu": null
  },
  "shortcodes": {
    "id": "shortcodes",
    "codeName": "shortcodes",
    "displayName": "Shortcodes",
    "description": 'Registered shortcode functions for dynamic content. Use [[shortcode_name param="value"]] syntax in rich text fields for server-side resolution. Includes handler registry, CRUD admin, and live preview.',
    "version": "1.0.0",
    "author": "SonicJS Community",
    "category": "content",
    "iconEmoji": "",
    "is_core": false,
    "permissions": [
      "shortcodes:manage",
      "shortcodes:view"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": {
      "label": "Shortcodes",
      "icon": "bolt",
      "path": "/admin/shortcodes",
      "order": 46
    }
  },
  "stripe": {
    "id": "stripe",
    "codeName": "stripe",
    "displayName": "Stripe Subscriptions",
    "description": "Stripe subscription management with webhook handling, checkout sessions, and subscription gating",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "payments",
    "iconEmoji": "\u{1F4B3}",
    "is_core": true,
    "permissions": [
      "stripe:manage",
      "stripe:view"
    ],
    "dependencies": [],
    "defaultSettings": {
      "stripeSecretKey": "",
      "stripeWebhookSecret": "",
      "stripePriceId": "",
      "successUrl": "/admin/dashboard",
      "cancelUrl": "/admin/dashboard"
    },
    "adminMenu": {
      "label": "Stripe",
      "icon": "credit-card",
      "path": "/admin/plugins/stripe",
      "order": 90
    }
  },
  "testimonials-plugin": {
    "id": "testimonials-plugin",
    "codeName": "testimonials-plugin",
    "displayName": "Testimonials",
    "description": "Customer testimonials and reviews management with display widgets and ratings",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "content",
    "iconEmoji": "\u{1F4AC}",
    "is_core": false,
    "permissions": [
      "testimonials:manage"
    ],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": null
  },
  "tinymce-plugin": {
    "id": "tinymce-plugin",
    "codeName": "tinymce-plugin",
    "displayName": "TinyMCE Rich Text Editor",
    "description": "Powerful WYSIWYG rich text editor for content creation. Provides a full-featured editor with formatting, media embedding, and customizable toolbars for richtext fields.",
    "version": "1.0.0",
    "author": "SonicJS Team",
    "category": "editor",
    "iconEmoji": "\u{1F4DD}",
    "is_core": false,
    "permissions": [],
    "dependencies": [],
    "defaultSettings": {
      "apiKey": "no-api-key",
      "defaultHeight": 300,
      "defaultToolbar": "full",
      "skin": "oxide-dark"
    },
    "adminMenu": null
  },
  "turnstile": {
    "id": "turnstile",
    "codeName": "turnstile-plugin",
    "displayName": "Cloudflare Turnstile",
    "description": "CAPTCHA-free bot protection using Cloudflare Turnstile. Provides reusable verification for any form.",
    "version": "1.0.0",
    "author": "SonicJS",
    "category": "security",
    "iconEmoji": "\u{1F6E1}\uFE0F",
    "is_core": true,
    "permissions": [
      "settings:write",
      "admin:access"
    ],
    "dependencies": [],
    "defaultSettings": {
      "siteKey": "",
      "secretKey": "",
      "theme": "auto",
      "size": "normal",
      "mode": "managed",
      "appearance": "always",
      "preClearanceEnabled": false,
      "preClearanceLevel": "managed",
      "enabled": false
    },
    "adminMenu": {
      "label": "Turnstile",
      "icon": "shield-check",
      "path": "/admin/plugins/turnstile/settings",
      "order": 100
    }
  },
  "user-profiles": {
    "id": "user-profiles",
    "codeName": "user-profiles",
    "displayName": "User Profiles",
    "description": "Configurable custom profile fields for users",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "users",
    "iconEmoji": "\u{1F464}",
    "is_core": true,
    "permissions": [],
    "dependencies": [],
    "defaultSettings": {},
    "adminMenu": null
  },
  "workflow-plugin": {
    "id": "workflow-plugin",
    "codeName": "workflow-plugin",
    "displayName": "Workflow Engine",
    "description": "Content workflow and approval system with customizable states, transitions, and review processes",
    "version": "1.0.0-beta.1",
    "author": "SonicJS Team",
    "category": "content",
    "iconEmoji": "\u{1F504}",
    "is_core": false,
    "permissions": [
      "workflow:manage",
      "workflow:approve"
    ],
    "dependencies": [],
    "defaultSettings": {
      "enableApprovalChains": true,
      "enableScheduling": true,
      "enableAutomation": true,
      "enableNotifications": true
    },
    "adminMenu": null
  }
};
var ALL_PLUGIN_IDS = Object.keys(PLUGIN_REGISTRY);
ALL_PLUGIN_IDS.filter(
  (id) => PLUGIN_REGISTRY[id]?.adminMenu !== null
);
function findPluginByCodeName(codeName) {
  return Object.values(PLUGIN_REGISTRY).find((p) => p.codeName === codeName) || PLUGIN_REGISTRY[codeName];
}

// src/services/plugin-bootstrap.ts
var BOOTSTRAP_PLUGIN_IDS = [
  "core-auth",
  "core-media",
  "database-tools",
  "seed-data",
  "core-cache",
  "workflow-plugin",
  "easy-mdx",
  "ai-search",
  "oauth-providers",
  "global-variables",
  "user-profiles",
  "stripe"
];
function registryToCorePlugin(entry) {
  return {
    id: entry.id,
    name: entry.codeName,
    display_name: entry.displayName,
    description: entry.description,
    version: entry.version,
    author: entry.author,
    category: entry.category,
    icon: entry.iconEmoji,
    permissions: entry.permissions,
    dependencies: entry.dependencies,
    settings: entry.defaultSettings
  };
}
var PluginBootstrapService = class {
  constructor(db) {
    this.db = db;
    this.pluginService = new PluginService(db);
  }
  pluginService;
  /**
   * Core plugins derived from the auto-generated plugin registry.
   * Only plugins listed in BOOTSTRAP_PLUGIN_IDS are included.
   */
  CORE_PLUGINS = BOOTSTRAP_PLUGIN_IDS.filter((id) => PLUGIN_REGISTRY[id] !== void 0).map((id) => registryToCorePlugin(PLUGIN_REGISTRY[id]));
  /**
   * Bootstrap all core plugins - install them if they don't exist
   */
  async bootstrapCorePlugins() {
    console.log("[PluginBootstrap] Starting core plugin bootstrap process...");
    try {
      for (const corePlugin of this.CORE_PLUGINS) {
        await this.ensurePluginInstalled(corePlugin);
      }
      console.log(
        "[PluginBootstrap] Core plugin bootstrap completed successfully"
      );
    } catch (error) {
      console.error("[PluginBootstrap] Error during plugin bootstrap:", error);
      throw error;
    }
  }
  /**
   * Ensure a specific plugin is installed
   */
  async ensurePluginInstalled(plugin) {
    try {
      const existingPlugin = await this.pluginService.getPlugin(plugin.id);
      if (existingPlugin) {
        console.log(
          `[PluginBootstrap] Plugin already installed: ${plugin.display_name} (status: ${existingPlugin.status})`
        );
        if (existingPlugin.version !== plugin.version) {
          console.log(
            `[PluginBootstrap] Updating plugin version: ${plugin.display_name} from ${existingPlugin.version} to ${plugin.version}`
          );
          await this.updatePlugin(plugin);
        }
        if (plugin.id === "core-auth" && existingPlugin.status !== "active") {
          console.log(
            `[PluginBootstrap] Core-auth plugin is inactive, activating it now...`
          );
          await this.pluginService.activatePlugin(plugin.id);
        }
      } else {
        console.log(
          `[PluginBootstrap] Installing plugin: ${plugin.display_name}`
        );
        await this.pluginService.installPlugin({
          ...plugin,
          is_core: plugin.name.startsWith("core-")
        });
        console.log(
          `[PluginBootstrap] Activating newly installed plugin: ${plugin.display_name}`
        );
        await this.pluginService.activatePlugin(plugin.id);
      }
    } catch (error) {
      console.error(
        `[PluginBootstrap] Error ensuring plugin ${plugin.display_name}:`,
        error
      );
    }
  }
  /**
   * Update an existing plugin
   */
  async updatePlugin(plugin) {
    const now = Math.floor(Date.now() / 1e3);
    const stmt = this.db.prepare(`
      UPDATE plugins
      SET
        version = ?,
        description = ?,
        permissions = ?,
        settings = ?,
        last_updated = ?
      WHERE id = ?
    `);
    await stmt.bind(
      plugin.version,
      plugin.description,
      JSON.stringify(plugin.permissions),
      JSON.stringify(plugin.settings || {}),
      now,
      plugin.id
    ).run();
  }
  /**
   * Check if bootstrap is needed (first run detection)
   */
  async isBootstrapNeeded() {
    try {
      for (const corePlugin of this.CORE_PLUGINS.filter(
        (p) => p.name.startsWith("core-")
      )) {
        const exists = await this.pluginService.getPlugin(corePlugin.id);
        if (!exists) {
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error(
        "[PluginBootstrap] Error checking bootstrap status:",
        error
      );
      return true;
    }
  }
};

exports.PLUGIN_REGISTRY = PLUGIN_REGISTRY;
exports.PluginBootstrapService = PluginBootstrapService;
exports.PluginService = PluginService;
exports.backfillFormSubmissions = backfillFormSubmissions;
exports.cleanupRemovedCollections = cleanupRemovedCollections;
exports.createContentFromSubmission = createContentFromSubmission;
exports.deriveCollectionSchemaFromFormio = deriveCollectionSchemaFromFormio;
exports.deriveSubmissionTitle = deriveSubmissionTitle;
exports.findPluginByCodeName = findPluginByCodeName;
exports.fullCollectionSync = fullCollectionSync;
exports.getAvailableCollectionNames = getAvailableCollectionNames;
exports.getManagedCollections = getManagedCollections;
exports.isCollectionManaged = isCollectionManaged;
exports.loadCollectionConfig = loadCollectionConfig;
exports.loadCollectionConfigs = loadCollectionConfigs;
exports.mapFormStatusToContentStatus = mapFormStatusToContentStatus;
exports.registerCollections = registerCollections;
exports.syncAllFormCollections = syncAllFormCollections;
exports.syncCollection = syncCollection;
exports.syncCollections = syncCollections;
exports.syncFormCollection = syncFormCollection;
exports.validateCollectionConfig = validateCollectionConfig;
//# sourceMappingURL=chunk-GZRO5JO5.cjs.map
//# sourceMappingURL=chunk-GZRO5JO5.cjs.map