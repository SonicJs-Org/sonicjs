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

// src/services/plugin-bootstrap.ts
var PluginBootstrapService = class {
  constructor(db) {
    this.db = db;
    this.pluginService = new PluginService(db);
  }
  pluginService;
  /**
   * Core plugins that should always be available in the system
   */
  CORE_PLUGINS = [
    {
      id: "core-auth",
      name: "core-auth",
      display_name: "Authentication System",
      description: "Core authentication and user management system",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "security",
      icon: "\u{1F510}",
      permissions: ["manage:users", "manage:roles", "manage:permissions"],
      dependencies: [],
      settings: {
        requiredFields: {
          email: { required: true, minLength: 5, label: "Email", type: "email" },
          password: { required: true, minLength: 8, label: "Password", type: "password" },
          username: { required: true, minLength: 3, label: "Username", type: "text" },
          firstName: { required: true, minLength: 1, label: "First Name", type: "text" },
          lastName: { required: true, minLength: 1, label: "Last Name", type: "text" }
        },
        validation: {
          emailFormat: true,
          allowDuplicateUsernames: false,
          passwordRequirements: {
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSpecialChars: false
          }
        },
        registration: {
          enabled: true,
          requireEmailVerification: false,
          defaultRole: "viewer"
        }
      }
    },
    {
      id: "core-media",
      name: "core-media",
      display_name: "Media Manager",
      description: "Core media upload and management system",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "media",
      icon: "\u{1F4F8}",
      permissions: ["manage:media", "upload:files"],
      dependencies: [],
      settings: {}
    },
    {
      id: "database-tools",
      name: "database-tools",
      display_name: "Database Tools",
      description: "Database management tools including truncate, backup, and validation",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "system",
      icon: "\u{1F5C4}\uFE0F",
      permissions: ["manage:database", "admin"],
      dependencies: [],
      settings: {
        enableTruncate: true,
        enableBackup: true,
        enableValidation: true,
        requireConfirmation: true
      }
    },
    {
      id: "seed-data",
      name: "seed-data",
      display_name: "Seed Data",
      description: "Generate realistic example users and content for testing and development",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "development",
      icon: "\u{1F331}",
      permissions: ["admin"],
      dependencies: [],
      settings: {
        userCount: 20,
        contentCount: 200,
        defaultPassword: "password123"
      }
    },
    {
      id: "core-cache",
      name: "core-cache",
      display_name: "Cache System",
      description: "Three-tiered caching system with memory, KV, and database layers",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "performance",
      icon: "\u26A1",
      permissions: ["manage:cache", "view:stats"],
      dependencies: [],
      settings: {
        enableMemoryCache: true,
        enableKVCache: true,
        enableDatabaseCache: true,
        defaultTTL: 3600
      }
    },
    {
      id: "workflow-plugin",
      name: "workflow-plugin",
      display_name: "Workflow Management",
      description: "Content workflow management with approval chains, scheduling, and automation",
      version: "1.0.0-beta.1",
      author: "SonicJS Team",
      category: "content",
      icon: "\u{1F504}",
      permissions: ["manage:workflows", "view:workflows", "transition:content"],
      dependencies: ["content-plugin"],
      settings: {
        enableApprovalChains: true,
        enableScheduling: true,
        enableAutomation: true,
        enableNotifications: true
      }
    },
    {
      id: "easy-mdx",
      name: "easy-mdx",
      display_name: "EasyMDE Editor",
      description: "Lightweight markdown editor with live preview for richtext fields",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "editor",
      icon: "\u270D\uFE0F",
      permissions: [],
      dependencies: [],
      settings: {
        defaultHeight: 400,
        toolbar: "full",
        placeholder: "Start writing your content..."
      }
    },
    {
      id: "ai-search",
      name: "ai-search-plugin",
      display_name: "AI Search",
      description: "Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "search",
      icon: "\u{1F50D}",
      permissions: ["settings:write", "admin:access", "content:read"],
      dependencies: [],
      settings: {
        enabled: false,
        ai_mode_enabled: true,
        selected_collections: [],
        dismissed_collections: [],
        autocomplete_enabled: true,
        cache_duration: 1,
        results_limit: 20,
        index_media: false
      }
    }
  ];
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
        if (plugin.name.startsWith("core-")) {
          console.log(
            `[PluginBootstrap] Activating newly installed core plugin: ${plugin.display_name}`
          );
          await this.pluginService.activatePlugin(plugin.id);
        }
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

exports.PluginBootstrapService = PluginBootstrapService;
exports.PluginService = PluginService;
exports.cleanupRemovedCollections = cleanupRemovedCollections;
exports.fullCollectionSync = fullCollectionSync;
exports.getAvailableCollectionNames = getAvailableCollectionNames;
exports.getManagedCollections = getManagedCollections;
exports.isCollectionManaged = isCollectionManaged;
exports.loadCollectionConfig = loadCollectionConfig;
exports.loadCollectionConfigs = loadCollectionConfigs;
exports.registerCollections = registerCollections;
exports.syncCollection = syncCollection;
exports.syncCollections = syncCollections;
exports.validateCollectionConfig = validateCollectionConfig;
//# sourceMappingURL=chunk-IIBRG5S5.cjs.map
//# sourceMappingURL=chunk-IIBRG5S5.cjs.map