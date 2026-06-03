'use strict';

var chunk3ZXNJZOP_cjs = require('./chunk-3ZXNJZOP.cjs');
var chunkP3XDZL6Q_cjs = require('./chunk-P3XDZL6Q.cjs');
var d1 = require('drizzle-orm/d1');
var drizzleOrm = require('drizzle-orm');
var dev = require('hono/dev');

var Logger = class {
  db;
  enabled = true;
  configCache = /* @__PURE__ */ new Map();
  lastConfigRefresh = 0;
  configRefreshInterval = 6e4;
  // 1 minute
  constructor(database) {
    this.db = d1.drizzle(database);
  }
  /**
   * Log a debug message
   */
  async debug(category, message, data, context) {
    return this.log("debug", category, message, data, context);
  }
  /**
   * Log an info message
   */
  async info(category, message, data, context) {
    return this.log("info", category, message, data, context);
  }
  /**
   * Log a warning message
   */
  async warn(category, message, data, context) {
    return this.log("warn", category, message, data, context);
  }
  /**
   * Log an error message
   */
  async error(category, message, error, context) {
    const errorData = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error;
    return this.log("error", category, message, errorData, {
      ...context,
      stackTrace: error instanceof Error ? error.stack : void 0
    });
  }
  /**
   * Log a fatal message
   */
  async fatal(category, message, error, context) {
    const errorData = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error;
    return this.log("fatal", category, message, errorData, {
      ...context,
      stackTrace: error instanceof Error ? error.stack : void 0
    });
  }
  /**
   * Log an API request
   */
  async logRequest(method, url, statusCode, duration, context) {
    const level = statusCode >= 500 ? "error" : statusCode >= 400 ? "warn" : "info";
    return this.log(level, "api", `${method} ${url} - ${statusCode}`, {
      method,
      url,
      statusCode,
      duration
    }, {
      ...context,
      method,
      url,
      statusCode,
      duration
    });
  }
  /**
   * Log an authentication event
   */
  async logAuth(action, userId, success = true, context) {
    const level = success ? "info" : "warn";
    return this.log(level, "auth", `Authentication ${action}: ${success ? "success" : "failed"}`, {
      action,
      success,
      userId
    }, {
      ...context,
      userId,
      tags: ["authentication", action]
    });
  }
  /**
   * Log a security event
   */
  async logSecurity(event, severity, context) {
    const level = severity === "critical" ? "fatal" : severity === "high" ? "error" : "warn";
    return this.log(level, "security", `Security event: ${event}`, {
      event,
      severity
    }, {
      ...context,
      tags: ["security", severity]
    });
  }
  /**
   * Core logging method
   */
  async log(level, category, message, data, context) {
    if (!this.enabled) return;
    try {
      const config = await this.getConfig(category);
      if (!config || !config.enabled || !this.shouldLog(level, config.level)) {
        return;
      }
      const logEntry = {
        id: crypto.randomUUID(),
        level,
        category,
        message,
        data: data ? JSON.stringify(data) : null,
        userId: context?.userId || null,
        sessionId: context?.sessionId || null,
        requestId: context?.requestId || null,
        ipAddress: context?.ipAddress || null,
        userAgent: context?.userAgent || null,
        method: context?.method || null,
        url: context?.url || null,
        statusCode: context?.statusCode || null,
        duration: context?.duration || null,
        stackTrace: context?.stackTrace || null,
        tags: context?.tags ? JSON.stringify(context.tags) : null,
        source: context?.source || null,
        createdAt: /* @__PURE__ */ new Date()
      };
      await this.db.insert(chunk3ZXNJZOP_cjs.systemLogs).values(logEntry);
      if (config.maxSize) {
        await this.cleanupCategory(category, config.maxSize);
      }
    } catch (error) {
      console.error("Logger error:", error);
    }
  }
  /**
   * Get logs with filtering and pagination
   */
  async getLogs(filter = {}) {
    try {
      const conditions = [];
      if (filter.level && filter.level.length > 0) {
        conditions.push(drizzleOrm.inArray(chunk3ZXNJZOP_cjs.systemLogs.level, filter.level));
      }
      if (filter.category && filter.category.length > 0) {
        conditions.push(drizzleOrm.inArray(chunk3ZXNJZOP_cjs.systemLogs.category, filter.category));
      }
      if (filter.userId) {
        conditions.push(drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.userId, filter.userId));
      }
      if (filter.source) {
        conditions.push(drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.source, filter.source));
      }
      if (filter.search) {
        conditions.push(
          drizzleOrm.like(chunk3ZXNJZOP_cjs.systemLogs.message, `%${filter.search}%`)
        );
      }
      if (filter.startDate) {
        conditions.push(drizzleOrm.gte(chunk3ZXNJZOP_cjs.systemLogs.createdAt, filter.startDate));
      }
      if (filter.endDate) {
        conditions.push(drizzleOrm.lte(chunk3ZXNJZOP_cjs.systemLogs.createdAt, filter.endDate));
      }
      const whereClause = conditions.length > 0 ? drizzleOrm.and(...conditions) : void 0;
      const totalResult = await this.db.select({ count: drizzleOrm.count() }).from(chunk3ZXNJZOP_cjs.systemLogs).where(whereClause);
      const total = totalResult[0]?.count || 0;
      const sortColumn = filter.sortBy === "level" ? chunk3ZXNJZOP_cjs.systemLogs.level : filter.sortBy === "category" ? chunk3ZXNJZOP_cjs.systemLogs.category : chunk3ZXNJZOP_cjs.systemLogs.createdAt;
      const sortFn = filter.sortOrder === "asc" ? drizzleOrm.asc : drizzleOrm.desc;
      const logs = await this.db.select().from(chunk3ZXNJZOP_cjs.systemLogs).where(whereClause).orderBy(sortFn(sortColumn)).limit(filter.limit || 50).offset(filter.offset || 0);
      return { logs, total };
    } catch (error) {
      console.error("Error getting logs:", error);
      return { logs: [], total: 0 };
    }
  }
  /**
   * Get log configuration for a category
   */
  async getConfig(category) {
    try {
      const now = Date.now();
      if (this.configCache.has(category) && now - this.lastConfigRefresh < this.configRefreshInterval) {
        return this.configCache.get(category) || null;
      }
      const configs = await this.db.select().from(chunk3ZXNJZOP_cjs.logConfig).where(drizzleOrm.eq(chunk3ZXNJZOP_cjs.logConfig.category, category));
      const config = configs[0] || null;
      if (config) {
        this.configCache.set(category, config);
        this.lastConfigRefresh = now;
      }
      return config;
    } catch (error) {
      console.error("Error getting log config:", error);
      return null;
    }
  }
  /**
   * Update log configuration
   */
  async updateConfig(category, updates) {
    try {
      await this.db.update(chunk3ZXNJZOP_cjs.logConfig).set({
        ...updates,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(drizzleOrm.eq(chunk3ZXNJZOP_cjs.logConfig.category, category));
      this.configCache.delete(category);
    } catch (error) {
      console.error("Error updating log config:", error);
    }
  }
  /**
   * Get all log configurations
   */
  async getAllConfigs() {
    try {
      return await this.db.select().from(chunk3ZXNJZOP_cjs.logConfig);
    } catch (error) {
      console.error("Error getting log configs:", error);
      return [];
    }
  }
  /**
   * Clean up old logs for a category
   */
  async cleanupCategory(category, maxSize) {
    try {
      const countResult = await this.db.select({ count: drizzleOrm.count() }).from(chunk3ZXNJZOP_cjs.systemLogs).where(drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.category, category));
      const currentCount = countResult[0]?.count || 0;
      if (currentCount > maxSize) {
        const cutoffLogs = await this.db.select({ createdAt: chunk3ZXNJZOP_cjs.systemLogs.createdAt }).from(chunk3ZXNJZOP_cjs.systemLogs).where(drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.category, category)).orderBy(drizzleOrm.desc(chunk3ZXNJZOP_cjs.systemLogs.createdAt)).limit(1).offset(maxSize - 1);
        if (cutoffLogs[0]) {
          await this.db.delete(chunk3ZXNJZOP_cjs.systemLogs).where(
            drizzleOrm.and(
              drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.category, category),
              drizzleOrm.lte(chunk3ZXNJZOP_cjs.systemLogs.createdAt, cutoffLogs[0].createdAt)
            )
          );
        }
      }
    } catch (error) {
      console.error("Error cleaning up logs:", error);
    }
  }
  /**
   * Clean up logs based on retention policy
   */
  async cleanupByRetention() {
    try {
      const configs = await this.getAllConfigs();
      for (const config of configs) {
        if (config.retention > 0) {
          const cutoffDate = /* @__PURE__ */ new Date();
          cutoffDate.setDate(cutoffDate.getDate() - config.retention);
          await this.db.delete(chunk3ZXNJZOP_cjs.systemLogs).where(
            drizzleOrm.and(
              drizzleOrm.eq(chunk3ZXNJZOP_cjs.systemLogs.category, config.category),
              drizzleOrm.lte(chunk3ZXNJZOP_cjs.systemLogs.createdAt, cutoffDate)
            )
          );
        }
      }
    } catch (error) {
      console.error("Error cleaning up logs by retention:", error);
    }
  }
  /**
   * Check if a log level should be recorded based on configuration
   */
  shouldLog(level, configLevel) {
    const levels = ["debug", "info", "warn", "error", "fatal"];
    const levelIndex = levels.indexOf(level);
    const configLevelIndex = levels.indexOf(configLevel);
    return levelIndex >= configLevelIndex;
  }
  /**
   * Enable or disable logging
   */
  setEnabled(enabled) {
    this.enabled = enabled;
  }
  /**
   * Check if logging is enabled
   */
  isEnabled() {
    return this.enabled;
  }
};
var loggerInstance = null;
function getLogger(database) {
  if (!loggerInstance && database) {
    loggerInstance = new Logger(database);
  }
  if (!loggerInstance) {
    throw new Error("Logger not initialized. Call getLogger with a database instance first.");
  }
  return loggerInstance;
}
function initLogger(database) {
  loggerInstance = new Logger(database);
  return loggerInstance;
}

// src/services/cache.ts
var CacheService = class {
  config;
  memoryCache = /* @__PURE__ */ new Map();
  constructor(config) {
    this.config = config;
  }
  /**
   * Generate cache key with prefix
   */
  generateKey(type, identifier) {
    const parts = [this.config.keyPrefix, type];
    if (identifier) {
      parts.push(identifier);
    }
    return parts.join(":");
  }
  /**
   * Get value from cache
   */
  async get(key) {
    const cached = this.memoryCache.get(key);
    if (!cached) {
      return null;
    }
    if (Date.now() > cached.expires) {
      this.memoryCache.delete(key);
      return null;
    }
    return cached.value;
  }
  /**
   * Get value from cache with source information
   */
  async getWithSource(key) {
    const cached = this.memoryCache.get(key);
    if (!cached) {
      return {
        hit: false,
        data: null,
        source: "none"
      };
    }
    if (Date.now() > cached.expires) {
      this.memoryCache.delete(key);
      return {
        hit: false,
        data: null,
        source: "expired"
      };
    }
    return {
      hit: true,
      data: cached.value,
      source: "memory",
      ttl: (cached.expires - Date.now()) / 1e3
      // TTL in seconds
    };
  }
  /**
   * Set value in cache
   */
  async set(key, value, ttl) {
    const expires = Date.now() + (ttl || this.config.ttl) * 1e3;
    this.memoryCache.set(key, { value, expires });
  }
  /**
   * Delete specific key from cache
   */
  async delete(key) {
    this.memoryCache.delete(key);
  }
  /**
   * Invalidate cache keys matching a pattern
   * For memory cache, we do simple string matching
   */
  async invalidate(pattern) {
    const regexPattern = pattern.replace(/\*/g, ".*").replace(/\?/g, ".");
    const regex = new RegExp(`^${regexPattern}$`);
    for (const key of this.memoryCache.keys()) {
      if (regex.test(key)) {
        this.memoryCache.delete(key);
      }
    }
  }
  /**
   * Clear all cache
   */
  async clear() {
    this.memoryCache.clear();
  }
  /**
   * Get value from cache or set it using a callback
   */
  async getOrSet(key, callback, ttl) {
    const cached = await this.get(key);
    if (cached !== null) {
      return cached;
    }
    const value = await callback();
    await this.set(key, value, ttl);
    return value;
  }
};
var CACHE_CONFIGS = {
  api: {
    ttl: 300,
    // 5 minutes
    keyPrefix: "api"
  },
  user: {
    ttl: 600,
    // 10 minutes
    keyPrefix: "user"
  },
  content: {
    ttl: 300,
    // 5 minutes
    keyPrefix: "content"
  },
  collection: {
    ttl: 600,
    // 10 minutes
    keyPrefix: "collection"
  }
};
function getCacheService(config) {
  return new CacheService(config);
}

// src/services/settings.ts
var SettingsService = class {
  constructor(db) {
    this.db = db;
  }
  /**
   * Get a setting value by category and key
   */
  async getSetting(category, key) {
    try {
      const result = await this.db.prepare("SELECT value FROM settings WHERE category = ? AND key = ?").bind(category, key).first();
      if (!result) {
        return null;
      }
      return JSON.parse(result.value);
    } catch (error) {
      console.error(`Error getting setting ${category}.${key}:`, error);
      return null;
    }
  }
  /**
   * Get all settings for a category
   */
  async getCategorySettings(category) {
    try {
      const { results } = await this.db.prepare("SELECT key, value FROM settings WHERE category = ?").bind(category).all();
      const settings = {};
      for (const row of results || []) {
        const r = row;
        settings[r.key] = JSON.parse(r.value);
      }
      return settings;
    } catch (error) {
      console.error(`Error getting category settings for ${category}:`, error);
      return {};
    }
  }
  /**
   * Set a setting value
   */
  async setSetting(category, key, value) {
    try {
      const now = Date.now();
      const jsonValue = JSON.stringify(value);
      await this.db.prepare(`
          INSERT INTO settings (id, category, key, value, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(category, key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        `).bind(crypto.randomUUID(), category, key, jsonValue, now, now).run();
      return true;
    } catch (error) {
      console.error(`Error setting ${category}.${key}:`, error);
      return false;
    }
  }
  /**
   * Set multiple settings at once
   */
  async setMultipleSettings(category, settings) {
    try {
      const now = Date.now();
      for (const [key, value] of Object.entries(settings)) {
        const jsonValue = JSON.stringify(value);
        await this.db.prepare(`
            INSERT INTO settings (id, category, key, value, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(category, key) DO UPDATE SET
              value = excluded.value,
              updated_at = excluded.updated_at
          `).bind(crypto.randomUUID(), category, key, jsonValue, now, now).run();
      }
      return true;
    } catch (error) {
      console.error(`Error setting multiple settings for ${category}:`, error);
      return false;
    }
  }
  /**
   * Get general settings with defaults
   */
  async getGeneralSettings(userEmail) {
    const settings = await this.getCategorySettings("general");
    return {
      siteName: settings.siteName || "SonicJS AI",
      siteDescription: settings.siteDescription || "A modern headless CMS powered by AI",
      adminEmail: settings.adminEmail || userEmail || "admin@example.com",
      timezone: settings.timezone || "UTC",
      language: settings.language || "en",
      maintenanceMode: settings.maintenanceMode || false
    };
  }
  /**
   * Save general settings
   */
  async saveGeneralSettings(settings) {
    const settingsToSave = {};
    if (settings.siteName !== void 0) settingsToSave.siteName = settings.siteName;
    if (settings.siteDescription !== void 0) settingsToSave.siteDescription = settings.siteDescription;
    if (settings.adminEmail !== void 0) settingsToSave.adminEmail = settings.adminEmail;
    if (settings.timezone !== void 0) settingsToSave.timezone = settings.timezone;
    if (settings.language !== void 0) settingsToSave.language = settings.language;
    if (settings.maintenanceMode !== void 0) settingsToSave.maintenanceMode = settings.maintenanceMode;
    return await this.setMultipleSettings("general", settingsToSave);
  }
  /**
   * Get security settings with defaults
   */
  async getSecuritySettings() {
    const settings = await this.getCategorySettings("security");
    return {
      jwtExpiresIn: settings.jwtExpiresIn || "30d",
      jwtRefreshGraceSeconds: typeof settings.jwtRefreshGraceSeconds === "number" ? settings.jwtRefreshGraceSeconds : 60 * 60 * 24 * 7
    };
  }
  /**
   * Save security settings
   */
  async saveSecuritySettings(settings) {
    const settingsToSave = {};
    if (settings.jwtExpiresIn !== void 0) settingsToSave.jwtExpiresIn = settings.jwtExpiresIn;
    if (settings.jwtRefreshGraceSeconds !== void 0)
      settingsToSave.jwtRefreshGraceSeconds = settings.jwtRefreshGraceSeconds;
    return await this.setMultipleSettings("security", settingsToSave);
  }
};

// src/services/telemetry-service.ts
var TelemetryService = class {
  config;
  identity = null;
  enabled = true;
  eventQueue = [];
  isInitialized = false;
  constructor(config) {
    this.config = {
      ...chunkP3XDZL6Q_cjs.getTelemetryConfig(),
      ...config
    };
    this.enabled = this.config.enabled;
  }
  /**
   * Initialize the telemetry service
   */
  async initialize(identity) {
    if (!this.enabled) {
      if (this.config.debug) {
        console.log("[Telemetry] Disabled via configuration");
      }
      return;
    }
    try {
      this.identity = identity;
      if (this.config.debug) {
        console.log("[Telemetry] Initialized with installation ID:", identity.installationId);
      }
      this.isInitialized = true;
      await this.flushQueue();
    } catch (error) {
      if (this.config.debug) {
        console.error("[Telemetry] Initialization failed:", error);
      }
      this.enabled = false;
    }
  }
  /**
   * Track a telemetry event
   */
  async track(event, properties) {
    if (!this.enabled) return;
    try {
      const sanitizedProps = this.sanitizeProperties(properties);
      const enrichedProps = {
        ...sanitizedProps,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        version: this.getVersion()
      };
      if (!this.isInitialized) {
        this.eventQueue.push({ event, properties: enrichedProps });
        if (this.config.debug) {
          console.log("[Telemetry] Queued event:", event, enrichedProps);
        }
        return;
      }
      if (this.identity && this.config.host) {
        const payload = {
          data: {
            installation_id: this.identity.installationId,
            event_type: event,
            properties: enrichedProps,
            timestamp: enrichedProps.timestamp
          }
        };
        fetch(`${this.config.host}/v1/events`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        }).catch(() => {
        });
        if (this.config.debug) {
          console.log("[Telemetry] Tracked event:", event, enrichedProps);
        }
      } else if (this.config.debug) {
        console.log("[Telemetry] Event (no endpoint):", event, enrichedProps);
      }
    } catch (error) {
      if (this.config.debug) {
        console.error("[Telemetry] Failed to track event:", error);
      }
    }
  }
  /**
   * Track installation started
   */
  async trackInstallationStarted(properties) {
    await this.track("installation_started", properties);
  }
  /**
   * Track installation completed
   */
  async trackInstallationCompleted(properties) {
    await this.track("installation_completed", properties);
  }
  /**
   * Track installation failed
   */
  async trackInstallationFailed(error, properties) {
    await this.track("installation_failed", {
      ...properties,
      errorType: chunkP3XDZL6Q_cjs.sanitizeErrorMessage(error)
    });
  }
  /**
   * Track dev server started
   */
  async trackDevServerStarted(properties) {
    await this.track("dev_server_started", properties);
  }
  /**
   * Track page view in admin UI
   */
  async trackPageView(route, properties) {
    await this.track("page_viewed", {
      ...properties,
      route: chunkP3XDZL6Q_cjs.sanitizeRoute(route)
    });
  }
  /**
   * Track error (sanitized)
   */
  async trackError(error, properties) {
    await this.track("error_occurred", {
      ...properties,
      errorType: chunkP3XDZL6Q_cjs.sanitizeErrorMessage(error)
    });
  }
  /**
   * Track plugin activation
   */
  async trackPluginActivated(properties) {
    await this.track("plugin_activated", properties);
  }
  /**
   * Track migration run
   */
  async trackMigrationRun(properties) {
    await this.track("migration_run", properties);
  }
  /**
   * Flush queued events
   */
  async flushQueue() {
    if (this.eventQueue.length === 0) return;
    const queue = [...this.eventQueue];
    this.eventQueue = [];
    for (const { event, properties } of queue) {
      await this.track(event, properties);
    }
  }
  /**
   * Sanitize properties to ensure no PII
   */
  sanitizeProperties(properties) {
    if (!properties) return {};
    const sanitized = {};
    for (const [key, value] of Object.entries(properties)) {
      if (value === void 0) continue;
      if (key === "route" && typeof value === "string") {
        sanitized[key] = chunkP3XDZL6Q_cjs.sanitizeRoute(value);
        continue;
      }
      if (key.toLowerCase().includes("error") && typeof value === "string") {
        sanitized[key] = chunkP3XDZL6Q_cjs.sanitizeErrorMessage(value);
        continue;
      }
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
  /**
   * Get SonicJS version
   */
  getVersion() {
    try {
      if (typeof process !== "undefined" && process.env) {
        return process.env.SONICJS_VERSION || "2.0.0";
      }
      return "2.0.0";
    } catch {
      return "unknown";
    }
  }
  /**
   * Shutdown the telemetry service (no-op for fetch-based telemetry)
   */
  async shutdown() {
  }
  /**
   * Enable telemetry
   */
  enable() {
    this.enabled = true;
  }
  /**
   * Disable telemetry
   */
  disable() {
    this.enabled = false;
  }
  /**
   * Check if telemetry is enabled
   */
  isEnabled() {
    return this.enabled;
  }
};
var telemetryInstance = null;
function getTelemetryService(config) {
  if (!telemetryInstance) {
    telemetryInstance = new TelemetryService(config);
  }
  return telemetryInstance;
}
async function initTelemetry(identity, config) {
  const service = getTelemetryService(config);
  await service.initialize(identity);
  return service;
}
function createInstallationIdentity(projectName) {
  const installationId = chunkP3XDZL6Q_cjs.generateInstallationId();
  const identity = { installationId };
  if (projectName) {
    identity.projectId = chunkP3XDZL6Q_cjs.generateProjectId(projectName);
  }
  return identity;
}
var appInstance = null;
function setAppInstance(app) {
  appInstance = app;
}
function getAppInstance() {
  return appInstance;
}
var CATEGORY_INFO = {
  "Auth": {
    title: "Authentication",
    description: "User authentication and authorization endpoints",
    icon: "&#x1f510;"
  },
  "Content": {
    title: "Content Management",
    description: "Content creation, retrieval, and management",
    icon: "&#x1f4dd;"
  },
  "Media": {
    title: "Media Management",
    description: "File upload, storage, and media operations",
    icon: "&#x1f5bc;&#xfe0f;"
  },
  "Admin": {
    title: "Admin Interface",
    description: "Administrative panel and management features",
    icon: "&#x2699;&#xfe0f;"
  },
  "System": {
    title: "System",
    description: "Health checks and system information",
    icon: "&#x1f527;"
  },
  "Search": {
    title: "Search",
    description: "AI-powered search, full-text search, and analytics",
    icon: "&#x1f50d;"
  },
  "API Keys": {
    title: "API Keys",
    description: "API key management and authentication",
    icon: "&#x1f511;"
  },
  "Workflow": {
    title: "Workflow",
    description: "Content workflow and approval processes",
    icon: "&#x1f504;"
  },
  "Cache": {
    title: "Cache",
    description: "Cache management and invalidation",
    icon: "&#x26a1;"
  },
  "Forms": {
    title: "Forms",
    description: "Form submissions and management",
    icon: "&#x1f4cb;"
  },
  "Files": {
    title: "Files",
    description: "File serving from R2 storage",
    icon: "&#x1f4c1;"
  }
};
var ROUTE_METADATA = {
  // Auth endpoints
  "POST /auth/login": { description: "Authenticate user with email and password (returns JWT)", category: "Auth", authentication: false },
  "POST /auth/login/form": { description: "Form-based login (sets session cookie)", category: "Auth", authentication: false },
  "POST /auth/register": { description: "Register a new user account", category: "Auth", authentication: false },
  "POST /auth/logout": { description: "Log out the current user and invalidate session", category: "Auth", authentication: true },
  "GET /auth/me": { description: "Get current authenticated user information", category: "Auth", authentication: true },
  "POST /auth/refresh": { description: "Refresh authentication token", category: "Auth", authentication: true },
  "POST /auth/seed-admin": { description: "Create or reset the admin user account", category: "Auth", authentication: false },
  "POST /auth/magic-link/request": { description: "Request a magic link login email", category: "Auth", authentication: false },
  "GET /auth/magic-link/verify": { description: "Verify magic link token and authenticate", category: "Auth", authentication: false },
  "POST /auth/otp/request": { description: "Request a one-time password via email", category: "Auth", authentication: false },
  "POST /auth/otp/verify": { description: "Verify OTP code and authenticate", category: "Auth", authentication: false },
  // Content endpoints
  "GET /api/collections": { description: "List all available collections", category: "Content", authentication: false },
  "GET /api/collections/:collection/content": { description: "Get all content items from a specific collection", category: "Content", authentication: false },
  "GET /api/content/:id": { description: "Get a specific content item by ID", category: "Content", authentication: false },
  "POST /api/content": { description: "Create a new content item", category: "Content", authentication: true },
  "PUT /api/content/:id": { description: "Update an existing content item", category: "Content", authentication: true },
  "DELETE /api/content/:id": { description: "Delete a content item", category: "Content", authentication: true },
  "GET /api/content/:id/versions": { description: "Get version history for a content item", category: "Content", authentication: true },
  "POST /api/content/:id/restore/:versionId": { description: "Restore a content item to a previous version", category: "Content", authentication: true },
  // Media endpoints
  "GET /api/media": { description: "List all media files with pagination", category: "Media", authentication: false },
  "GET /api/media/:id": { description: "Get a specific media file by ID", category: "Media", authentication: false },
  "POST /api/media/upload": { description: "Upload a new media file to R2 storage", category: "Media", authentication: true },
  "DELETE /api/media/:id": { description: "Delete a media file from storage", category: "Media", authentication: true },
  // Admin API endpoints
  "GET /admin/api/stats": { description: "Get dashboard statistics (collections, content, media, users)", category: "Admin", authentication: true },
  "GET /admin/api/storage": { description: "Get storage usage information", category: "Admin", authentication: true },
  "GET /admin/api/activity": { description: "Get recent activity logs", category: "Admin", authentication: true },
  "GET /admin/api/collections": { description: "List all collections with field counts", category: "Admin", authentication: true },
  "POST /admin/api/collections": { description: "Create a new collection", category: "Admin", authentication: true },
  "GET /admin/api/collections/:id": { description: "Get a specific collection with its fields", category: "Admin", authentication: true },
  "PATCH /admin/api/collections/:id": { description: "Update an existing collection", category: "Admin", authentication: true },
  "DELETE /admin/api/collections/:id": { description: "Delete a collection (must be empty)", category: "Admin", authentication: true },
  "GET /admin/api/collections/:id/fields": { description: "Get fields for a specific collection", category: "Admin", authentication: true },
  "POST /admin/api/collections/:id/fields": { description: "Add a field to a collection", category: "Admin", authentication: true },
  "PATCH /admin/api/collections/:id/fields/:fieldId": { description: "Update a collection field", category: "Admin", authentication: true },
  "DELETE /admin/api/collections/:id/fields/:fieldId": { description: "Remove a field from a collection", category: "Admin", authentication: true },
  "POST /admin/api/collections/:id/fields/reorder": { description: "Reorder fields in a collection", category: "Admin", authentication: true },
  "GET /admin/api/migrations/status": { description: "Get database migration status", category: "Admin", authentication: true },
  "POST /admin/api/migrations/run": { description: "Run pending database migrations", category: "Admin", authentication: true },
  "GET /admin/api/content": { description: "List content items with filtering and pagination", category: "Admin", authentication: true },
  "GET /admin/api/content/:id": { description: "Get a content item for admin editing", category: "Admin", authentication: true },
  "POST /admin/api/content": { description: "Create content via admin API", category: "Admin", authentication: true },
  "PUT /admin/api/content/:id": { description: "Update content via admin API", category: "Admin", authentication: true },
  "DELETE /admin/api/content/:id": { description: "Delete content via admin API", category: "Admin", authentication: true },
  "GET /admin/api/media": { description: "List media files for admin management", category: "Admin", authentication: true },
  "POST /admin/api/media/upload": { description: "Upload media via admin interface", category: "Admin", authentication: true },
  "DELETE /admin/api/media/:id": { description: "Delete media via admin interface", category: "Admin", authentication: true },
  "GET /admin/api/users": { description: "List all users", category: "Admin", authentication: true },
  "POST /admin/api/users": { description: "Create a new user", category: "Admin", authentication: true },
  "PUT /admin/api/users/:id": { description: "Update a user", category: "Admin", authentication: true },
  "DELETE /admin/api/users/:id": { description: "Delete a user", category: "Admin", authentication: true },
  "GET /admin/api/logs": { description: "Get application logs with filtering", category: "Admin", authentication: true },
  "GET /admin/api/plugins": { description: "List all registered plugins", category: "Admin", authentication: true },
  "POST /admin/api/plugins/:id/toggle": { description: "Enable or disable a plugin", category: "Admin", authentication: true },
  "GET /admin/api/settings": { description: "Get application settings", category: "Admin", authentication: true },
  "PUT /admin/api/settings": { description: "Update application settings", category: "Admin", authentication: true },
  "GET /admin/api/forms": { description: "List all forms", category: "Admin", authentication: true },
  "GET /admin/api/forms/:id": { description: "Get form details and submissions", category: "Admin", authentication: true },
  "POST /admin/api/forms": { description: "Create a new form", category: "Admin", authentication: true },
  "PUT /admin/api/forms/:id": { description: "Update a form", category: "Admin", authentication: true },
  "DELETE /admin/api/forms/:id": { description: "Delete a form", category: "Admin", authentication: true },
  "GET /admin/api/forms/:id/submissions": { description: "Get form submissions", category: "Admin", authentication: true },
  "DELETE /admin/api/forms/:id/submissions/:submissionId": { description: "Delete a form submission", category: "Admin", authentication: true },
  // Search endpoints
  "GET /api/search": { description: "Search content using AI, FTS5, keyword, or hybrid mode", category: "Search", authentication: false },
  "POST /api/search/click": { description: "Track a search result click for analytics", category: "Search", authentication: false },
  "GET /admin/plugins/ai-search/api/status": { description: "Get search plugin status and configuration", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/index": { description: "Trigger content indexing for search", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/index/reset": { description: "Reset the search index", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/analytics": { description: "Get search analytics and metrics", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/analytics/queries": { description: "Get top search queries", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/analytics/clicks": { description: "Get click-through analytics", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/fts5/status": { description: "Get FTS5 full-text search status", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/fts5/rebuild": { description: "Rebuild the FTS5 search index", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/facets": { description: "Get available search facets", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/experiments": { description: "List search A/B test experiments", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/experiments": { description: "Create a search A/B test experiment", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/experiments/:id": { description: "Get experiment details", category: "Search", authentication: true },
  "PUT /admin/plugins/ai-search/api/experiments/:id": { description: "Update an experiment", category: "Search", authentication: true },
  "DELETE /admin/plugins/ai-search/api/experiments/:id": { description: "Delete an experiment", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/experiments/:id/start": { description: "Start an experiment", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/experiments/:id/stop": { description: "Stop a running experiment", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/experiments/:id/results": { description: "Get experiment results and statistics", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/quality": { description: "Get search quality agent analysis", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/quality/run": { description: "Run search quality analysis", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/quality/recommendations": { description: "Get quality improvement recommendations", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/quality/recommendations/:id/apply": { description: "Apply a quality recommendation", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/quality/recommendations/:id/dismiss": { description: "Dismiss a quality recommendation", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/synonyms": { description: "List search synonyms", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/synonyms": { description: "Add a search synonym", category: "Search", authentication: true },
  "DELETE /admin/plugins/ai-search/api/synonyms/:id": { description: "Delete a search synonym", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/query-rules": { description: "List search query rules", category: "Search", authentication: true },
  "POST /admin/plugins/ai-search/api/query-rules": { description: "Create a query rule", category: "Search", authentication: true },
  "PUT /admin/plugins/ai-search/api/query-rules/:id": { description: "Update a query rule", category: "Search", authentication: true },
  "DELETE /admin/plugins/ai-search/api/query-rules/:id": { description: "Delete a query rule", category: "Search", authentication: true },
  "GET /admin/plugins/ai-search/api/settings": { description: "Get search plugin settings", category: "Search", authentication: true },
  "PUT /admin/plugins/ai-search/api/settings": { description: "Update search plugin settings", category: "Search", authentication: true },
  // API Key endpoints
  "GET /admin/api-keys/api/keys": { description: "List all API keys", category: "API Keys", authentication: true },
  "POST /admin/api-keys/api/keys": { description: "Create a new API key", category: "API Keys", authentication: true },
  "DELETE /admin/api-keys/api/keys/:id": { description: "Revoke an API key", category: "API Keys", authentication: true },
  "PUT /admin/api-keys/api/keys/:id": { description: "Update an API key", category: "API Keys", authentication: true },
  // Cache endpoints
  "GET /admin/cache/api/stats": { description: "Get cache statistics", category: "Cache", authentication: true },
  "POST /admin/cache/api/purge": { description: "Purge cache entries", category: "Cache", authentication: true },
  "GET /admin/cache/api/entries": { description: "List cache entries", category: "Cache", authentication: true },
  "DELETE /admin/cache/api/entries/:key": { description: "Delete a specific cache entry", category: "Cache", authentication: true },
  // Workflow endpoints
  "GET /workflow/status/:id": { description: "Get workflow status for a content item", category: "Workflow", authentication: true },
  "POST /workflow/submit/:id": { description: "Submit content for review", category: "Workflow", authentication: true },
  "POST /workflow/approve/:id": { description: "Approve content in review", category: "Workflow", authentication: true },
  "POST /workflow/reject/:id": { description: "Reject content in review", category: "Workflow", authentication: true },
  "POST /workflow/publish/:id": { description: "Publish approved content", category: "Workflow", authentication: true },
  "POST /workflow/unpublish/:id": { description: "Unpublish content", category: "Workflow", authentication: true },
  "GET /workflow/history/:id": { description: "Get workflow history for a content item", category: "Workflow", authentication: true },
  // Form endpoints (public)
  "POST /forms/:formId/submit": { description: "Submit a form (public endpoint)", category: "Forms", authentication: false },
  "GET /forms/:formId": { description: "Get form definition for rendering", category: "Forms", authentication: false },
  "POST /api/forms/:formId/submit": { description: "Submit a form via API", category: "Forms", authentication: false },
  "GET /api/forms/:formId": { description: "Get form definition via API", category: "Forms", authentication: false },
  // System endpoints
  "GET /health": { description: "Health check endpoint for monitoring", category: "System", authentication: false },
  "GET /api/health": { description: "API health check with schema information", category: "System", authentication: false },
  "GET /api": { description: "API root - returns API information and available endpoints", category: "System", authentication: false },
  "GET /api/system/info": { description: "Get system information and version", category: "System", authentication: false },
  "GET /api/system/schema": { description: "Get database schema information", category: "System", authentication: false },
  // File serving
  "GET /files/*": { description: "Serve files from R2 storage (public access)", category: "Files", authentication: false },
  // Database tools
  "POST /admin/database-tools/api/query": { description: "Execute a database query", category: "Admin", authentication: true },
  "GET /admin/database-tools/api/tables": { description: "List database tables", category: "Admin", authentication: true },
  "GET /admin/database-tools/api/tables/:name": { description: "Get table schema and sample data", category: "Admin", authentication: true },
  // Seed data
  "POST /admin/seed-data/api/generate": { description: "Generate seed data for development", category: "Admin", authentication: true },
  "GET /admin/seed-data/api/status": { description: "Get seed data generation status", category: "Admin", authentication: true },
  // Email plugin
  "POST /admin/plugins/email/api/send": { description: "Send an email", category: "Admin", authentication: true },
  "GET /admin/plugins/email/api/templates": { description: "List email templates", category: "Admin", authentication: true },
  "POST /admin/plugins/email/api/test": { description: "Send a test email", category: "Admin", authentication: true }
};
var INCLUDED_ROUTE_PATTERNS = [
  /^\/api\//,
  // All /api/* routes
  /^\/api$/,
  // API root
  /^\/auth\/(?!login$|register$)/,
  // Auth routes except GET login/register HTML pages
  /^\/auth\/login$/,
  // POST /auth/login (method filtered later)
  /^\/auth\/register$/,
  // POST /auth/register (method filtered later)
  /^\/admin\/api\//,
  // Admin API endpoints
  /^\/admin\/api-keys\/api\//,
  // API key management
  /^\/admin\/cache\/api\//,
  // Cache management API
  /^\/admin\/plugins\/.*\/api\//,
  // Plugin API endpoints
  /^\/admin\/database-tools\/api\//,
  // Database tools API
  /^\/admin\/seed-data\/api\//,
  // Seed data API
  /^\/workflow\//,
  // Workflow endpoints
  /^\/health$/,
  // Health check
  /^\/files\//,
  // File serving
  /^\/forms\//
  // Public form endpoints
];
var EXCLUDED_ROUTES = /* @__PURE__ */ new Set([
  "GET /auth/login",
  "GET /auth/register",
  "GET /auth/login/form"
]);
var cachedRouteList = null;
function isIncludedRoute(method, path) {
  const key = `${method} ${path}`;
  if (EXCLUDED_ROUTES.has(key)) {
    return false;
  }
  return INCLUDED_ROUTE_PATTERNS.some((pattern) => pattern.test(path));
}
function inferCategory(path) {
  if (path.startsWith("/auth/")) return "Auth";
  if (path.startsWith("/api/search")) return "Search";
  if (path.startsWith("/api/media")) return "Media";
  if (path.startsWith("/api/system")) return "System";
  if (path.startsWith("/api/content") || path.startsWith("/api/collections")) return "Content";
  if (path.startsWith("/api/forms")) return "Forms";
  if (path.startsWith("/admin/api-keys")) return "API Keys";
  if (path.startsWith("/admin/cache")) return "Cache";
  if (path.startsWith("/admin/plugins/ai-search")) return "Search";
  if (path.startsWith("/admin/api")) return "Admin";
  if (path.startsWith("/admin/database-tools")) return "Admin";
  if (path.startsWith("/admin/seed-data")) return "Admin";
  if (path.startsWith("/admin/plugins/email")) return "Admin";
  if (path.startsWith("/workflow/")) return "Workflow";
  if (path.startsWith("/forms/")) return "Forms";
  if (path.startsWith("/files/")) return "Files";
  if (path === "/health" || path.startsWith("/api")) return "System";
  return "Other";
}
function inferAuth(path) {
  if (path === "/health" || path === "/api" || path === "/api/health") return false;
  if (path === "/api/system/info" || path === "/api/system/schema") return false;
  if (path.startsWith("/files/")) return false;
  if (path.startsWith("/forms/") || path.startsWith("/api/forms/")) return false;
  if (path.startsWith("/admin/")) return true;
  if (path.startsWith("/workflow/")) return true;
  return "unknown";
}
function buildRouteList(app) {
  if (cachedRouteList) return cachedRouteList;
  if (!app) return [];
  try {
    const routes = dev.inspectRoutes(app);
    const seen = /* @__PURE__ */ new Set();
    const result = [];
    for (const route of routes) {
      if (route.isMiddleware) continue;
      if (route.method === "ALL") continue;
      const key = `${route.method} ${route.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!isIncludedRoute(route.method, route.path)) continue;
      const meta = ROUTE_METADATA[key];
      if (meta) {
        result.push({
          method: route.method,
          path: route.path,
          description: meta.description,
          authentication: meta.authentication,
          category: meta.category,
          documented: true
        });
      } else {
        result.push({
          method: route.method,
          path: route.path,
          description: "",
          authentication: inferAuth(route.path),
          category: inferCategory(route.path),
          documented: false
        });
      }
    }
    const methodOrder = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 };
    result.sort((a, b) => {
      const catCmp = a.category.localeCompare(b.category);
      if (catCmp !== 0) return catCmp;
      const methCmp = (methodOrder[a.method] ?? 5) - (methodOrder[b.method] ?? 5);
      if (methCmp !== 0) return methCmp;
      return a.path.localeCompare(b.path);
    });
    cachedRouteList = result;
    return result;
  } catch (error) {
    console.error("Failed to inspect routes:", error);
    return [];
  }
}

exports.CACHE_CONFIGS = CACHE_CONFIGS;
exports.CATEGORY_INFO = CATEGORY_INFO;
exports.CacheService = CacheService;
exports.Logger = Logger;
exports.SettingsService = SettingsService;
exports.TelemetryService = TelemetryService;
exports.buildRouteList = buildRouteList;
exports.createInstallationIdentity = createInstallationIdentity;
exports.getAppInstance = getAppInstance;
exports.getCacheService = getCacheService;
exports.getLogger = getLogger;
exports.getTelemetryService = getTelemetryService;
exports.initLogger = initLogger;
exports.initTelemetry = initTelemetry;
exports.setAppInstance = setAppInstance;
//# sourceMappingURL=chunk-QAHXKCFP.cjs.map
//# sourceMappingURL=chunk-QAHXKCFP.cjs.map