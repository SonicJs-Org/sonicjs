import { getTelemetryConfig, sanitizeErrorMessage, sanitizeRoute, generateInstallationId, generateProjectId } from './chunk-X7ZAEI5S.js';
import { __export } from './chunk-V4OQ3NZ2.js';
import { sqliteTable, integer, text } from 'drizzle-orm/sqlite-core';
import { z } from 'zod/v4';
import { getTableColumns, getViewSelectedFields, isTable, is, Column, SQL, isView, inArray, eq, like, gte, lte, and, count, asc, desc } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';

// src/db/schema.ts
var schema_exports = {};
__export(schema_exports, {
  apiTokens: () => apiTokens,
  collections: () => collections,
  content: () => content,
  contentVersions: () => contentVersions,
  formFiles: () => formFiles,
  formSubmissions: () => formSubmissions,
  forms: () => forms,
  insertCollectionSchema: () => insertCollectionSchema,
  insertContentSchema: () => insertContentSchema,
  insertFormFileSchema: () => insertFormFileSchema,
  insertFormSchema: () => insertFormSchema,
  insertFormSubmissionSchema: () => insertFormSubmissionSchema,
  insertLogConfigSchema: () => insertLogConfigSchema,
  insertMediaSchema: () => insertMediaSchema,
  insertPluginActivityLogSchema: () => insertPluginActivityLogSchema,
  insertPluginAssetSchema: () => insertPluginAssetSchema,
  insertPluginHookSchema: () => insertPluginHookSchema,
  insertPluginRouteSchema: () => insertPluginRouteSchema,
  insertPluginSchema: () => insertPluginSchema,
  insertSystemLogSchema: () => insertSystemLogSchema,
  insertUserSchema: () => insertUserSchema,
  insertWorkflowHistorySchema: () => insertWorkflowHistorySchema,
  logConfig: () => logConfig,
  media: () => media,
  pluginActivityLog: () => pluginActivityLog,
  pluginAssets: () => pluginAssets,
  pluginHooks: () => pluginHooks,
  pluginRoutes: () => pluginRoutes,
  plugins: () => plugins,
  selectCollectionSchema: () => selectCollectionSchema,
  selectContentSchema: () => selectContentSchema,
  selectFormFileSchema: () => selectFormFileSchema,
  selectFormSchema: () => selectFormSchema,
  selectFormSubmissionSchema: () => selectFormSubmissionSchema,
  selectLogConfigSchema: () => selectLogConfigSchema,
  selectMediaSchema: () => selectMediaSchema,
  selectPluginActivityLogSchema: () => selectPluginActivityLogSchema,
  selectPluginAssetSchema: () => selectPluginAssetSchema,
  selectPluginHookSchema: () => selectPluginHookSchema,
  selectPluginRouteSchema: () => selectPluginRouteSchema,
  selectPluginSchema: () => selectPluginSchema,
  selectSystemLogSchema: () => selectSystemLogSchema,
  selectUserSchema: () => selectUserSchema,
  selectWorkflowHistorySchema: () => selectWorkflowHistorySchema,
  systemLogs: () => systemLogs,
  users: () => users,
  workflowHistory: () => workflowHistory
});
var CONSTANTS = {
  INT8_MIN: -128,
  INT8_MAX: 127,
  INT8_UNSIGNED_MAX: 255,
  INT16_MIN: -32768,
  INT16_MAX: 32767,
  INT16_UNSIGNED_MAX: 65535,
  INT24_MIN: -8388608,
  INT24_MAX: 8388607,
  INT24_UNSIGNED_MAX: 16777215,
  INT32_MIN: -2147483648,
  INT32_MAX: 2147483647,
  INT32_UNSIGNED_MAX: 4294967295,
  INT48_MIN: -140737488355328,
  INT48_MAX: 140737488355327,
  INT48_UNSIGNED_MAX: 281474976710655,
  INT64_MIN: -9223372036854775808n,
  INT64_MAX: 9223372036854775807n,
  INT64_UNSIGNED_MAX: 18446744073709551615n
};
function isColumnType(column, columnTypes) {
  return columnTypes.includes(column.columnType);
}
function isWithEnum(column) {
  return "enumValues" in column && Array.isArray(column.enumValues) && column.enumValues.length > 0;
}
var isPgEnum = isWithEnum;
var literalSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
var jsonSchema = z.union([
  literalSchema,
  z.record(z.string(), z.any()),
  z.array(z.any())
]);
var bufferSchema = z.custom((v) => v instanceof Buffer);
function columnToSchema(column, factory) {
  const z$1 = z;
  const coerce = {};
  let schema;
  if (isWithEnum(column)) {
    schema = column.enumValues.length ? z$1.enum(column.enumValues) : z$1.string();
  }
  if (!schema) {
    if (isColumnType(column, ["PgGeometry", "PgPointTuple"])) {
      schema = z$1.tuple([z$1.number(), z$1.number()]);
    } else if (isColumnType(column, ["PgGeometryObject", "PgPointObject"])) {
      schema = z$1.object({ x: z$1.number(), y: z$1.number() });
    } else if (isColumnType(column, ["PgHalfVector", "PgVector"])) {
      schema = z$1.array(z$1.number());
      schema = column.dimensions ? schema.length(column.dimensions) : schema;
    } else if (isColumnType(column, ["PgLine"])) {
      schema = z$1.tuple([z$1.number(), z$1.number(), z$1.number()]);
    } else if (isColumnType(column, ["PgLineABC"])) {
      schema = z$1.object({
        a: z$1.number(),
        b: z$1.number(),
        c: z$1.number()
      });
    } else if (isColumnType(column, ["PgArray"])) {
      schema = z$1.array(columnToSchema(column.baseColumn));
      schema = column.size ? schema.length(column.size) : schema;
    } else if (column.dataType === "array") {
      schema = z$1.array(z$1.any());
    } else if (column.dataType === "number") {
      schema = numberColumnToSchema(column, z$1, coerce);
    } else if (column.dataType === "bigint") {
      schema = bigintColumnToSchema(column, z$1, coerce);
    } else if (column.dataType === "boolean") {
      schema = coerce === true || coerce.boolean ? z$1.coerce.boolean() : z$1.boolean();
    } else if (column.dataType === "date") {
      schema = coerce === true || coerce.date ? z$1.coerce.date() : z$1.date();
    } else if (column.dataType === "string") {
      schema = stringColumnToSchema(column, z$1, coerce);
    } else if (column.dataType === "json") {
      schema = jsonSchema;
    } else if (column.dataType === "custom") {
      schema = z$1.any();
    } else if (column.dataType === "buffer") {
      schema = bufferSchema;
    }
  }
  if (!schema) {
    schema = z$1.any();
  }
  return schema;
}
function numberColumnToSchema(column, z2, coerce) {
  let unsigned = column.getSQLType().includes("unsigned");
  let min;
  let max;
  let integer2 = false;
  if (isColumnType(column, ["MySqlTinyInt", "SingleStoreTinyInt"])) {
    min = unsigned ? 0 : CONSTANTS.INT8_MIN;
    max = unsigned ? CONSTANTS.INT8_UNSIGNED_MAX : CONSTANTS.INT8_MAX;
    integer2 = true;
  } else if (isColumnType(column, [
    "PgSmallInt",
    "PgSmallSerial",
    "MySqlSmallInt",
    "SingleStoreSmallInt"
  ])) {
    min = unsigned ? 0 : CONSTANTS.INT16_MIN;
    max = unsigned ? CONSTANTS.INT16_UNSIGNED_MAX : CONSTANTS.INT16_MAX;
    integer2 = true;
  } else if (isColumnType(column, [
    "PgReal",
    "MySqlFloat",
    "MySqlMediumInt",
    "SingleStoreMediumInt",
    "SingleStoreFloat"
  ])) {
    min = unsigned ? 0 : CONSTANTS.INT24_MIN;
    max = unsigned ? CONSTANTS.INT24_UNSIGNED_MAX : CONSTANTS.INT24_MAX;
    integer2 = isColumnType(column, ["MySqlMediumInt", "SingleStoreMediumInt"]);
  } else if (isColumnType(column, [
    "PgInteger",
    "PgSerial",
    "MySqlInt",
    "SingleStoreInt"
  ])) {
    min = unsigned ? 0 : CONSTANTS.INT32_MIN;
    max = unsigned ? CONSTANTS.INT32_UNSIGNED_MAX : CONSTANTS.INT32_MAX;
    integer2 = true;
  } else if (isColumnType(column, [
    "PgDoublePrecision",
    "MySqlReal",
    "MySqlDouble",
    "SingleStoreReal",
    "SingleStoreDouble",
    "SQLiteReal"
  ])) {
    min = unsigned ? 0 : CONSTANTS.INT48_MIN;
    max = unsigned ? CONSTANTS.INT48_UNSIGNED_MAX : CONSTANTS.INT48_MAX;
  } else if (isColumnType(column, [
    "PgBigInt53",
    "PgBigSerial53",
    "MySqlBigInt53",
    "MySqlSerial",
    "SingleStoreBigInt53",
    "SingleStoreSerial",
    "SQLiteInteger"
  ])) {
    unsigned = unsigned || isColumnType(column, ["MySqlSerial", "SingleStoreSerial"]);
    min = unsigned ? 0 : Number.MIN_SAFE_INTEGER;
    max = Number.MAX_SAFE_INTEGER;
    integer2 = true;
  } else if (isColumnType(column, ["MySqlYear", "SingleStoreYear"])) {
    min = 1901;
    max = 2155;
    integer2 = true;
  } else {
    min = Number.MIN_SAFE_INTEGER;
    max = Number.MAX_SAFE_INTEGER;
  }
  let schema = coerce === true || coerce?.number ? integer2 ? z2.coerce.number() : z2.coerce.number().int() : integer2 ? z2.int() : z2.number();
  schema = schema.gte(min).lte(max);
  return schema;
}
function bigintColumnToSchema(column, z2, coerce) {
  const unsigned = column.getSQLType().includes("unsigned");
  const min = unsigned ? 0n : CONSTANTS.INT64_MIN;
  const max = unsigned ? CONSTANTS.INT64_UNSIGNED_MAX : CONSTANTS.INT64_MAX;
  const schema = coerce === true || coerce?.bigint ? z2.coerce.bigint() : z2.bigint();
  return schema.gte(min).lte(max);
}
function stringColumnToSchema(column, z2, coerce) {
  if (isColumnType(column, ["PgUUID"])) {
    return z2.uuid();
  }
  let max;
  let regex;
  let fixed = false;
  if (isColumnType(column, ["PgVarchar", "SQLiteText"])) {
    max = column.length;
  } else if (isColumnType(column, ["MySqlVarChar", "SingleStoreVarChar"])) {
    max = column.length ?? CONSTANTS.INT16_UNSIGNED_MAX;
  } else if (isColumnType(column, ["MySqlText", "SingleStoreText"])) {
    if (column.textType === "longtext") {
      max = CONSTANTS.INT32_UNSIGNED_MAX;
    } else if (column.textType === "mediumtext") {
      max = CONSTANTS.INT24_UNSIGNED_MAX;
    } else if (column.textType === "text") {
      max = CONSTANTS.INT16_UNSIGNED_MAX;
    } else {
      max = CONSTANTS.INT8_UNSIGNED_MAX;
    }
  }
  if (isColumnType(column, [
    "PgChar",
    "MySqlChar",
    "SingleStoreChar"
  ])) {
    max = column.length;
    fixed = true;
  }
  if (isColumnType(column, ["PgBinaryVector"])) {
    regex = /^[01]+$/;
    max = column.dimensions;
  }
  let schema = coerce === true || coerce?.string ? z2.coerce.string() : z2.string();
  schema = regex ? schema.regex(regex) : schema;
  return max && fixed ? schema.length(max) : max ? schema.max(max) : schema;
}
function getColumns(tableLike) {
  return isTable(tableLike) ? getTableColumns(tableLike) : getViewSelectedFields(tableLike);
}
function handleColumns(columns, refinements, conditions, factory) {
  const columnSchemas = {};
  for (const [key, selected] of Object.entries(columns)) {
    if (!is(selected, Column) && !is(selected, SQL) && !is(selected, SQL.Aliased) && typeof selected === "object") {
      const columns2 = isTable(selected) || isView(selected) ? getColumns(selected) : selected;
      columnSchemas[key] = handleColumns(columns2, refinements[key] ?? {}, conditions);
      continue;
    }
    const refinement = refinements[key];
    if (refinement !== void 0 && typeof refinement !== "function") {
      columnSchemas[key] = refinement;
      continue;
    }
    const column = is(selected, Column) ? selected : void 0;
    const schema = column ? columnToSchema(column) : z.any();
    const refined = typeof refinement === "function" ? refinement(schema) : schema;
    if (conditions.never(column)) {
      continue;
    } else {
      columnSchemas[key] = refined;
    }
    if (column) {
      if (conditions.nullable(column)) {
        columnSchemas[key] = columnSchemas[key].nullable();
      }
      if (conditions.optional(column)) {
        columnSchemas[key] = columnSchemas[key].optional();
      }
    }
  }
  return z.object(columnSchemas);
}
function handleEnum(enum_, factory) {
  const zod = z;
  return zod.enum(enum_.enumValues);
}
var selectConditions = {
  never: () => false,
  optional: () => false,
  nullable: (column) => !column.notNull
};
var insertConditions = {
  never: (column) => column?.generated?.type === "always" || column?.generatedIdentity?.type === "always",
  optional: (column) => !column.notNull || column.notNull && column.hasDefault,
  nullable: (column) => !column.notNull
};
var createSelectSchema = (entity, refine) => {
  if (isPgEnum(entity)) {
    return handleEnum(entity);
  }
  const columns = getColumns(entity);
  return handleColumns(columns, {}, selectConditions);
};
var createInsertSchema = (entity, refine) => {
  const columns = getColumns(entity);
  return handleColumns(columns, refine ?? {}, insertConditions);
};

// src/db/schema.ts
var users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  username: text("username").notNull().unique(),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  passwordHash: text("password_hash"),
  // Hashed password, nullable for OAuth users
  role: text("role").notNull().default("viewer"),
  // 'admin', 'editor', 'author', 'viewer'
  avatar: text("avatar"),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  lastLoginAt: integer("last_login_at"),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull()
});
var collections = sqliteTable("collections", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  displayName: text("display_name").notNull(),
  description: text("description"),
  schema: text("schema", { mode: "json" }).notNull(),
  // JSON schema definition
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  managed: integer("managed", { mode: "boolean" }).notNull().default(false),
  // Config-managed collections cannot be edited in UI
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var content = sqliteTable("content", {
  id: text("id").primaryKey(),
  collectionId: text("collection_id").notNull().references(() => collections.id),
  slug: text("slug").notNull(),
  title: text("title").notNull(),
  data: text("data", { mode: "json" }).notNull(),
  // JSON content data
  status: text("status").notNull().default("draft"),
  // 'draft', 'published', 'archived'
  publishedAt: integer("published_at", { mode: "timestamp" }),
  authorId: text("author_id").notNull().references(() => users.id),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var contentVersions = sqliteTable("content_versions", {
  id: text("id").primaryKey(),
  contentId: text("content_id").notNull().references(() => content.id),
  version: integer("version").notNull(),
  data: text("data", { mode: "json" }).notNull(),
  authorId: text("author_id").notNull().references(() => users.id),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var media = sqliteTable("media", {
  id: text("id").primaryKey(),
  filename: text("filename").notNull(),
  originalName: text("original_name").notNull(),
  mimeType: text("mime_type").notNull(),
  size: integer("size").notNull(),
  width: integer("width"),
  height: integer("height"),
  folder: text("folder").notNull().default("uploads"),
  r2Key: text("r2_key").notNull(),
  // R2 storage key
  publicUrl: text("public_url").notNull(),
  // CDN URL
  thumbnailUrl: text("thumbnail_url"),
  alt: text("alt"),
  caption: text("caption"),
  tags: text("tags", { mode: "json" }),
  // JSON array of tags
  uploadedBy: text("uploaded_by").notNull().references(() => users.id),
  uploadedAt: integer("uploaded_at").notNull(),
  updatedAt: integer("updated_at"),
  publishedAt: integer("published_at"),
  scheduledAt: integer("scheduled_at"),
  archivedAt: integer("archived_at"),
  deletedAt: integer("deleted_at")
});
var apiTokens = sqliteTable("api_tokens", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  token: text("token").notNull().unique(),
  userId: text("user_id").notNull().references(() => users.id),
  permissions: text("permissions", { mode: "json" }).notNull(),
  // Array of permissions
  expiresAt: integer("expires_at", { mode: "timestamp" }),
  lastUsedAt: integer("last_used_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var workflowHistory = sqliteTable("workflow_history", {
  id: text("id").primaryKey(),
  contentId: text("content_id").notNull().references(() => content.id),
  action: text("action").notNull(),
  fromStatus: text("from_status").notNull(),
  toStatus: text("to_status").notNull(),
  userId: text("user_id").notNull().references(() => users.id),
  comment: text("comment"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var plugins = sqliteTable("plugins", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  displayName: text("display_name").notNull(),
  description: text("description"),
  version: text("version").notNull(),
  author: text("author").notNull(),
  category: text("category").notNull(),
  icon: text("icon"),
  status: text("status").notNull().default("inactive"),
  // 'active', 'inactive', 'error'
  isCore: integer("is_core", { mode: "boolean" }).notNull().default(false),
  settings: text("settings", { mode: "json" }),
  permissions: text("permissions", { mode: "json" }),
  dependencies: text("dependencies", { mode: "json" }),
  downloadCount: integer("download_count").notNull().default(0),
  rating: integer("rating").notNull().default(0),
  installedAt: integer("installed_at").notNull(),
  activatedAt: integer("activated_at"),
  lastUpdated: integer("last_updated").notNull(),
  errorMessage: text("error_message"),
  createdAt: integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3)),
  updatedAt: integer("updated_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginHooks = sqliteTable("plugin_hooks", {
  id: text("id").primaryKey(),
  pluginId: text("plugin_id").notNull().references(() => plugins.id),
  hookName: text("hook_name").notNull(),
  handlerName: text("handler_name").notNull(),
  priority: integer("priority").notNull().default(10),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginRoutes = sqliteTable("plugin_routes", {
  id: text("id").primaryKey(),
  pluginId: text("plugin_id").notNull().references(() => plugins.id),
  path: text("path").notNull(),
  method: text("method").notNull(),
  handlerName: text("handler_name").notNull(),
  middleware: text("middleware", { mode: "json" }),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginAssets = sqliteTable("plugin_assets", {
  id: text("id").primaryKey(),
  pluginId: text("plugin_id").notNull().references(() => plugins.id),
  assetType: text("asset_type").notNull(),
  // 'css', 'js', 'image', 'font'
  assetPath: text("asset_path").notNull(),
  loadOrder: integer("load_order").notNull().default(100),
  loadLocation: text("load_location").notNull().default("footer"),
  // 'header', 'footer'
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginActivityLog = sqliteTable("plugin_activity_log", {
  id: text("id").primaryKey(),
  pluginId: text("plugin_id").notNull().references(() => plugins.id),
  action: text("action").notNull(),
  userId: text("user_id"),
  details: text("details", { mode: "json" }),
  timestamp: integer("timestamp").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var insertUserSchema = createInsertSchema(users, {
  email: (schema) => schema.email(),
  firstName: (schema) => schema.min(1),
  lastName: (schema) => schema.min(1),
  username: (schema) => schema.min(3)
});
var selectUserSchema = createSelectSchema(users);
var insertCollectionSchema = createInsertSchema(collections, {
  name: (schema) => schema.min(1).regex(/^[a-z0-9_]+$/, "Collection name must be lowercase with underscores"),
  displayName: (schema) => schema.min(1)
});
var selectCollectionSchema = createSelectSchema(collections);
var insertContentSchema = createInsertSchema(content, {
  slug: (schema) => schema.min(1).regex(/^[a-zA-Z0-9_-]+$/, "Slug must contain only letters, numbers, underscores, and hyphens"),
  title: (schema) => schema.min(1),
  status: (schema) => schema
});
var selectContentSchema = createSelectSchema(content);
var insertMediaSchema = createInsertSchema(media, {
  filename: (schema) => schema.min(1),
  originalName: (schema) => schema.min(1),
  mimeType: (schema) => schema.min(1),
  size: (schema) => schema.positive(),
  r2Key: (schema) => schema.min(1),
  publicUrl: (schema) => schema.url(),
  folder: (schema) => schema.min(1)
});
var selectMediaSchema = createSelectSchema(media);
var insertWorkflowHistorySchema = createInsertSchema(workflowHistory, {
  action: (schema) => schema.min(1),
  fromStatus: (schema) => schema.min(1),
  toStatus: (schema) => schema.min(1)
});
var selectWorkflowHistorySchema = createSelectSchema(workflowHistory);
var insertPluginSchema = createInsertSchema(plugins, {
  name: (schema) => schema.min(1),
  displayName: (schema) => schema.min(1),
  version: (schema) => schema.min(1),
  author: (schema) => schema.min(1),
  category: (schema) => schema.min(1)
});
var selectPluginSchema = createSelectSchema(plugins);
var insertPluginHookSchema = createInsertSchema(pluginHooks, {
  hookName: (schema) => schema.min(1),
  handlerName: (schema) => schema.min(1)
});
var selectPluginHookSchema = createSelectSchema(pluginHooks);
var insertPluginRouteSchema = createInsertSchema(pluginRoutes, {
  path: (schema) => schema.min(1),
  method: (schema) => schema.min(1),
  handlerName: (schema) => schema.min(1)
});
var selectPluginRouteSchema = createSelectSchema(pluginRoutes);
var insertPluginAssetSchema = createInsertSchema(pluginAssets, {
  assetType: (schema) => schema.min(1),
  assetPath: (schema) => schema.min(1)
});
var selectPluginAssetSchema = createSelectSchema(pluginAssets);
var insertPluginActivityLogSchema = createInsertSchema(pluginActivityLog, {
  action: (schema) => schema.min(1)
});
var selectPluginActivityLogSchema = createSelectSchema(pluginActivityLog);
var systemLogs = sqliteTable("system_logs", {
  id: text("id").primaryKey(),
  level: text("level").notNull(),
  // 'debug', 'info', 'warn', 'error', 'fatal'
  category: text("category").notNull(),
  // 'auth', 'api', 'workflow', 'plugin', 'media', 'system', etc.
  message: text("message").notNull(),
  data: text("data", { mode: "json" }),
  // Additional structured data
  userId: text("user_id").references(() => users.id),
  sessionId: text("session_id"),
  requestId: text("request_id"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  method: text("method"),
  // HTTP method for API logs
  url: text("url"),
  // Request URL for API logs
  statusCode: integer("status_code"),
  // HTTP status code for API logs
  duration: integer("duration"),
  // Request duration in milliseconds
  stackTrace: text("stack_trace"),
  // Error stack trace for error logs
  tags: text("tags", { mode: "json" }),
  // Array of tags for categorization
  source: text("source"),
  // Source component/module that generated the log
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var logConfig = sqliteTable("log_config", {
  id: text("id").primaryKey(),
  category: text("category").notNull().unique(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  level: text("level").notNull().default("info"),
  // minimum log level to store
  retention: integer("retention").notNull().default(30),
  // days to keep logs
  maxSize: integer("max_size").default(1e4),
  // max number of logs per category
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var insertSystemLogSchema = createInsertSchema(systemLogs, {
  level: (schema) => schema.min(1),
  category: (schema) => schema.min(1),
  message: (schema) => schema.min(1)
});
var selectSystemLogSchema = createSelectSchema(systemLogs);
var insertLogConfigSchema = createInsertSchema(logConfig, {
  category: (schema) => schema.min(1),
  level: (schema) => schema.min(1)
});
var selectLogConfigSchema = createSelectSchema(logConfig);
var forms = sqliteTable("forms", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  // Machine name (e.g., "contact-form")
  displayName: text("display_name").notNull(),
  // Human name (e.g., "Contact Form")
  description: text("description"),
  category: text("category").notNull().default("general"),
  // contact, survey, registration, etc.
  // Form.io schema (JSON)
  formioSchema: text("formio_schema", { mode: "json" }).notNull(),
  // Complete Form.io JSON schema
  // Settings (JSON)
  settings: text("settings", { mode: "json" }),
  // emailNotifications, successMessage, etc.
  // Status & Management
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  isPublic: integer("is_public", { mode: "boolean" }).notNull().default(true),
  managed: integer("managed", { mode: "boolean" }).notNull().default(false),
  // Metadata
  icon: text("icon"),
  color: text("color"),
  tags: text("tags", { mode: "json" }),
  // JSON array
  // Stats
  submissionCount: integer("submission_count").notNull().default(0),
  viewCount: integer("view_count").notNull().default(0),
  // Ownership
  createdBy: text("created_by").references(() => users.id),
  updatedBy: text("updated_by").references(() => users.id),
  // Timestamps
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull()
});
var formSubmissions = sqliteTable("form_submissions", {
  id: text("id").primaryKey(),
  formId: text("form_id").notNull().references(() => forms.id, { onDelete: "cascade" }),
  // Submission data
  submissionData: text("submission_data", { mode: "json" }).notNull(),
  // The actual form data
  // Submission metadata
  status: text("status").notNull().default("pending"),
  // pending, reviewed, approved, rejected, spam
  submissionNumber: integer("submission_number"),
  // User information
  userId: text("user_id").references(() => users.id),
  userEmail: text("user_email"),
  // Tracking
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  referrer: text("referrer"),
  utmSource: text("utm_source"),
  utmMedium: text("utm_medium"),
  utmCampaign: text("utm_campaign"),
  // Review/Processing
  reviewedBy: text("reviewed_by").references(() => users.id),
  reviewedAt: integer("reviewed_at"),
  reviewNotes: text("review_notes"),
  // Flags
  isSpam: integer("is_spam", { mode: "boolean" }).notNull().default(false),
  isArchived: integer("is_archived", { mode: "boolean" }).notNull().default(false),
  // Timestamps
  submittedAt: integer("submitted_at").notNull(),
  updatedAt: integer("updated_at").notNull()
});
var formFiles = sqliteTable("form_files", {
  id: text("id").primaryKey(),
  submissionId: text("submission_id").notNull().references(() => formSubmissions.id, { onDelete: "cascade" }),
  mediaId: text("media_id").notNull().references(() => media.id, { onDelete: "cascade" }),
  fieldName: text("field_name").notNull(),
  // Form field that uploaded this file
  uploadedAt: integer("uploaded_at").notNull()
});
var insertFormSchema = createInsertSchema(forms);
var selectFormSchema = createSelectSchema(forms);
var insertFormSubmissionSchema = createInsertSchema(formSubmissions);
var selectFormSubmissionSchema = createSelectSchema(formSubmissions);
var insertFormFileSchema = createInsertSchema(formFiles);
var selectFormFileSchema = createSelectSchema(formFiles);
var Logger = class {
  db;
  enabled = true;
  configCache = /* @__PURE__ */ new Map();
  lastConfigRefresh = 0;
  configRefreshInterval = 6e4;
  // 1 minute
  constructor(database) {
    this.db = drizzle(database);
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
      await this.db.insert(systemLogs).values(logEntry);
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
        conditions.push(inArray(systemLogs.level, filter.level));
      }
      if (filter.category && filter.category.length > 0) {
        conditions.push(inArray(systemLogs.category, filter.category));
      }
      if (filter.userId) {
        conditions.push(eq(systemLogs.userId, filter.userId));
      }
      if (filter.source) {
        conditions.push(eq(systemLogs.source, filter.source));
      }
      if (filter.search) {
        conditions.push(
          like(systemLogs.message, `%${filter.search}%`)
        );
      }
      if (filter.startDate) {
        conditions.push(gte(systemLogs.createdAt, filter.startDate));
      }
      if (filter.endDate) {
        conditions.push(lte(systemLogs.createdAt, filter.endDate));
      }
      const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
      const totalResult = await this.db.select({ count: count() }).from(systemLogs).where(whereClause);
      const total = totalResult[0]?.count || 0;
      const sortColumn = filter.sortBy === "level" ? systemLogs.level : filter.sortBy === "category" ? systemLogs.category : systemLogs.createdAt;
      const sortFn = filter.sortOrder === "asc" ? asc : desc;
      const logs = await this.db.select().from(systemLogs).where(whereClause).orderBy(sortFn(sortColumn)).limit(filter.limit || 50).offset(filter.offset || 0);
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
      const configs = await this.db.select().from(logConfig).where(eq(logConfig.category, category));
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
      await this.db.update(logConfig).set({
        ...updates,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq(logConfig.category, category));
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
      return await this.db.select().from(logConfig);
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
      const countResult = await this.db.select({ count: count() }).from(systemLogs).where(eq(systemLogs.category, category));
      const currentCount = countResult[0]?.count || 0;
      if (currentCount > maxSize) {
        const cutoffLogs = await this.db.select({ createdAt: systemLogs.createdAt }).from(systemLogs).where(eq(systemLogs.category, category)).orderBy(desc(systemLogs.createdAt)).limit(1).offset(maxSize - 1);
        if (cutoffLogs[0]) {
          await this.db.delete(systemLogs).where(
            and(
              eq(systemLogs.category, category),
              lte(systemLogs.createdAt, cutoffLogs[0].createdAt)
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
          await this.db.delete(systemLogs).where(
            and(
              eq(systemLogs.category, config.category),
              lte(systemLogs.createdAt, cutoffDate)
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
      ...getTelemetryConfig(),
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
      errorType: sanitizeErrorMessage(error)
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
      route: sanitizeRoute(route)
    });
  }
  /**
   * Track error (sanitized)
   */
  async trackError(error, properties) {
    await this.track("error_occurred", {
      ...properties,
      errorType: sanitizeErrorMessage(error)
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
        sanitized[key] = sanitizeRoute(value);
        continue;
      }
      if (key.toLowerCase().includes("error") && typeof value === "string") {
        sanitized[key] = sanitizeErrorMessage(value);
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
  const installationId = generateInstallationId();
  const identity = { installationId };
  if (projectName) {
    identity.projectId = generateProjectId(projectName);
  }
  return identity;
}

export { CACHE_CONFIGS, CacheService, Logger, SettingsService, TelemetryService, apiTokens, collections, content, contentVersions, createInstallationIdentity, getCacheService, getLogger, getTelemetryService, initLogger, initTelemetry, insertCollectionSchema, insertContentSchema, insertLogConfigSchema, insertMediaSchema, insertPluginActivityLogSchema, insertPluginAssetSchema, insertPluginHookSchema, insertPluginRouteSchema, insertPluginSchema, insertSystemLogSchema, insertUserSchema, insertWorkflowHistorySchema, logConfig, media, pluginActivityLog, pluginAssets, pluginHooks, pluginRoutes, plugins, schema_exports, selectCollectionSchema, selectContentSchema, selectLogConfigSchema, selectMediaSchema, selectPluginActivityLogSchema, selectPluginAssetSchema, selectPluginHookSchema, selectPluginRouteSchema, selectPluginSchema, selectSystemLogSchema, selectUserSchema, selectWorkflowHistorySchema, systemLogs, users, workflowHistory };
//# sourceMappingURL=chunk-G44QUVNM.js.map
//# sourceMappingURL=chunk-G44QUVNM.js.map