import { __export } from './chunk-V4OQ3NZ2.js';
import { sqliteTable, integer, text } from 'drizzle-orm/sqlite-core';
import { z } from 'zod/v4';
import { isTable, getTableColumns, getViewSelectedFields, is, Column, SQL, isView } from 'drizzle-orm';

// src/db/schema.ts
var schema_exports = {};
__export(schema_exports, {
  account: () => account,
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
  insertSecurityEventSchema: () => insertSecurityEventSchema,
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
  securityEvents: () => securityEvents,
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
  selectSecurityEventSchema: () => selectSecurityEventSchema,
  selectSystemLogSchema: () => selectSystemLogSchema,
  selectUserSchema: () => selectUserSchema,
  selectWorkflowHistorySchema: () => selectWorkflowHistorySchema,
  session: () => session,
  systemLogs: () => systemLogs,
  users: () => users,
  verification: () => verification,
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
  name: text("name"),
  // Better Auth display name (required by Better Auth for registration)
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  // Better Auth
  role: text("role").notNull().default("viewer"),
  // 'admin', 'editor', 'author', 'viewer'
  avatar: text("avatar"),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  lastLoginAt: integer("last_login_at"),
  // Password reset (routes/auth.ts)
  passwordResetToken: text("password_reset_token"),
  passwordResetExpires: integer("password_reset_expires"),
  // Invitation flow (routes/auth.ts accept-invitation)
  invitationToken: text("invitation_token"),
  invitedAt: integer("invited_at"),
  acceptedInvitationAt: integer("accepted_invitation_at"),
  // Account lockout (migration 041): reset on success; set on threshold failures
  failedLoginCount: integer("failed_login_count").notNull().default(0),
  lockedUntil: integer("locked_until"),
  // 2FA enrollment flag (migration 042, twoFactor BA plugin)
  twoFactorEnabled: integer("two_factor_enabled").notNull().default(0),
  // timestamp_ms so Better Auth's Date values round-trip; matches SonicJS's
  // existing Date.now() (ms) convention for these columns.
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var session = sqliteTable("session", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  token: text("token").notNull().unique(),
  expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var account = sqliteTable("account", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp_ms" }),
  refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp_ms" }),
  scope: text("scope"),
  idToken: text("id_token"),
  password: text("password"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var verification = sqliteTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull()
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
  sourceType: text("source_type").default("user"),
  // 'user' (normal), 'form' (form-derived)
  sourceId: text("source_id"),
  // stores the form ID for form-derived collections
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
var securityEvents = sqliteTable("security_events", {
  id: text("id").primaryKey(),
  eventType: text("event_type").notNull(),
  severity: text("severity").notNull().default("info"),
  userId: text("user_id"),
  email: text("email"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  countryCode: text("country_code"),
  requestPath: text("request_path"),
  requestMethod: text("request_method"),
  details: text("details", { mode: "json" }),
  fingerprint: text("fingerprint"),
  blocked: integer("blocked").notNull().default(0),
  createdAt: integer("created_at").notNull().$defaultFn(() => Date.now())
});
var insertSecurityEventSchema = createInsertSchema(securityEvents, {
  eventType: (schema) => schema.min(1),
  severity: (schema) => schema.min(1)
});
var selectSecurityEventSchema = createSelectSchema(securityEvents);
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
  // Content integration
  contentId: text("content_id").references(() => content.id),
  // Links submission to its content item
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

export { account, apiTokens, collections, content, contentVersions, insertCollectionSchema, insertContentSchema, insertLogConfigSchema, insertMediaSchema, insertPluginActivityLogSchema, insertPluginAssetSchema, insertPluginHookSchema, insertPluginRouteSchema, insertPluginSchema, insertSystemLogSchema, insertUserSchema, insertWorkflowHistorySchema, logConfig, media, pluginActivityLog, pluginAssets, pluginHooks, pluginRoutes, plugins, schema_exports, selectCollectionSchema, selectContentSchema, selectLogConfigSchema, selectMediaSchema, selectPluginActivityLogSchema, selectPluginAssetSchema, selectPluginHookSchema, selectPluginRouteSchema, selectPluginSchema, selectSystemLogSchema, selectUserSchema, selectWorkflowHistorySchema, session, systemLogs, users, verification, workflowHistory };
//# sourceMappingURL=chunk-REZQ3JKD.js.map
//# sourceMappingURL=chunk-REZQ3JKD.js.map