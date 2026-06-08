'use strict';

var chunkIGJUBJBW_cjs = require('./chunk-IGJUBJBW.cjs');
var sqliteCore = require('drizzle-orm/sqlite-core');
var v4 = require('zod/v4');
var drizzleOrm = require('drizzle-orm');

// src/db/schema.ts
var schema_exports = {};
chunkIGJUBJBW_cjs.__export(schema_exports, {
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
var literalSchema = v4.z.union([v4.z.string(), v4.z.number(), v4.z.boolean(), v4.z.null()]);
var jsonSchema = v4.z.union([
  literalSchema,
  v4.z.record(v4.z.string(), v4.z.any()),
  v4.z.array(v4.z.any())
]);
var bufferSchema = v4.z.custom((v) => v instanceof Buffer);
function columnToSchema(column, factory) {
  const z$1 = v4.z;
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
  return drizzleOrm.isTable(tableLike) ? drizzleOrm.getTableColumns(tableLike) : drizzleOrm.getViewSelectedFields(tableLike);
}
function handleColumns(columns, refinements, conditions, factory) {
  const columnSchemas = {};
  for (const [key, selected] of Object.entries(columns)) {
    if (!drizzleOrm.is(selected, drizzleOrm.Column) && !drizzleOrm.is(selected, drizzleOrm.SQL) && !drizzleOrm.is(selected, drizzleOrm.SQL.Aliased) && typeof selected === "object") {
      const columns2 = drizzleOrm.isTable(selected) || drizzleOrm.isView(selected) ? getColumns(selected) : selected;
      columnSchemas[key] = handleColumns(columns2, refinements[key] ?? {}, conditions);
      continue;
    }
    const refinement = refinements[key];
    if (refinement !== void 0 && typeof refinement !== "function") {
      columnSchemas[key] = refinement;
      continue;
    }
    const column = drizzleOrm.is(selected, drizzleOrm.Column) ? selected : void 0;
    const schema = column ? columnToSchema(column) : v4.z.any();
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
  return v4.z.object(columnSchemas);
}
function handleEnum(enum_, factory) {
  const zod = v4.z;
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
var users = sqliteCore.sqliteTable("users", {
  id: sqliteCore.text("id").primaryKey(),
  email: sqliteCore.text("email").notNull().unique(),
  username: sqliteCore.text("username").notNull().unique(),
  firstName: sqliteCore.text("first_name").notNull(),
  lastName: sqliteCore.text("last_name").notNull(),
  passwordHash: sqliteCore.text("password_hash"),
  // Hashed password, nullable for OAuth users
  name: sqliteCore.text("name"),
  // Better Auth display name (required by Better Auth for registration)
  emailVerified: sqliteCore.integer("email_verified", { mode: "boolean" }).notNull().default(false),
  // Better Auth
  role: sqliteCore.text("role").notNull().default("viewer"),
  // 'admin', 'editor', 'author', 'viewer'
  avatar: sqliteCore.text("avatar"),
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  lastLoginAt: sqliteCore.integer("last_login_at"),
  // Password reset (routes/auth.ts)
  passwordResetToken: sqliteCore.text("password_reset_token"),
  passwordResetExpires: sqliteCore.integer("password_reset_expires"),
  // Invitation flow (routes/auth.ts accept-invitation)
  invitationToken: sqliteCore.text("invitation_token"),
  invitedAt: sqliteCore.integer("invited_at"),
  acceptedInvitationAt: sqliteCore.integer("accepted_invitation_at"),
  // Account lockout (migration 041): reset on success; set on threshold failures
  failedLoginCount: sqliteCore.integer("failed_login_count").notNull().default(0),
  lockedUntil: sqliteCore.integer("locked_until"),
  // 2FA enrollment flag (migration 042, twoFactor BA plugin)
  twoFactorEnabled: sqliteCore.integer("two_factor_enabled").notNull().default(0),
  // timestamp_ms so Better Auth's Date values round-trip; matches SonicJS's
  // existing Date.now() (ms) convention for these columns.
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var session = sqliteCore.sqliteTable("session", {
  id: sqliteCore.text("id").primaryKey(),
  userId: sqliteCore.text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  token: sqliteCore.text("token").notNull().unique(),
  expiresAt: sqliteCore.integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  ipAddress: sqliteCore.text("ip_address"),
  userAgent: sqliteCore.text("user_agent"),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var account = sqliteCore.sqliteTable("account", {
  id: sqliteCore.text("id").primaryKey(),
  userId: sqliteCore.text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  accountId: sqliteCore.text("account_id").notNull(),
  providerId: sqliteCore.text("provider_id").notNull(),
  accessToken: sqliteCore.text("access_token"),
  refreshToken: sqliteCore.text("refresh_token"),
  accessTokenExpiresAt: sqliteCore.integer("access_token_expires_at", { mode: "timestamp_ms" }),
  refreshTokenExpiresAt: sqliteCore.integer("refresh_token_expires_at", { mode: "timestamp_ms" }),
  scope: sqliteCore.text("scope"),
  idToken: sqliteCore.text("id_token"),
  password: sqliteCore.text("password"),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var verification = sqliteCore.sqliteTable("verification", {
  id: sqliteCore.text("id").primaryKey(),
  identifier: sqliteCore.text("identifier").notNull(),
  value: sqliteCore.text("value").notNull(),
  expiresAt: sqliteCore.integer("expires_at", { mode: "timestamp_ms" }).notNull(),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp_ms" }).notNull(),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp_ms" }).notNull()
});
var collections = sqliteCore.sqliteTable("collections", {
  id: sqliteCore.text("id").primaryKey(),
  name: sqliteCore.text("name").notNull().unique(),
  displayName: sqliteCore.text("display_name").notNull(),
  description: sqliteCore.text("description"),
  schema: sqliteCore.text("schema", { mode: "json" }).notNull(),
  // JSON schema definition
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  managed: sqliteCore.integer("managed", { mode: "boolean" }).notNull().default(false),
  // Config-managed collections cannot be edited in UI
  sourceType: sqliteCore.text("source_type").default("user"),
  // 'user' (normal), 'form' (form-derived)
  sourceId: sqliteCore.text("source_id"),
  // stores the form ID for form-derived collections
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var content = sqliteCore.sqliteTable("content", {
  id: sqliteCore.text("id").primaryKey(),
  collectionId: sqliteCore.text("collection_id").notNull().references(() => collections.id),
  slug: sqliteCore.text("slug").notNull(),
  title: sqliteCore.text("title").notNull(),
  data: sqliteCore.text("data", { mode: "json" }).notNull(),
  // JSON content data
  status: sqliteCore.text("status").notNull().default("draft"),
  // 'draft', 'published', 'archived'
  publishedAt: sqliteCore.integer("published_at", { mode: "timestamp" }),
  authorId: sqliteCore.text("author_id").notNull().references(() => users.id),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var contentVersions = sqliteCore.sqliteTable("content_versions", {
  id: sqliteCore.text("id").primaryKey(),
  contentId: sqliteCore.text("content_id").notNull().references(() => content.id),
  version: sqliteCore.integer("version").notNull(),
  data: sqliteCore.text("data", { mode: "json" }).notNull(),
  authorId: sqliteCore.text("author_id").notNull().references(() => users.id),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var media = sqliteCore.sqliteTable("media", {
  id: sqliteCore.text("id").primaryKey(),
  filename: sqliteCore.text("filename").notNull(),
  originalName: sqliteCore.text("original_name").notNull(),
  mimeType: sqliteCore.text("mime_type").notNull(),
  size: sqliteCore.integer("size").notNull(),
  width: sqliteCore.integer("width"),
  height: sqliteCore.integer("height"),
  folder: sqliteCore.text("folder").notNull().default("uploads"),
  r2Key: sqliteCore.text("r2_key").notNull(),
  // R2 storage key
  publicUrl: sqliteCore.text("public_url").notNull(),
  // CDN URL
  thumbnailUrl: sqliteCore.text("thumbnail_url"),
  alt: sqliteCore.text("alt"),
  caption: sqliteCore.text("caption"),
  tags: sqliteCore.text("tags", { mode: "json" }),
  // JSON array of tags
  uploadedBy: sqliteCore.text("uploaded_by").notNull().references(() => users.id),
  uploadedAt: sqliteCore.integer("uploaded_at").notNull(),
  updatedAt: sqliteCore.integer("updated_at"),
  publishedAt: sqliteCore.integer("published_at"),
  scheduledAt: sqliteCore.integer("scheduled_at"),
  archivedAt: sqliteCore.integer("archived_at"),
  deletedAt: sqliteCore.integer("deleted_at")
});
var apiTokens = sqliteCore.sqliteTable("api_tokens", {
  id: sqliteCore.text("id").primaryKey(),
  name: sqliteCore.text("name").notNull(),
  token: sqliteCore.text("token").notNull().unique(),
  userId: sqliteCore.text("user_id").notNull().references(() => users.id),
  permissions: sqliteCore.text("permissions", { mode: "json" }).notNull(),
  // Array of permissions
  expiresAt: sqliteCore.integer("expires_at", { mode: "timestamp" }),
  lastUsedAt: sqliteCore.integer("last_used_at", { mode: "timestamp" }),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var workflowHistory = sqliteCore.sqliteTable("workflow_history", {
  id: sqliteCore.text("id").primaryKey(),
  contentId: sqliteCore.text("content_id").notNull().references(() => content.id),
  action: sqliteCore.text("action").notNull(),
  fromStatus: sqliteCore.text("from_status").notNull(),
  toStatus: sqliteCore.text("to_status").notNull(),
  userId: sqliteCore.text("user_id").notNull().references(() => users.id),
  comment: sqliteCore.text("comment"),
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var plugins = sqliteCore.sqliteTable("plugins", {
  id: sqliteCore.text("id").primaryKey(),
  name: sqliteCore.text("name").notNull().unique(),
  displayName: sqliteCore.text("display_name").notNull(),
  description: sqliteCore.text("description"),
  version: sqliteCore.text("version").notNull(),
  author: sqliteCore.text("author").notNull(),
  category: sqliteCore.text("category").notNull(),
  icon: sqliteCore.text("icon"),
  status: sqliteCore.text("status").notNull().default("inactive"),
  // 'active', 'inactive', 'error'
  isCore: sqliteCore.integer("is_core", { mode: "boolean" }).notNull().default(false),
  settings: sqliteCore.text("settings", { mode: "json" }),
  permissions: sqliteCore.text("permissions", { mode: "json" }),
  dependencies: sqliteCore.text("dependencies", { mode: "json" }),
  downloadCount: sqliteCore.integer("download_count").notNull().default(0),
  rating: sqliteCore.integer("rating").notNull().default(0),
  installedAt: sqliteCore.integer("installed_at").notNull(),
  activatedAt: sqliteCore.integer("activated_at"),
  lastUpdated: sqliteCore.integer("last_updated").notNull(),
  errorMessage: sqliteCore.text("error_message"),
  createdAt: sqliteCore.integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3)),
  updatedAt: sqliteCore.integer("updated_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginHooks = sqliteCore.sqliteTable("plugin_hooks", {
  id: sqliteCore.text("id").primaryKey(),
  pluginId: sqliteCore.text("plugin_id").notNull().references(() => plugins.id),
  hookName: sqliteCore.text("hook_name").notNull(),
  handlerName: sqliteCore.text("handler_name").notNull(),
  priority: sqliteCore.integer("priority").notNull().default(10),
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: sqliteCore.integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginRoutes = sqliteCore.sqliteTable("plugin_routes", {
  id: sqliteCore.text("id").primaryKey(),
  pluginId: sqliteCore.text("plugin_id").notNull().references(() => plugins.id),
  path: sqliteCore.text("path").notNull(),
  method: sqliteCore.text("method").notNull(),
  handlerName: sqliteCore.text("handler_name").notNull(),
  middleware: sqliteCore.text("middleware", { mode: "json" }),
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: sqliteCore.integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginAssets = sqliteCore.sqliteTable("plugin_assets", {
  id: sqliteCore.text("id").primaryKey(),
  pluginId: sqliteCore.text("plugin_id").notNull().references(() => plugins.id),
  assetType: sqliteCore.text("asset_type").notNull(),
  // 'css', 'js', 'image', 'font'
  assetPath: sqliteCore.text("asset_path").notNull(),
  loadOrder: sqliteCore.integer("load_order").notNull().default(100),
  loadLocation: sqliteCore.text("load_location").notNull().default("footer"),
  // 'header', 'footer'
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  createdAt: sqliteCore.integer("created_at").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
});
var pluginActivityLog = sqliteCore.sqliteTable("plugin_activity_log", {
  id: sqliteCore.text("id").primaryKey(),
  pluginId: sqliteCore.text("plugin_id").notNull().references(() => plugins.id),
  action: sqliteCore.text("action").notNull(),
  userId: sqliteCore.text("user_id"),
  details: sqliteCore.text("details", { mode: "json" }),
  timestamp: sqliteCore.integer("timestamp").notNull().$defaultFn(() => Math.floor(Date.now() / 1e3))
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
var systemLogs = sqliteCore.sqliteTable("system_logs", {
  id: sqliteCore.text("id").primaryKey(),
  level: sqliteCore.text("level").notNull(),
  // 'debug', 'info', 'warn', 'error', 'fatal'
  category: sqliteCore.text("category").notNull(),
  // 'auth', 'api', 'workflow', 'plugin', 'media', 'system', etc.
  message: sqliteCore.text("message").notNull(),
  data: sqliteCore.text("data", { mode: "json" }),
  // Additional structured data
  userId: sqliteCore.text("user_id").references(() => users.id),
  sessionId: sqliteCore.text("session_id"),
  requestId: sqliteCore.text("request_id"),
  ipAddress: sqliteCore.text("ip_address"),
  userAgent: sqliteCore.text("user_agent"),
  method: sqliteCore.text("method"),
  // HTTP method for API logs
  url: sqliteCore.text("url"),
  // Request URL for API logs
  statusCode: sqliteCore.integer("status_code"),
  // HTTP status code for API logs
  duration: sqliteCore.integer("duration"),
  // Request duration in milliseconds
  stackTrace: sqliteCore.text("stack_trace"),
  // Error stack trace for error logs
  tags: sqliteCore.text("tags", { mode: "json" }),
  // Array of tags for categorization
  source: sqliteCore.text("source"),
  // Source component/module that generated the log
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
});
var logConfig = sqliteCore.sqliteTable("log_config", {
  id: sqliteCore.text("id").primaryKey(),
  category: sqliteCore.text("category").notNull().unique(),
  enabled: sqliteCore.integer("enabled", { mode: "boolean" }).notNull().default(true),
  level: sqliteCore.text("level").notNull().default("info"),
  // minimum log level to store
  retention: sqliteCore.integer("retention").notNull().default(30),
  // days to keep logs
  maxSize: sqliteCore.integer("max_size").default(1e4),
  // max number of logs per category
  createdAt: sqliteCore.integer("created_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date()),
  updatedAt: sqliteCore.integer("updated_at", { mode: "timestamp" }).notNull().$defaultFn(() => /* @__PURE__ */ new Date())
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
var securityEvents = sqliteCore.sqliteTable("security_events", {
  id: sqliteCore.text("id").primaryKey(),
  eventType: sqliteCore.text("event_type").notNull(),
  severity: sqliteCore.text("severity").notNull().default("info"),
  userId: sqliteCore.text("user_id"),
  email: sqliteCore.text("email"),
  ipAddress: sqliteCore.text("ip_address"),
  userAgent: sqliteCore.text("user_agent"),
  countryCode: sqliteCore.text("country_code"),
  requestPath: sqliteCore.text("request_path"),
  requestMethod: sqliteCore.text("request_method"),
  details: sqliteCore.text("details", { mode: "json" }),
  fingerprint: sqliteCore.text("fingerprint"),
  blocked: sqliteCore.integer("blocked").notNull().default(0),
  createdAt: sqliteCore.integer("created_at").notNull().$defaultFn(() => Date.now())
});
var insertSecurityEventSchema = createInsertSchema(securityEvents, {
  eventType: (schema) => schema.min(1),
  severity: (schema) => schema.min(1)
});
var selectSecurityEventSchema = createSelectSchema(securityEvents);
var forms = sqliteCore.sqliteTable("forms", {
  id: sqliteCore.text("id").primaryKey(),
  name: sqliteCore.text("name").notNull().unique(),
  // Machine name (e.g., "contact-form")
  displayName: sqliteCore.text("display_name").notNull(),
  // Human name (e.g., "Contact Form")
  description: sqliteCore.text("description"),
  category: sqliteCore.text("category").notNull().default("general"),
  // contact, survey, registration, etc.
  // Form.io schema (JSON)
  formioSchema: sqliteCore.text("formio_schema", { mode: "json" }).notNull(),
  // Complete Form.io JSON schema
  // Settings (JSON)
  settings: sqliteCore.text("settings", { mode: "json" }),
  // emailNotifications, successMessage, etc.
  // Status & Management
  isActive: sqliteCore.integer("is_active", { mode: "boolean" }).notNull().default(true),
  isPublic: sqliteCore.integer("is_public", { mode: "boolean" }).notNull().default(true),
  managed: sqliteCore.integer("managed", { mode: "boolean" }).notNull().default(false),
  // Metadata
  icon: sqliteCore.text("icon"),
  color: sqliteCore.text("color"),
  tags: sqliteCore.text("tags", { mode: "json" }),
  // JSON array
  // Stats
  submissionCount: sqliteCore.integer("submission_count").notNull().default(0),
  viewCount: sqliteCore.integer("view_count").notNull().default(0),
  // Ownership
  createdBy: sqliteCore.text("created_by").references(() => users.id),
  updatedBy: sqliteCore.text("updated_by").references(() => users.id),
  // Timestamps
  createdAt: sqliteCore.integer("created_at").notNull(),
  updatedAt: sqliteCore.integer("updated_at").notNull()
});
var formSubmissions = sqliteCore.sqliteTable("form_submissions", {
  id: sqliteCore.text("id").primaryKey(),
  formId: sqliteCore.text("form_id").notNull().references(() => forms.id, { onDelete: "cascade" }),
  // Submission data
  submissionData: sqliteCore.text("submission_data", { mode: "json" }).notNull(),
  // The actual form data
  // Submission metadata
  status: sqliteCore.text("status").notNull().default("pending"),
  // pending, reviewed, approved, rejected, spam
  submissionNumber: sqliteCore.integer("submission_number"),
  // User information
  userId: sqliteCore.text("user_id").references(() => users.id),
  userEmail: sqliteCore.text("user_email"),
  // Tracking
  ipAddress: sqliteCore.text("ip_address"),
  userAgent: sqliteCore.text("user_agent"),
  referrer: sqliteCore.text("referrer"),
  utmSource: sqliteCore.text("utm_source"),
  utmMedium: sqliteCore.text("utm_medium"),
  utmCampaign: sqliteCore.text("utm_campaign"),
  // Review/Processing
  reviewedBy: sqliteCore.text("reviewed_by").references(() => users.id),
  reviewedAt: sqliteCore.integer("reviewed_at"),
  reviewNotes: sqliteCore.text("review_notes"),
  // Flags
  isSpam: sqliteCore.integer("is_spam", { mode: "boolean" }).notNull().default(false),
  isArchived: sqliteCore.integer("is_archived", { mode: "boolean" }).notNull().default(false),
  // Content integration
  contentId: sqliteCore.text("content_id").references(() => content.id),
  // Links submission to its content item
  // Timestamps
  submittedAt: sqliteCore.integer("submitted_at").notNull(),
  updatedAt: sqliteCore.integer("updated_at").notNull()
});
var formFiles = sqliteCore.sqliteTable("form_files", {
  id: sqliteCore.text("id").primaryKey(),
  submissionId: sqliteCore.text("submission_id").notNull().references(() => formSubmissions.id, { onDelete: "cascade" }),
  mediaId: sqliteCore.text("media_id").notNull().references(() => media.id, { onDelete: "cascade" }),
  fieldName: sqliteCore.text("field_name").notNull(),
  // Form field that uploaded this file
  uploadedAt: sqliteCore.integer("uploaded_at").notNull()
});
var insertFormSchema = createInsertSchema(forms);
var selectFormSchema = createSelectSchema(forms);
var insertFormSubmissionSchema = createInsertSchema(formSubmissions);
var selectFormSubmissionSchema = createSelectSchema(formSubmissions);
var insertFormFileSchema = createInsertSchema(formFiles);
var selectFormFileSchema = createSelectSchema(formFiles);

exports.account = account;
exports.apiTokens = apiTokens;
exports.collections = collections;
exports.content = content;
exports.contentVersions = contentVersions;
exports.insertCollectionSchema = insertCollectionSchema;
exports.insertContentSchema = insertContentSchema;
exports.insertLogConfigSchema = insertLogConfigSchema;
exports.insertMediaSchema = insertMediaSchema;
exports.insertPluginActivityLogSchema = insertPluginActivityLogSchema;
exports.insertPluginAssetSchema = insertPluginAssetSchema;
exports.insertPluginHookSchema = insertPluginHookSchema;
exports.insertPluginRouteSchema = insertPluginRouteSchema;
exports.insertPluginSchema = insertPluginSchema;
exports.insertSystemLogSchema = insertSystemLogSchema;
exports.insertUserSchema = insertUserSchema;
exports.insertWorkflowHistorySchema = insertWorkflowHistorySchema;
exports.logConfig = logConfig;
exports.media = media;
exports.pluginActivityLog = pluginActivityLog;
exports.pluginAssets = pluginAssets;
exports.pluginHooks = pluginHooks;
exports.pluginRoutes = pluginRoutes;
exports.plugins = plugins;
exports.schema_exports = schema_exports;
exports.selectCollectionSchema = selectCollectionSchema;
exports.selectContentSchema = selectContentSchema;
exports.selectLogConfigSchema = selectLogConfigSchema;
exports.selectMediaSchema = selectMediaSchema;
exports.selectPluginActivityLogSchema = selectPluginActivityLogSchema;
exports.selectPluginAssetSchema = selectPluginAssetSchema;
exports.selectPluginHookSchema = selectPluginHookSchema;
exports.selectPluginRouteSchema = selectPluginRouteSchema;
exports.selectPluginSchema = selectPluginSchema;
exports.selectSystemLogSchema = selectSystemLogSchema;
exports.selectUserSchema = selectUserSchema;
exports.selectWorkflowHistorySchema = selectWorkflowHistorySchema;
exports.session = session;
exports.systemLogs = systemLogs;
exports.users = users;
exports.verification = verification;
exports.workflowHistory = workflowHistory;
//# sourceMappingURL=chunk-4RVMY6FI.cjs.map
//# sourceMappingURL=chunk-4RVMY6FI.cjs.map