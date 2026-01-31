import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { createInsertSchema, createSelectSchema } from 'drizzle-zod';

// Users table for authentication and user management
export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  username: text('username').notNull().unique(),
  name: text('name'), // Better Auth display name (required by Better Auth for registration)
  firstName: text('first_name').notNull(),
  lastName: text('last_name').notNull(),
  passwordHash: text('password_hash'), // Hashed password, nullable for OAuth users
  role: text('role').notNull().default('viewer'), // 'admin', 'editor', 'author', 'viewer'
  avatar: text('avatar'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  lastLoginAt: integer('last_login_at'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Better Auth session table (cookie-based sessions)
export const session = sqliteTable('session', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  token: text('token').notNull().unique(),
  expiresAt: integer('expires_at').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Better Auth account table (credentials + OAuth providers)
export const account = sqliteTable('account', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  accessTokenExpiresAt: integer('access_token_expires_at'),
  refreshTokenExpiresAt: integer('refresh_token_expires_at'),
  scope: text('scope'),
  idToken: text('id_token'),
  password: text('password'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Better Auth verification table (email verification, password reset, etc.)
export const verification = sqliteTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: integer('expires_at').notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Content collections - dynamic schema definitions
export const collections = sqliteTable('collections', {
  id: text('id').primaryKey(),
  name: text('name').notNull().unique(),
  displayName: text('display_name').notNull(),
  description: text('description'),
  schema: text('schema', { mode: 'json' }).notNull(), // JSON schema definition
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  managed: integer('managed', { mode: 'boolean' }).notNull().default(false), // Config-managed collections cannot be edited in UI
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Content items - actual content data
export const content = sqliteTable('content', {
  id: text('id').primaryKey(),
  collectionId: text('collection_id').notNull().references(() => collections.id),
  slug: text('slug').notNull(),
  title: text('title').notNull(),
  data: text('data', { mode: 'json' }).notNull(), // JSON content data
  status: text('status').notNull().default('draft'), // 'draft', 'published', 'archived'
  publishedAt: integer('published_at', { mode: 'timestamp' }),
  authorId: text('author_id').notNull().references(() => users.id),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Content versions for versioning system
export const contentVersions = sqliteTable('content_versions', {
  id: text('id').primaryKey(),
  contentId: text('content_id').notNull().references(() => content.id),
  version: integer('version').notNull(),
  data: text('data', { mode: 'json' }).notNull(),
  authorId: text('author_id').notNull().references(() => users.id),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Media/Files table
export const media = sqliteTable('media', {
  id: text('id').primaryKey(),
  filename: text('filename').notNull(),
  originalName: text('original_name').notNull(),
  mimeType: text('mime_type').notNull(),
  size: integer('size').notNull(),
  width: integer('width'),
  height: integer('height'),
  folder: text('folder').notNull().default('uploads'),
  r2Key: text('r2_key').notNull(), // R2 storage key
  publicUrl: text('public_url').notNull(), // CDN URL
  thumbnailUrl: text('thumbnail_url'),
  alt: text('alt'),
  caption: text('caption'),
  tags: text('tags', { mode: 'json' }), // JSON array of tags
  uploadedBy: text('uploaded_by').notNull().references(() => users.id),
  uploadedAt: integer('uploaded_at').notNull(),
  updatedAt: integer('updated_at'),
  publishedAt: integer('published_at'),
  scheduledAt: integer('scheduled_at'),
  archivedAt: integer('archived_at'),
  deletedAt: integer('deleted_at'),
});

// API tokens for programmatic access
export const apiTokens = sqliteTable('api_tokens', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  token: text('token').notNull().unique(),
  userId: text('user_id').notNull().references(() => users.id),
  permissions: text('permissions', { mode: 'json' }).notNull(), // Array of permissions
  expiresAt: integer('expires_at', { mode: 'timestamp' }),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});


// Workflow history for content workflow tracking
export const workflowHistory = sqliteTable('workflow_history', {
  id: text('id').primaryKey(),
  contentId: text('content_id').notNull().references(() => content.id),
  action: text('action').notNull(),
  fromStatus: text('from_status').notNull(),
  toStatus: text('to_status').notNull(),
  userId: text('user_id').notNull().references(() => users.id),
  comment: text('comment'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Plugin system tables
export const plugins = sqliteTable('plugins', {
  id: text('id').primaryKey(),
  name: text('name').notNull().unique(),
  displayName: text('display_name').notNull(),
  description: text('description'),
  version: text('version').notNull(),
  author: text('author').notNull(),
  category: text('category').notNull(),
  icon: text('icon'),
  status: text('status').notNull().default('inactive'), // 'active', 'inactive', 'error'
  isCore: integer('is_core', { mode: 'boolean' }).notNull().default(false),
  settings: text('settings', { mode: 'json' }),
  permissions: text('permissions', { mode: 'json' }),
  dependencies: text('dependencies', { mode: 'json' }),
  downloadCount: integer('download_count').notNull().default(0),
  rating: integer('rating').notNull().default(0),
  installedAt: integer('installed_at').notNull(),
  activatedAt: integer('activated_at'),
  lastUpdated: integer('last_updated').notNull(),
  errorMessage: text('error_message'),
  createdAt: integer('created_at').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
  updatedAt: integer('updated_at').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
});

export const pluginHooks = sqliteTable('plugin_hooks', {
  id: text('id').primaryKey(),
  pluginId: text('plugin_id').notNull().references(() => plugins.id),
  hookName: text('hook_name').notNull(),
  handlerName: text('handler_name').notNull(),
  priority: integer('priority').notNull().default(10),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
});

export const pluginRoutes = sqliteTable('plugin_routes', {
  id: text('id').primaryKey(),
  pluginId: text('plugin_id').notNull().references(() => plugins.id),
  path: text('path').notNull(),
  method: text('method').notNull(),
  handlerName: text('handler_name').notNull(),
  middleware: text('middleware', { mode: 'json' }),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
});

export const pluginAssets = sqliteTable('plugin_assets', {
  id: text('id').primaryKey(),
  pluginId: text('plugin_id').notNull().references(() => plugins.id),
  assetType: text('asset_type').notNull(), // 'css', 'js', 'image', 'font'
  assetPath: text('asset_path').notNull(),
  loadOrder: integer('load_order').notNull().default(100),
  loadLocation: text('load_location').notNull().default('footer'), // 'header', 'footer'
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
});

export const pluginActivityLog = sqliteTable('plugin_activity_log', {
  id: text('id').primaryKey(),
  pluginId: text('plugin_id').notNull().references(() => plugins.id),
  action: text('action').notNull(),
  userId: text('user_id'),
  details: text('details', { mode: 'json' }),
  timestamp: integer('timestamp').notNull().$defaultFn(() => Math.floor(Date.now() / 1000)),
});

// Zod schemas for validation
export const insertUserSchema = createInsertSchema(users, {
  email: (schema: any) => schema.email(),
  firstName: (schema: any) => schema.min(1),
  lastName: (schema: any) => schema.min(1),
  username: (schema: any) => schema.min(3),
});

export const selectUserSchema = createSelectSchema(users);

export const insertCollectionSchema = createInsertSchema(collections, {
  name: (schema: any) => schema.min(1).regex(/^[a-z0-9_]+$/, 'Collection name must be lowercase with underscores'),
  displayName: (schema: any) => schema.min(1),
});

export const selectCollectionSchema = createSelectSchema(collections);

export const insertContentSchema = createInsertSchema(content, {
  slug: (schema: any) => schema.min(1).regex(/^[a-zA-Z0-9_-]+$/, 'Slug must contain only letters, numbers, underscores, and hyphens'),
  title: (schema: any) => schema.min(1),
  status: (schema: any) => schema,
});

export const selectContentSchema = createSelectSchema(content);

export const insertMediaSchema = createInsertSchema(media, {
  filename: (schema: any) => schema.min(1),
  originalName: (schema: any) => schema.min(1),
  mimeType: (schema: any) => schema.min(1),
  size: (schema: any) => schema.positive(),
  r2Key: (schema: any) => schema.min(1),
  publicUrl: (schema: any) => schema.url(),
  folder: (schema: any) => schema.min(1),
});

export const selectMediaSchema = createSelectSchema(media);


export const insertWorkflowHistorySchema = createInsertSchema(workflowHistory, {
  action: (schema: any) => schema.min(1),
  fromStatus: (schema: any) => schema.min(1),
  toStatus: (schema: any) => schema.min(1),
});

export const selectWorkflowHistorySchema = createSelectSchema(workflowHistory);

export const insertPluginSchema = createInsertSchema(plugins, {
  name: (schema: any) => schema.min(1),
  displayName: (schema: any) => schema.min(1),
  version: (schema: any) => schema.min(1),
  author: (schema: any) => schema.min(1),
  category: (schema: any) => schema.min(1),
});

export const selectPluginSchema = createSelectSchema(plugins);

export const insertPluginHookSchema = createInsertSchema(pluginHooks, {
  hookName: (schema: any) => schema.min(1),
  handlerName: (schema: any) => schema.min(1),
});

export const selectPluginHookSchema = createSelectSchema(pluginHooks);

export const insertPluginRouteSchema = createInsertSchema(pluginRoutes, {
  path: (schema: any) => schema.min(1),
  method: (schema: any) => schema.min(1),
  handlerName: (schema: any) => schema.min(1),
});

export const selectPluginRouteSchema = createSelectSchema(pluginRoutes);

export const insertPluginAssetSchema = createInsertSchema(pluginAssets, {
  assetType: (schema: any) => schema.min(1),
  assetPath: (schema: any) => schema.min(1),
});

export const selectPluginAssetSchema = createSelectSchema(pluginAssets);

export const insertPluginActivityLogSchema = createInsertSchema(pluginActivityLog, {
  action: (schema: any) => schema.min(1),
});

export const selectPluginActivityLogSchema = createSelectSchema(pluginActivityLog);

// System logs table for comprehensive logging
export const systemLogs = sqliteTable('system_logs', {
  id: text('id').primaryKey(),
  level: text('level').notNull(), // 'debug', 'info', 'warn', 'error', 'fatal'
  category: text('category').notNull(), // 'auth', 'api', 'workflow', 'plugin', 'media', 'system', etc.
  message: text('message').notNull(),
  data: text('data', { mode: 'json' }), // Additional structured data
  userId: text('user_id').references(() => users.id),
  sessionId: text('session_id'),
  requestId: text('request_id'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  method: text('method'), // HTTP method for API logs
  url: text('url'), // Request URL for API logs
  statusCode: integer('status_code'), // HTTP status code for API logs
  duration: integer('duration'), // Request duration in milliseconds
  stackTrace: text('stack_trace'), // Error stack trace for error logs
  tags: text('tags', { mode: 'json' }), // Array of tags for categorization
  source: text('source'), // Source component/module that generated the log
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Log configuration table
export const logConfig = sqliteTable('log_config', {
  id: text('id').primaryKey(),
  category: text('category').notNull().unique(),
  enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
  level: text('level').notNull().default('info'), // minimum log level to store
  retention: integer('retention').notNull().default(30), // days to keep logs
  maxSize: integer('max_size').default(10000), // max number of logs per category
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// Insert and select schemas for system logs
export const insertSystemLogSchema = createInsertSchema(systemLogs, {
  level: (schema: any) => schema.min(1),
  category: (schema: any) => schema.min(1),
  message: (schema: any) => schema.min(1),
});

export const selectSystemLogSchema = createSelectSchema(systemLogs);

export const insertLogConfigSchema = createInsertSchema(logConfig, {
  category: (schema: any) => schema.min(1),
  level: (schema: any) => schema.min(1),
});

export const selectLogConfigSchema = createSelectSchema(logConfig);

// Type exports
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Collection = typeof collections.$inferSelect;
export type NewCollection = typeof collections.$inferInsert;
export type Content = typeof content.$inferSelect;
export type NewContent = typeof content.$inferInsert;
export type Media = typeof media.$inferSelect;
export type NewMedia = typeof media.$inferInsert;
export type WorkflowHistory = typeof workflowHistory.$inferSelect;
export type NewWorkflowHistory = typeof workflowHistory.$inferInsert;
export type Plugin = typeof plugins.$inferSelect;
export type NewPlugin = typeof plugins.$inferInsert;
export type PluginHook = typeof pluginHooks.$inferSelect;
export type NewPluginHook = typeof pluginHooks.$inferInsert;
export type PluginRoute = typeof pluginRoutes.$inferSelect;
export type NewPluginRoute = typeof pluginRoutes.$inferInsert;
export type PluginAsset = typeof pluginAssets.$inferSelect;
export type NewPluginAsset = typeof pluginAssets.$inferInsert;
export type PluginActivityLog = typeof pluginActivityLog.$inferSelect;
export type NewPluginActivityLog = typeof pluginActivityLog.$inferInsert;
export type SystemLog = typeof systemLogs.$inferSelect;
export type NewSystemLog = typeof systemLogs.$inferInsert;
export type LogConfig = typeof logConfig.$inferSelect;
export type NewLogConfig = typeof logConfig.$inferInsert;

// =====================================================
// Form.io Integration Tables
// =====================================================

// Forms table - stores Form.io form definitions
export const forms = sqliteTable('forms', {
  id: text('id').primaryKey(),
  name: text('name').notNull().unique(), // Machine name (e.g., "contact-form")
  displayName: text('display_name').notNull(), // Human name (e.g., "Contact Form")
  description: text('description'),
  category: text('category').notNull().default('general'), // contact, survey, registration, etc.
  
  // Form.io schema (JSON)
  formioSchema: text('formio_schema', { mode: 'json' }).notNull(), // Complete Form.io JSON schema
  
  // Settings (JSON)
  settings: text('settings', { mode: 'json' }), // emailNotifications, successMessage, etc.
  
  // Status & Management
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  isPublic: integer('is_public', { mode: 'boolean' }).notNull().default(true),
  managed: integer('managed', { mode: 'boolean' }).notNull().default(false),
  
  // Metadata
  icon: text('icon'),
  color: text('color'),
  tags: text('tags', { mode: 'json' }), // JSON array
  
  // Stats
  submissionCount: integer('submission_count').notNull().default(0),
  viewCount: integer('view_count').notNull().default(0),
  
  // Ownership
  createdBy: text('created_by').references(() => users.id),
  updatedBy: text('updated_by').references(() => users.id),
  
  // Timestamps
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Form submissions table
export const formSubmissions = sqliteTable('form_submissions', {
  id: text('id').primaryKey(),
  formId: text('form_id').notNull().references(() => forms.id, { onDelete: 'cascade' }),
  
  // Submission data
  submissionData: text('submission_data', { mode: 'json' }).notNull(), // The actual form data
  
  // Submission metadata
  status: text('status').notNull().default('pending'), // pending, reviewed, approved, rejected, spam
  submissionNumber: integer('submission_number'),
  
  // User information
  userId: text('user_id').references(() => users.id),
  userEmail: text('user_email'),
  
  // Tracking
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  referrer: text('referrer'),
  utmSource: text('utm_source'),
  utmMedium: text('utm_medium'),
  utmCampaign: text('utm_campaign'),
  
  // Review/Processing
  reviewedBy: text('reviewed_by').references(() => users.id),
  reviewedAt: integer('reviewed_at'),
  reviewNotes: text('review_notes'),
  
  // Flags
  isSpam: integer('is_spam', { mode: 'boolean' }).notNull().default(false),
  isArchived: integer('is_archived', { mode: 'boolean' }).notNull().default(false),
  
  // Timestamps
  submittedAt: integer('submitted_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

// Form files table - links submissions to uploaded files
export const formFiles = sqliteTable('form_files', {
  id: text('id').primaryKey(),
  submissionId: text('submission_id').notNull().references(() => formSubmissions.id, { onDelete: 'cascade' }),
  mediaId: text('media_id').notNull().references(() => media.id, { onDelete: 'cascade' }),
  fieldName: text('field_name').notNull(), // Form field that uploaded this file
  uploadedAt: integer('uploaded_at').notNull(),
});

// Zod schemas for validation
export const insertFormSchema = createInsertSchema(forms);
export const selectFormSchema = createSelectSchema(forms);
export const insertFormSubmissionSchema = createInsertSchema(formSubmissions);
export const selectFormSubmissionSchema = createSelectSchema(formSubmissions);
export const insertFormFileSchema = createInsertSchema(formFiles);
export const selectFormFileSchema = createSelectSchema(formFiles);

// TypeScript types
export type Form = typeof forms.$inferSelect;
export type NewForm = typeof forms.$inferInsert;
export type FormSubmission = typeof formSubmissions.$inferSelect;
export type NewFormSubmission = typeof formSubmissions.$inferInsert;
export type FormFile = typeof formFiles.$inferSelect;
export type NewFormFile = typeof formFiles.$inferInsert;