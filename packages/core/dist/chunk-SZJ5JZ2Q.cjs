'use strict';

// src/db/migrations-bundle.ts
var bundledMigrations = [
  {
    id: "001",
    name: "Initial Schema",
    filename: "001_initial_schema.sql",
    description: "Migration 001: Initial Schema",
    sql: `-- Initial schema for SonicJS AI
-- Create users table for authentication
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'viewer',
  avatar TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  last_login_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create collections table for content schema definitions
CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  schema TEXT NOT NULL, -- JSON schema definition
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create content table for actual content data
CREATE TABLE IF NOT EXISTS content (
  id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES collections(id),
  slug TEXT NOT NULL,
  title TEXT NOT NULL,
  data TEXT NOT NULL, -- JSON content data
  status TEXT NOT NULL DEFAULT 'draft',
  published_at INTEGER,
  author_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Create content_versions table for versioning
CREATE TABLE IF NOT EXISTS content_versions (
  id TEXT PRIMARY KEY,
  content_id TEXT NOT NULL REFERENCES content(id),
  version INTEGER NOT NULL,
  data TEXT NOT NULL, -- JSON data
  author_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);

-- Create media/files table with comprehensive R2 integration
CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  width INTEGER,
  height INTEGER,
  folder TEXT NOT NULL DEFAULT 'uploads',
  r2_key TEXT NOT NULL, -- R2 storage key
  public_url TEXT NOT NULL, -- CDN URL
  thumbnail_url TEXT, -- Cloudflare Images URL
  alt TEXT,
  caption TEXT,
  tags TEXT, -- JSON array of tags
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  uploaded_at INTEGER NOT NULL,
  updated_at INTEGER,
  published_at INTEGER,
  scheduled_at INTEGER,
  archived_at INTEGER,
  deleted_at INTEGER
);

-- Create API tokens table for programmatic access
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  permissions TEXT NOT NULL, -- JSON array of permissions
  expires_at INTEGER,
  last_used_at INTEGER,
  created_at INTEGER NOT NULL
);

-- Create workflow history table for content workflow tracking
CREATE TABLE IF NOT EXISTS workflow_history (
  id TEXT PRIMARY KEY,
  content_id TEXT NOT NULL REFERENCES content(id),
  action TEXT NOT NULL,
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  comment TEXT,
  created_at INTEGER NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE INDEX IF NOT EXISTS idx_collections_name ON collections(name);
CREATE INDEX IF NOT EXISTS idx_collections_active ON collections(is_active);

CREATE INDEX IF NOT EXISTS idx_content_collection ON content(collection_id);
CREATE INDEX IF NOT EXISTS idx_content_author ON content(author_id);
CREATE INDEX IF NOT EXISTS idx_content_status ON content(status);
CREATE INDEX IF NOT EXISTS idx_content_published ON content(published_at);
CREATE INDEX IF NOT EXISTS idx_content_slug ON content(slug);

CREATE INDEX IF NOT EXISTS idx_content_versions_content ON content_versions(content_id);
CREATE INDEX IF NOT EXISTS idx_content_versions_version ON content_versions(version);

CREATE INDEX IF NOT EXISTS idx_media_folder ON media(folder);
CREATE INDEX IF NOT EXISTS idx_media_type ON media(mime_type);
CREATE INDEX IF NOT EXISTS idx_media_uploaded_by ON media(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_media_uploaded_at ON media(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_media_deleted ON media(deleted_at);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token);

CREATE INDEX IF NOT EXISTS idx_workflow_history_content ON workflow_history(content_id);
CREATE INDEX IF NOT EXISTS idx_workflow_history_user ON workflow_history(user_id);

-- Note: Admin user is created via the seed script with user-provided credentials
-- Run 'npm run seed' after migrations to create the admin user

-- Insert sample collections
INSERT OR IGNORE INTO collections (
  id, name, display_name, description, schema, 
  is_active, created_at, updated_at
) VALUES (
  'blog-posts-collection',
  'blog_posts',
  'Blog Posts',
  'Blog post content collection',
  '{"type":"object","properties":{"title":{"type":"string","title":"Title","required":true},"content":{"type":"string","title":"Content","format":"richtext"},"excerpt":{"type":"string","title":"Excerpt"},"featured_image":{"type":"string","title":"Featured Image","format":"media"},"tags":{"type":"array","title":"Tags","items":{"type":"string"}},"status":{"type":"string","title":"Status","enum":["draft","published","archived"],"default":"draft"}},"required":["title"]}',
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
),
(
  'pages-collection',
  'pages',
  'Pages',
  'Static page content collection',
  '{"type":"object","properties":{"title":{"type":"string","title":"Title","required":true},"content":{"type":"string","title":"Content","format":"richtext"},"slug":{"type":"string","title":"Slug"},"meta_description":{"type":"string","title":"Meta Description"},"featured_image":{"type":"string","title":"Featured Image","format":"media"}},"required":["title"]}',
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
),
(
  'news-collection',
  'news',
  'News',
  'News article content collection',
  '{"type":"object","properties":{"title":{"type":"string","title":"Title","required":true},"content":{"type":"string","title":"Content","format":"richtext"},"publish_date":{"type":"string","title":"Publish Date","format":"date"},"author":{"type":"string","title":"Author"},"category":{"type":"string","title":"Category","enum":["technology","business","general"]}},"required":["title"]}',
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
);

-- Note: Sample content can be created via the admin interface after the admin user is seeded`
  },
  {
    id: "002",
    name: "Faq Plugin",
    filename: "002_faq_plugin.sql",
    description: "Migration 002: Faq Plugin",
    sql: `-- FAQ Plugin Migration (DEPRECATED - Now managed by third-party plugin)
-- Creates FAQ table for the FAQ plugin
-- NOTE: This migration is kept for historical purposes. 
-- The FAQ functionality is now provided by the faq-plugin third-party plugin.

CREATE TABLE IF NOT EXISTS faqs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question TEXT NOT NULL,
  answer TEXT NOT NULL,
  category TEXT,
  tags TEXT,
  isPublished INTEGER NOT NULL DEFAULT 1,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_faqs_category ON faqs(category);
CREATE INDEX IF NOT EXISTS idx_faqs_published ON faqs(isPublished);
CREATE INDEX IF NOT EXISTS idx_faqs_sort_order ON faqs(sortOrder);

-- Create trigger to update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS faqs_updated_at
  AFTER UPDATE ON faqs
BEGIN
  UPDATE faqs SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- Insert sample FAQ data
INSERT OR IGNORE INTO faqs (question, answer, category, tags, isPublished, sortOrder) VALUES 
('What is SonicJS AI?', 
'SonicJS AI is a modern, TypeScript-first headless CMS built for Cloudflare''s edge platform. It provides a complete content management system with admin interface, API endpoints, and plugin architecture.',
'general',
'sonicjs, cms, cloudflare',
1,
1),

('How do I get started with SonicJS AI?',
'To get started: 1) Clone the repository, 2) Install dependencies with npm install, 3) Set up your Cloudflare account and services, 4) Run the development server with npm run dev, 5) Access the admin interface at /admin.',
'general',
'getting-started, setup',
1,
2),

('What technologies does SonicJS AI use?',
'SonicJS AI is built with: TypeScript for type safety, Hono.js as the web framework, Cloudflare D1 for the database, Cloudflare R2 for media storage, Cloudflare Workers for serverless execution, and Tailwind CSS for styling.',
'technical',
'technology-stack, typescript, cloudflare',
1,
3),

('How do I create content in SonicJS AI?',
'Content creation is done through the admin interface. Navigate to /admin, log in with your credentials, go to Content section, select a collection, and click "New Content" to create articles, pages, or other content types.',
'general',
'content-creation, admin',
1,
4),

('Is SonicJS AI free to use?',
'SonicJS AI is open source and free to use. You only pay for the Cloudflare services you consume (D1 database, R2 storage, Workers execution time). Cloudflare offers generous free tiers for development and small projects.',
'billing',
'pricing, open-source, cloudflare',
1,
5),

('How do I add custom functionality?',
'SonicJS AI features a plugin system that allows you to extend functionality. You can create plugins using the PluginBuilder API, add custom routes, models, admin pages, and integrate with external services.',
'technical',
'plugins, customization, development',
1,
6),

('Can I customize the admin interface?',
'Yes! The admin interface is built with TypeScript templates and can be customized. You can modify existing templates, create new components, add custom pages, and integrate your own styling while maintaining the dark theme.',
'technical',
'admin-interface, customization, templates',
1,
7),

('How does authentication work?',
'SonicJS AI includes a built-in authentication system with JWT tokens, role-based access control (admin, editor, viewer), secure password hashing, and session management. Users can be managed through the admin interface.',
'technical',
'authentication, security, users',
1,
8);`
  },
  {
    id: "003",
    name: "Stage5 Enhancements",
    filename: "003_stage5_enhancements.sql",
    description: "Migration 003: Stage5 Enhancements",
    sql: `-- Stage 5: Advanced Content Management enhancements
-- Add scheduling and workflow features to content table

-- Add content scheduling columns
ALTER TABLE content ADD COLUMN scheduled_publish_at INTEGER;
ALTER TABLE content ADD COLUMN scheduled_unpublish_at INTEGER;

-- Add workflow and review columns
ALTER TABLE content ADD COLUMN review_status TEXT DEFAULT 'none'; -- none, pending, approved, rejected
ALTER TABLE content ADD COLUMN reviewer_id TEXT REFERENCES users(id);
ALTER TABLE content ADD COLUMN reviewed_at INTEGER;
ALTER TABLE content ADD COLUMN review_notes TEXT;

-- Add content metadata
ALTER TABLE content ADD COLUMN meta_title TEXT;
ALTER TABLE content ADD COLUMN meta_description TEXT;
ALTER TABLE content ADD COLUMN featured_image_id TEXT REFERENCES media(id);
ALTER TABLE content ADD COLUMN content_type TEXT DEFAULT 'standard'; -- standard, template, component

-- Create content_fields table for dynamic field definitions
CREATE TABLE IF NOT EXISTS content_fields (
  id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES collections(id),
  field_name TEXT NOT NULL,
  field_type TEXT NOT NULL, -- text, richtext, number, boolean, date, select, media, relationship
  field_label TEXT NOT NULL,
  field_options TEXT, -- JSON for select options, validation rules, etc.
  field_order INTEGER NOT NULL DEFAULT 0,
  is_required INTEGER NOT NULL DEFAULT 0,
  is_searchable INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(collection_id, field_name)
);

-- Create content_relationships table for content relationships
CREATE TABLE IF NOT EXISTS content_relationships (
  id TEXT PRIMARY KEY,
  source_content_id TEXT NOT NULL REFERENCES content(id),
  target_content_id TEXT NOT NULL REFERENCES content(id),
  relationship_type TEXT NOT NULL, -- references, tags, categories
  created_at INTEGER NOT NULL,
  UNIQUE(source_content_id, target_content_id, relationship_type)
);

-- Create workflow_templates table for reusable workflows
CREATE TABLE IF NOT EXISTS workflow_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  collection_id TEXT REFERENCES collections(id), -- null means applies to all collections
  workflow_steps TEXT NOT NULL, -- JSON array of workflow steps
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_content_scheduled_publish ON content(scheduled_publish_at);
CREATE INDEX IF NOT EXISTS idx_content_scheduled_unpublish ON content(scheduled_unpublish_at);
CREATE INDEX IF NOT EXISTS idx_content_review_status ON content(review_status);
CREATE INDEX IF NOT EXISTS idx_content_reviewer ON content(reviewer_id);
CREATE INDEX IF NOT EXISTS idx_content_content_type ON content(content_type);

CREATE INDEX IF NOT EXISTS idx_content_fields_collection ON content_fields(collection_id);
CREATE INDEX IF NOT EXISTS idx_content_fields_name ON content_fields(field_name);
CREATE INDEX IF NOT EXISTS idx_content_fields_type ON content_fields(field_type);
CREATE INDEX IF NOT EXISTS idx_content_fields_order ON content_fields(field_order);

CREATE INDEX IF NOT EXISTS idx_content_relationships_source ON content_relationships(source_content_id);
CREATE INDEX IF NOT EXISTS idx_content_relationships_target ON content_relationships(target_content_id);
CREATE INDEX IF NOT EXISTS idx_content_relationships_type ON content_relationships(relationship_type);

CREATE INDEX IF NOT EXISTS idx_workflow_templates_collection ON workflow_templates(collection_id);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_active ON workflow_templates(is_active);

-- Insert default workflow template
INSERT OR IGNORE INTO workflow_templates (
  id, name, description, workflow_steps, is_active, created_at, updated_at
) VALUES (
  'default-content-workflow',
  'Default Content Workflow',
  'Standard content workflow: Draft \u2192 Review \u2192 Published',
  '[
    {"step": "draft", "name": "Draft", "description": "Content is being created", "permissions": ["author", "editor", "admin"]},
    {"step": "review", "name": "Under Review", "description": "Content is pending review", "permissions": ["editor", "admin"]},
    {"step": "published", "name": "Published", "description": "Content is live", "permissions": ["editor", "admin"]},
    {"step": "archived", "name": "Archived", "description": "Content is archived", "permissions": ["admin"]}
  ]',
  1,
  strftime('%s', 'now') * 1000,
  strftime('%s', 'now') * 1000
);

-- Insert enhanced field definitions for existing collections
INSERT OR IGNORE INTO content_fields (
  id, collection_id, field_name, field_type, field_label, field_options, field_order, is_required, is_searchable, created_at, updated_at
) VALUES 
-- Blog Posts fields
('blog-title-field', 'blog-posts-collection', 'title', 'text', 'Title', '{"maxLength": 200, "placeholder": "Enter blog post title"}', 1, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-content-field', 'blog-posts-collection', 'content', 'richtext', 'Content', '{"toolbar": "full", "height": 400}', 2, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-excerpt-field', 'blog-posts-collection', 'excerpt', 'text', 'Excerpt', '{"maxLength": 500, "rows": 3, "placeholder": "Brief description of the post"}', 3, 0, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-tags-field', 'blog-posts-collection', 'tags', 'select', 'Tags', '{"multiple": true, "options": ["technology", "business", "tutorial", "news", "update"], "allowCustom": true}', 4, 0, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-featured-image-field', 'blog-posts-collection', 'featured_image', 'media', 'Featured Image', '{"accept": "image/*", "maxSize": "5MB"}', 5, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-publish-date-field', 'blog-posts-collection', 'publish_date', 'date', 'Publish Date', '{"format": "YYYY-MM-DD", "defaultToday": true}', 6, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('blog-featured-field', 'blog-posts-collection', 'is_featured', 'boolean', 'Featured Post', '{"default": false}', 7, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),

-- Pages fields
('pages-title-field', 'pages-collection', 'title', 'text', 'Title', '{"maxLength": 200, "placeholder": "Enter page title"}', 1, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('pages-content-field', 'pages-collection', 'content', 'richtext', 'Content', '{"toolbar": "full", "height": 500}', 2, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('pages-slug-field', 'pages-collection', 'slug', 'text', 'URL Slug', '{"pattern": "^[a-z0-9-]+$", "placeholder": "url-friendly-slug"}', 3, 1, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('pages-meta-desc-field', 'pages-collection', 'meta_description', 'text', 'Meta Description', '{"maxLength": 160, "rows": 2, "placeholder": "SEO description for search engines"}', 4, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('pages-template-field', 'pages-collection', 'template', 'select', 'Page Template', '{"options": ["default", "landing", "contact", "about"], "default": "default"}', 5, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),

-- News fields
('news-title-field', 'news-collection', 'title', 'text', 'Title', '{"maxLength": 200, "placeholder": "Enter news title"}', 1, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('news-content-field', 'news-collection', 'content', 'richtext', 'Content', '{"toolbar": "news", "height": 400}', 2, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('news-category-field', 'news-collection', 'category', 'select', 'Category', '{"options": ["technology", "business", "politics", "sports", "entertainment", "health"], "required": true}', 3, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('news-author-field', 'news-collection', 'author', 'text', 'Author', '{"placeholder": "Author name"}', 4, 1, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('news-source-field', 'news-collection', 'source', 'text', 'Source', '{"placeholder": "News source"}', 5, 0, 1, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000),
('news-priority-field', 'news-collection', 'priority', 'select', 'Priority', '{"options": ["low", "normal", "high", "breaking"], "default": "normal"}', 6, 0, 0, strftime('%s', 'now') * 1000, strftime('%s', 'now') * 1000);`
  },
  {
    id: "004",
    name: "Stage6 User Management",
    filename: "004_stage6_user_management.sql",
    description: "Migration 004: Stage6 User Management",
    sql: "-- Stage 6: User Management & Permissions enhancements\n-- Enhanced user system with profiles, teams, permissions, and activity logging\n\n-- Add user profile and preferences columns\nALTER TABLE users ADD COLUMN phone TEXT;\nALTER TABLE users ADD COLUMN bio TEXT;\nALTER TABLE users ADD COLUMN avatar_url TEXT;\nALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC';\nALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en';\nALTER TABLE users ADD COLUMN email_notifications INTEGER DEFAULT 1;\nALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'dark';\nALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;\nALTER TABLE users ADD COLUMN two_factor_secret TEXT;\nALTER TABLE users ADD COLUMN password_reset_token TEXT;\nALTER TABLE users ADD COLUMN password_reset_expires INTEGER;\nALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;\nALTER TABLE users ADD COLUMN email_verification_token TEXT;\nALTER TABLE users ADD COLUMN invitation_token TEXT;\nALTER TABLE users ADD COLUMN invited_by TEXT REFERENCES users(id);\nALTER TABLE users ADD COLUMN invited_at INTEGER;\nALTER TABLE users ADD COLUMN accepted_invitation_at INTEGER;\n\n-- Create teams table for team-based collaboration\nCREATE TABLE IF NOT EXISTS teams (\n  id TEXT PRIMARY KEY,\n  name TEXT NOT NULL,\n  description TEXT,\n  slug TEXT NOT NULL UNIQUE,\n  owner_id TEXT NOT NULL REFERENCES users(id),\n  settings TEXT, -- JSON for team settings\n  is_active INTEGER NOT NULL DEFAULT 1,\n  created_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL\n);\n\n-- Create team memberships table\nCREATE TABLE IF NOT EXISTS team_memberships (\n  id TEXT PRIMARY KEY,\n  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  role TEXT NOT NULL DEFAULT 'member', -- owner, admin, editor, member, viewer\n  permissions TEXT, -- JSON for specific permissions\n  joined_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL,\n  UNIQUE(team_id, user_id)\n);\n\n-- Create permissions table for granular access control\nCREATE TABLE IF NOT EXISTS permissions (\n  id TEXT PRIMARY KEY,\n  name TEXT NOT NULL UNIQUE,\n  description TEXT,\n  category TEXT NOT NULL, -- content, users, collections, media, settings\n  created_at INTEGER NOT NULL\n);\n\n-- Create role permissions mapping\nCREATE TABLE IF NOT EXISTS role_permissions (\n  id TEXT PRIMARY KEY,\n  role TEXT NOT NULL,\n  permission_id TEXT NOT NULL REFERENCES permissions(id),\n  created_at INTEGER NOT NULL,\n  UNIQUE(role, permission_id)\n);\n\n-- Create user sessions table for better session management\nCREATE TABLE IF NOT EXISTS user_sessions (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  token_hash TEXT NOT NULL,\n  ip_address TEXT,\n  user_agent TEXT,\n  is_active INTEGER NOT NULL DEFAULT 1,\n  expires_at INTEGER NOT NULL,\n  created_at INTEGER NOT NULL,\n  last_used_at INTEGER\n);\n\n-- Create activity log table for audit trails\nCREATE TABLE IF NOT EXISTS activity_logs (\n  id TEXT PRIMARY KEY,\n  user_id TEXT REFERENCES users(id),\n  action TEXT NOT NULL,\n  resource_type TEXT, -- users, content, collections, media, etc.\n  resource_id TEXT,\n  details TEXT, -- JSON with additional details\n  ip_address TEXT,\n  user_agent TEXT,\n  created_at INTEGER NOT NULL\n);\n\n-- Create password history table for security\nCREATE TABLE IF NOT EXISTS password_history (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n  password_hash TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\n\n-- Insert default permissions\nINSERT OR IGNORE INTO permissions (id, name, description, category, created_at) VALUES\n  ('perm_content_create', 'content.create', 'Create new content', 'content', strftime('%s', 'now') * 1000),\n  ('perm_content_read', 'content.read', 'View content', 'content', strftime('%s', 'now') * 1000),\n  ('perm_content_update', 'content.update', 'Edit existing content', 'content', strftime('%s', 'now') * 1000),\n  ('perm_content_delete', 'content.delete', 'Delete content', 'content', strftime('%s', 'now') * 1000),\n  ('perm_content_publish', 'content.publish', 'Publish/unpublish content', 'content', strftime('%s', 'now') * 1000),\n  \n  ('perm_collections_create', 'collections.create', 'Create new collections', 'collections', strftime('%s', 'now') * 1000),\n  ('perm_collections_read', 'collections.read', 'View collections', 'collections', strftime('%s', 'now') * 1000),\n  ('perm_collections_update', 'collections.update', 'Edit collections', 'collections', strftime('%s', 'now') * 1000),\n  ('perm_collections_delete', 'collections.delete', 'Delete collections', 'collections', strftime('%s', 'now') * 1000),\n  ('perm_collections_fields', 'collections.fields', 'Manage collection fields', 'collections', strftime('%s', 'now') * 1000),\n  \n  ('perm_media_upload', 'media.upload', 'Upload media files', 'media', strftime('%s', 'now') * 1000),\n  ('perm_media_read', 'media.read', 'View media files', 'media', strftime('%s', 'now') * 1000),\n  ('perm_media_update', 'media.update', 'Edit media metadata', 'media', strftime('%s', 'now') * 1000),\n  ('perm_media_delete', 'media.delete', 'Delete media files', 'media', strftime('%s', 'now') * 1000),\n  \n  ('perm_users_create', 'users.create', 'Invite new users', 'users', strftime('%s', 'now') * 1000),\n  ('perm_users_read', 'users.read', 'View user profiles', 'users', strftime('%s', 'now') * 1000),\n  ('perm_users_update', 'users.update', 'Edit user profiles', 'users', strftime('%s', 'now') * 1000),\n  ('perm_users_delete', 'users.delete', 'Deactivate users', 'users', strftime('%s', 'now') * 1000),\n  ('perm_users_roles', 'users.roles', 'Manage user roles', 'users', strftime('%s', 'now') * 1000),\n  \n  ('perm_settings_read', 'settings.read', 'View system settings', 'settings', strftime('%s', 'now') * 1000),\n  ('perm_settings_update', 'settings.update', 'Modify system settings', 'settings', strftime('%s', 'now') * 1000),\n  ('perm_activity_read', 'activity.read', 'View activity logs', 'settings', strftime('%s', 'now') * 1000);\n\n-- Assign permissions to default roles\nINSERT OR IGNORE INTO role_permissions (id, role, permission_id, created_at) VALUES\n  -- Admin has all permissions\n  ('rp_admin_content_create', 'admin', 'perm_content_create', strftime('%s', 'now') * 1000),\n  ('rp_admin_content_read', 'admin', 'perm_content_read', strftime('%s', 'now') * 1000),\n  ('rp_admin_content_update', 'admin', 'perm_content_update', strftime('%s', 'now') * 1000),\n  ('rp_admin_content_delete', 'admin', 'perm_content_delete', strftime('%s', 'now') * 1000),\n  ('rp_admin_content_publish', 'admin', 'perm_content_publish', strftime('%s', 'now') * 1000),\n  ('rp_admin_collections_create', 'admin', 'perm_collections_create', strftime('%s', 'now') * 1000),\n  ('rp_admin_collections_read', 'admin', 'perm_collections_read', strftime('%s', 'now') * 1000),\n  ('rp_admin_collections_update', 'admin', 'perm_collections_update', strftime('%s', 'now') * 1000),\n  ('rp_admin_collections_delete', 'admin', 'perm_collections_delete', strftime('%s', 'now') * 1000),\n  ('rp_admin_collections_fields', 'admin', 'perm_collections_fields', strftime('%s', 'now') * 1000),\n  ('rp_admin_media_upload', 'admin', 'perm_media_upload', strftime('%s', 'now') * 1000),\n  ('rp_admin_media_read', 'admin', 'perm_media_read', strftime('%s', 'now') * 1000),\n  ('rp_admin_media_update', 'admin', 'perm_media_update', strftime('%s', 'now') * 1000),\n  ('rp_admin_media_delete', 'admin', 'perm_media_delete', strftime('%s', 'now') * 1000),\n  ('rp_admin_users_create', 'admin', 'perm_users_create', strftime('%s', 'now') * 1000),\n  ('rp_admin_users_read', 'admin', 'perm_users_read', strftime('%s', 'now') * 1000),\n  ('rp_admin_users_update', 'admin', 'perm_users_update', strftime('%s', 'now') * 1000),\n  ('rp_admin_users_delete', 'admin', 'perm_users_delete', strftime('%s', 'now') * 1000),\n  ('rp_admin_users_roles', 'admin', 'perm_users_roles', strftime('%s', 'now') * 1000),\n  ('rp_admin_settings_read', 'admin', 'perm_settings_read', strftime('%s', 'now') * 1000),\n  ('rp_admin_settings_update', 'admin', 'perm_settings_update', strftime('%s', 'now') * 1000),\n  ('rp_admin_activity_read', 'admin', 'perm_activity_read', strftime('%s', 'now') * 1000),\n  \n  -- Editor permissions\n  ('rp_editor_content_create', 'editor', 'perm_content_create', strftime('%s', 'now') * 1000),\n  ('rp_editor_content_read', 'editor', 'perm_content_read', strftime('%s', 'now') * 1000),\n  ('rp_editor_content_update', 'editor', 'perm_content_update', strftime('%s', 'now') * 1000),\n  ('rp_editor_content_publish', 'editor', 'perm_content_publish', strftime('%s', 'now') * 1000),\n  ('rp_editor_collections_read', 'editor', 'perm_collections_read', strftime('%s', 'now') * 1000),\n  ('rp_editor_media_upload', 'editor', 'perm_media_upload', strftime('%s', 'now') * 1000),\n  ('rp_editor_media_read', 'editor', 'perm_media_read', strftime('%s', 'now') * 1000),\n  ('rp_editor_media_update', 'editor', 'perm_media_update', strftime('%s', 'now') * 1000),\n  ('rp_editor_users_read', 'editor', 'perm_users_read', strftime('%s', 'now') * 1000),\n  \n  -- Viewer permissions\n  ('rp_viewer_content_read', 'viewer', 'perm_content_read', strftime('%s', 'now') * 1000),\n  ('rp_viewer_collections_read', 'viewer', 'perm_collections_read', strftime('%s', 'now') * 1000),\n  ('rp_viewer_media_read', 'viewer', 'perm_media_read', strftime('%s', 'now') * 1000),\n  ('rp_viewer_users_read', 'viewer', 'perm_users_read', strftime('%s', 'now') * 1000);\n\n-- Create indexes for performance\nCREATE INDEX IF NOT EXISTS idx_team_memberships_team_id ON team_memberships(team_id);\nCREATE INDEX IF NOT EXISTS idx_team_memberships_user_id ON team_memberships(user_id);\nCREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);\nCREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions(token_hash);\nCREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);\nCREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at);\nCREATE INDEX IF NOT EXISTS idx_activity_logs_resource ON activity_logs(resource_type, resource_id);\nCREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);\nCREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token);\nCREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token);\nCREATE INDEX IF NOT EXISTS idx_users_invitation_token ON users(invitation_token);"
  },
  {
    id: "005",
    name: "Stage7 Workflow Automation",
    filename: "005_stage7_workflow_automation.sql",
    description: "Migration 005: Stage7 Workflow Automation",
    sql: "-- Stage 7: Workflow & Automation Migration\n-- This migration adds workflow and automation capabilities to SonicJS\n\n-- Workflow States Table\nCREATE TABLE IF NOT EXISTS workflow_states (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  name TEXT NOT NULL,\n  description TEXT,\n  color TEXT DEFAULT '#6B7280',\n  is_initial INTEGER DEFAULT 0,\n  is_final INTEGER DEFAULT 0,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n);\n\n-- Insert default workflow states\nINSERT OR IGNORE INTO workflow_states (id, name, description, color, is_initial, is_final) VALUES\n('draft', 'Draft', 'Content is being worked on', '#F59E0B', 1, 0),\n('pending-review', 'Pending Review', 'Content is waiting for review', '#3B82F6', 0, 0),\n('approved', 'Approved', 'Content has been approved', '#10B981', 0, 0),\n('published', 'Published', 'Content is live', '#059669', 0, 1),\n('rejected', 'Rejected', 'Content was rejected', '#EF4444', 0, 1),\n('archived', 'Archived', 'Content has been archived', '#6B7280', 0, 1);\n\n-- Workflows Table\nCREATE TABLE IF NOT EXISTS workflows (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  name TEXT NOT NULL,\n  description TEXT,\n  collection_id TEXT,\n  is_active INTEGER DEFAULT 1,\n  auto_publish INTEGER DEFAULT 0,\n  require_approval INTEGER DEFAULT 1,\n  approval_levels INTEGER DEFAULT 1,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE\n);\n\n-- Workflow Transitions Table\nCREATE TABLE IF NOT EXISTS workflow_transitions (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  workflow_id TEXT NOT NULL,\n  from_state_id TEXT NOT NULL,\n  to_state_id TEXT NOT NULL,\n  required_permission TEXT,\n  auto_transition INTEGER DEFAULT 0,\n  transition_conditions TEXT, -- JSON\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE,\n  FOREIGN KEY (from_state_id) REFERENCES workflow_states(id),\n  FOREIGN KEY (to_state_id) REFERENCES workflow_states(id)\n);\n\n-- Content Workflow Status Table\nCREATE TABLE IF NOT EXISTS content_workflow_status (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  content_id TEXT NOT NULL,\n  workflow_id TEXT NOT NULL,\n  current_state_id TEXT NOT NULL,\n  assigned_to TEXT,\n  due_date DATETIME,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (content_id) REFERENCES content(id) ON DELETE CASCADE,\n  FOREIGN KEY (workflow_id) REFERENCES workflows(id),\n  FOREIGN KEY (current_state_id) REFERENCES workflow_states(id),\n  FOREIGN KEY (assigned_to) REFERENCES users(id),\n  UNIQUE(content_id, workflow_id)\n);\n\n-- Workflow History Table\nCREATE TABLE IF NOT EXISTS workflow_history (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  content_id TEXT NOT NULL,\n  workflow_id TEXT NOT NULL,\n  from_state_id TEXT,\n  to_state_id TEXT NOT NULL,\n  user_id TEXT NOT NULL,\n  comment TEXT,\n  metadata TEXT, -- JSON\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (content_id) REFERENCES content(id) ON DELETE CASCADE,\n  FOREIGN KEY (workflow_id) REFERENCES workflows(id),\n  FOREIGN KEY (from_state_id) REFERENCES workflow_states(id),\n  FOREIGN KEY (to_state_id) REFERENCES workflow_states(id),\n  FOREIGN KEY (user_id) REFERENCES users(id)\n);\n\n-- Scheduled Content Table\nCREATE TABLE IF NOT EXISTS scheduled_content (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  content_id TEXT NOT NULL,\n  action TEXT NOT NULL, -- 'publish', 'unpublish', 'archive'\n  scheduled_at DATETIME NOT NULL,\n  timezone TEXT DEFAULT 'UTC',\n  user_id TEXT NOT NULL,\n  status TEXT DEFAULT 'pending', -- 'pending', 'completed', 'failed', 'cancelled'\n  executed_at DATETIME,\n  error_message TEXT,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (content_id) REFERENCES content(id) ON DELETE CASCADE,\n  FOREIGN KEY (user_id) REFERENCES users(id)\n);\n\n-- Notifications Table\nCREATE TABLE IF NOT EXISTS notifications (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  user_id TEXT NOT NULL,\n  type TEXT NOT NULL, -- 'workflow', 'schedule', 'system'\n  title TEXT NOT NULL,\n  message TEXT NOT NULL,\n  data TEXT, -- JSON\n  is_read INTEGER DEFAULT 0,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n);\n\n-- Notification Preferences Table\nCREATE TABLE IF NOT EXISTS notification_preferences (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  user_id TEXT NOT NULL,\n  notification_type TEXT NOT NULL,\n  email_enabled INTEGER DEFAULT 1,\n  in_app_enabled INTEGER DEFAULT 1,\n  digest_frequency TEXT DEFAULT 'daily', -- 'immediate', 'hourly', 'daily', 'weekly'\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,\n  UNIQUE(user_id, notification_type)\n);\n\n-- Webhooks Table\nCREATE TABLE IF NOT EXISTS webhooks (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  name TEXT NOT NULL,\n  url TEXT NOT NULL,\n  secret TEXT,\n  events TEXT NOT NULL, -- JSON array of event types\n  is_active INTEGER DEFAULT 1,\n  retry_count INTEGER DEFAULT 3,\n  timeout_seconds INTEGER DEFAULT 30,\n  last_success_at DATETIME,\n  last_failure_at DATETIME,\n  failure_count INTEGER DEFAULT 0,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP\n);\n\n-- Webhook Deliveries Table\nCREATE TABLE IF NOT EXISTS webhook_deliveries (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  webhook_id TEXT NOT NULL,\n  event_type TEXT NOT NULL,\n  payload TEXT NOT NULL, -- JSON\n  response_status INTEGER,\n  response_body TEXT,\n  attempt_count INTEGER DEFAULT 1,\n  delivered_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE\n);\n\n-- Content Versions Table (for rollback functionality)\nCREATE TABLE IF NOT EXISTS content_versions (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  content_id TEXT NOT NULL,\n  version_number INTEGER NOT NULL,\n  title TEXT NOT NULL,\n  content TEXT NOT NULL,\n  fields TEXT, -- JSON\n  user_id TEXT NOT NULL,\n  change_summary TEXT,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (content_id) REFERENCES content(id) ON DELETE CASCADE,\n  FOREIGN KEY (user_id) REFERENCES users(id),\n  UNIQUE(content_id, version_number)\n);\n\n-- Automation Rules Table\nCREATE TABLE IF NOT EXISTS automation_rules (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  name TEXT NOT NULL,\n  description TEXT,\n  trigger_type TEXT NOT NULL, -- 'content_created', 'content_updated', 'workflow_transition', 'schedule'\n  trigger_conditions TEXT, -- JSON\n  action_type TEXT NOT NULL, -- 'workflow_transition', 'send_notification', 'webhook_call', 'auto_save'\n  action_config TEXT, -- JSON\n  is_active INTEGER DEFAULT 1,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP\n);\n\n-- Auto-save Drafts Table\nCREATE TABLE IF NOT EXISTS auto_save_drafts (\n  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),\n  content_id TEXT,\n  user_id TEXT NOT NULL,\n  title TEXT,\n  content TEXT,\n  fields TEXT, -- JSON\n  last_saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n  FOREIGN KEY (content_id) REFERENCES content(id) ON DELETE CASCADE,\n  FOREIGN KEY (user_id) REFERENCES users(id),\n  UNIQUE(content_id, user_id)\n);\n\n-- Add workflow-related columns to existing content table (skip existing columns)\nALTER TABLE content ADD COLUMN workflow_state_id TEXT DEFAULT 'draft';\nALTER TABLE content ADD COLUMN embargo_until DATETIME;\nALTER TABLE content ADD COLUMN expires_at DATETIME;\nALTER TABLE content ADD COLUMN version_number INTEGER DEFAULT 1;\nALTER TABLE content ADD COLUMN is_auto_saved INTEGER DEFAULT 0;\n\n-- Create indexes for performance\nCREATE INDEX IF NOT EXISTS idx_content_workflow_status_content_id ON content_workflow_status(content_id);\nCREATE INDEX IF NOT EXISTS idx_content_workflow_status_workflow_id ON content_workflow_status(workflow_id);\nCREATE INDEX IF NOT EXISTS idx_workflow_history_content_id ON workflow_history(content_id);\nCREATE INDEX IF NOT EXISTS idx_scheduled_content_scheduled_at ON scheduled_content(scheduled_at);\nCREATE INDEX IF NOT EXISTS idx_scheduled_content_status ON scheduled_content(status);\nCREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);\nCREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);\nCREATE INDEX IF NOT EXISTS idx_content_versions_content_id ON content_versions(content_id);\nCREATE INDEX IF NOT EXISTS idx_auto_save_drafts_user_id ON auto_save_drafts(user_id);\nCREATE INDEX IF NOT EXISTS idx_content_workflow_state ON content(workflow_state_id);\nCREATE INDEX IF NOT EXISTS idx_content_scheduled_publish ON content(scheduled_publish_at);\n\n-- Insert default workflow for collections\nINSERT OR IGNORE INTO workflows (id, name, description, collection_id, is_active, require_approval, approval_levels) \nSELECT \n  'default-' || id,\n  'Default Workflow for ' || name,\n  'Standard content approval workflow',\n  id,\n  1,\n  1,\n  1\nFROM collections;\n\n-- Insert default workflow transitions\nINSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) \nSELECT \n  w.id,\n  'draft',\n  'pending-review',\n  'content:submit'\nFROM workflows w;\n\nINSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) \nSELECT \n  w.id,\n  'pending-review',\n  'approved',\n  'content:approve'\nFROM workflows w;\n\nINSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) \nSELECT \n  w.id,\n  'approved',\n  'published',\n  'content:publish'\nFROM workflows w;\n\nINSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) \nSELECT \n  w.id,\n  'pending-review',\n  'rejected',\n  'content:approve'\nFROM workflows w;\n\n-- Insert default notification preferences for all users\nINSERT OR IGNORE INTO notification_preferences (user_id, notification_type, email_enabled, in_app_enabled)\nSELECT \n  id,\n  'workflow_assigned',\n  1,\n  1\nFROM users;\n\nINSERT OR IGNORE INTO notification_preferences (user_id, notification_type, email_enabled, in_app_enabled)\nSELECT \n  id,\n  'workflow_status_change',\n  1,\n  1\nFROM users;\n\nINSERT OR IGNORE INTO notification_preferences (user_id, notification_type, email_enabled, in_app_enabled)\nSELECT \n  id,\n  'content_scheduled',\n  1,\n  1\nFROM users;"
  },
  {
    id: "006",
    name: "Plugin System",
    filename: "006_plugin_system.sql",
    description: "Migration 006: Plugin System",
    sql: `-- Plugin System Tables
-- Migration: 006_plugin_system
-- Description: Add plugin management system tables

-- Plugins table
CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    version TEXT NOT NULL,
    author TEXT NOT NULL,
    category TEXT NOT NULL,
    icon TEXT,
    status TEXT DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'error')),
    is_core BOOLEAN DEFAULT FALSE,
    settings JSON,
    permissions JSON,
    dependencies JSON,
    download_count INTEGER DEFAULT 0,
    rating REAL DEFAULT 0,
    installed_at INTEGER NOT NULL,
    activated_at INTEGER,
    last_updated INTEGER NOT NULL,
    error_message TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
);

-- Plugin hooks table (registered hooks by plugins)
CREATE TABLE IF NOT EXISTS plugin_hooks (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    hook_name TEXT NOT NULL,
    handler_name TEXT NOT NULL,
    priority INTEGER DEFAULT 10,
    is_active BOOLEAN DEFAULT TRUE,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    UNIQUE(plugin_id, hook_name, handler_name)
);

-- Plugin routes table
CREATE TABLE IF NOT EXISTS plugin_routes (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    handler_name TEXT NOT NULL,
    middleware JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    UNIQUE(plugin_id, path, method)
);

-- Plugin assets table (CSS, JS files provided by plugins)
CREATE TABLE IF NOT EXISTS plugin_assets (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('css', 'js', 'image', 'font')),
    asset_path TEXT NOT NULL,
    load_order INTEGER DEFAULT 100,
    load_location TEXT DEFAULT 'footer' CHECK (load_location IN ('header', 'footer')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

-- Plugin activity log
CREATE TABLE IF NOT EXISTS plugin_activity_log (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    action TEXT NOT NULL,
    user_id TEXT,
    details JSON,
    timestamp INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_plugins_status ON plugins(status);
CREATE INDEX IF NOT EXISTS idx_plugins_category ON plugins(category);
CREATE INDEX IF NOT EXISTS idx_plugin_hooks_plugin ON plugin_hooks(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_routes_plugin ON plugin_routes(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_assets_plugin ON plugin_assets(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_activity_plugin ON plugin_activity_log(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_activity_timestamp ON plugin_activity_log(timestamp);

-- Insert core plugins
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES 
(
    'core-auth',
    'core-auth',
    'Authentication System',
    'Core authentication and user management system',
    '1.0.0',
    'SonicJS Team',
    'security',
    '\u{1F510}',
    'active',
    TRUE,
    '["manage:users", "manage:roles", "manage:permissions"]',
    unixepoch(),
    unixepoch()
),
(
    'core-media',
    'core-media', 
    'Media Manager',
    'Core media upload and management system',
    '1.0.0',
    'SonicJS Team',
    'media',
    '\u{1F4F8}',
    'active',
    TRUE,
    '["manage:media", "upload:files"]',
    unixepoch(),
    unixepoch()
),
(
    'core-workflow',
    'core-workflow',
    'Workflow Engine',
    'Content workflow and approval system',
    '1.0.0',
    'SonicJS Team',
    'content',
    '\u{1F504}',
    'active',
    TRUE,
    '["manage:workflows", "approve:content"]',
    unixepoch(),
    unixepoch()
);

-- FAQ Plugin will be added as a third-party plugin through the admin interface

-- Add plugin management permission
INSERT OR IGNORE INTO permissions (id, name, description, category, created_at)
VALUES (
    'manage:plugins',
    'Manage Plugins',
    'Install, uninstall, activate, and configure plugins',
    'system',
    unixepoch()
);

-- Grant plugin management permission to admin role
INSERT OR IGNORE INTO role_permissions (id, role, permission_id, created_at)
VALUES ('role-perm-manage-plugins', 'admin', 'manage:plugins', unixepoch());`
  },
  {
    id: "007",
    name: "Demo Login Plugin",
    filename: "007_demo_login_plugin.sql",
    description: "Migration 007: Demo Login Plugin",
    sql: "-- Demo Login Plugin Migration\n-- Migration: 007_demo_login_plugin\n-- Description: Add demo login prefill plugin to the plugin registry\n\n-- Insert demo login plugin\nINSERT INTO plugins (\n    id, name, display_name, description, version, author, category, icon, \n    status, is_core, permissions, installed_at, last_updated\n) VALUES (\n    'demo-login-prefill',\n    'demo-login-plugin',\n    'Demo Login Prefill',\n    'Prefills login form with demo credentials (admin@sonicjs.com/sonicjs!) for easy site demonstration',\n    '1.0.0',\n    'SonicJS',\n    'demo',\n    '\u{1F3AF}',\n    'inactive',\n    TRUE,\n    '[]',\n    unixepoch(),\n    unixepoch()\n);"
  },
  {
    id: "008",
    name: "Fix Slug Validation",
    filename: "008_fix_slug_validation.sql",
    description: "Migration 008: Fix Slug Validation",
    sql: `-- Migration: Fix overly restrictive slug validation patterns
-- This migration relaxes the slug field validation to be more user-friendly

-- Update the pages collection slug field to allow underscores and be less restrictive
UPDATE content_fields 
SET field_options = '{"pattern": "^[a-zA-Z0-9_-]+$", "placeholder": "url-friendly-slug", "help": "Use letters, numbers, underscores, and hyphens only"}'
WHERE field_name = 'slug' AND collection_id = 'pages-collection';

-- Update blog posts slug field if it exists
UPDATE content_fields 
SET field_options = '{"pattern": "^[a-zA-Z0-9_-]+$", "placeholder": "url-friendly-slug", "help": "Use letters, numbers, underscores, and hyphens only"}'
WHERE field_name = 'slug' AND collection_id = 'blog-posts-collection';

-- Update news slug field if it exists
UPDATE content_fields 
SET field_options = '{"pattern": "^[a-zA-Z0-9_-]+$", "placeholder": "url-friendly-slug", "help": "Use letters, numbers, underscores, and hyphens only"}'
WHERE field_name = 'slug' AND collection_id = 'news-collection';

-- Update any other slug fields with the restrictive pattern
UPDATE content_fields 
SET field_options = REPLACE(field_options, '"pattern": "^[a-z0-9-]+$"', '"pattern": "^[a-zA-Z0-9_-]+$"')
WHERE field_options LIKE '%"pattern": "^[a-z0-9-]+$"%';`
  },
  {
    id: "009",
    name: "System Logging",
    filename: "009_system_logging.sql",
    description: "Migration 009: System Logging",
    sql: "-- System Logging Tables\n-- Migration: 009_system_logging\n-- Description: Add system logging and configuration tables\n\n-- System logs table for tracking application events\nCREATE TABLE IF NOT EXISTS system_logs (\n    id TEXT PRIMARY KEY,\n    level TEXT NOT NULL CHECK (level IN ('debug', 'info', 'warn', 'error', 'fatal')),\n    category TEXT NOT NULL CHECK (category IN ('auth', 'api', 'workflow', 'plugin', 'media', 'system', 'security', 'error')),\n    message TEXT NOT NULL,\n    data TEXT,  -- JSON data\n    user_id TEXT,\n    session_id TEXT,\n    request_id TEXT,\n    ip_address TEXT,\n    user_agent TEXT,\n    method TEXT,\n    url TEXT,\n    status_code INTEGER,\n    duration INTEGER,  -- milliseconds\n    stack_trace TEXT,\n    tags TEXT,  -- JSON array\n    source TEXT,  -- source of the log entry\n    created_at INTEGER NOT NULL DEFAULT (unixepoch()),\n    FOREIGN KEY (user_id) REFERENCES users(id)\n);\n\n-- Log configuration table for managing log settings per category\nCREATE TABLE IF NOT EXISTS log_config (\n    id TEXT PRIMARY KEY,\n    category TEXT NOT NULL UNIQUE CHECK (category IN ('auth', 'api', 'workflow', 'plugin', 'media', 'system', 'security', 'error')),\n    enabled BOOLEAN NOT NULL DEFAULT TRUE,\n    level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('debug', 'info', 'warn', 'error', 'fatal')),\n    retention_days INTEGER NOT NULL DEFAULT 30,\n    max_size_mb INTEGER NOT NULL DEFAULT 100,\n    created_at INTEGER NOT NULL DEFAULT (unixepoch()),\n    updated_at INTEGER NOT NULL DEFAULT (unixepoch())\n);\n\n-- Create indexes for better performance\nCREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);\nCREATE INDEX IF NOT EXISTS idx_system_logs_category ON system_logs(category);\nCREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);\nCREATE INDEX IF NOT EXISTS idx_system_logs_user_id ON system_logs(user_id);\nCREATE INDEX IF NOT EXISTS idx_system_logs_status_code ON system_logs(status_code);\nCREATE INDEX IF NOT EXISTS idx_system_logs_source ON system_logs(source);\n\n-- Insert default log configurations\nINSERT OR IGNORE INTO log_config (id, category, enabled, level, retention_days, max_size_mb) VALUES\n('log-config-auth', 'auth', TRUE, 'info', 90, 50),\n('log-config-api', 'api', TRUE, 'info', 30, 100),\n('log-config-workflow', 'workflow', TRUE, 'info', 60, 50),\n('log-config-plugin', 'plugin', TRUE, 'warn', 30, 25),\n('log-config-media', 'media', TRUE, 'info', 30, 50),\n('log-config-system', 'system', TRUE, 'info', 90, 100),\n('log-config-security', 'security', TRUE, 'warn', 180, 100),\n('log-config-error', 'error', TRUE, 'error', 90, 200);"
  },
  {
    id: "011",
    name: "Config Managed Collections",
    filename: "011_config_managed_collections.sql",
    description: "Migration 011: Config Managed Collections",
    sql: "-- Migration: Add Config-Managed Collections Support\n-- Description: Add 'managed' column to collections table to support config-based collection definitions\n-- Created: 2025-10-03\n\n-- Add 'managed' column to collections table\n-- This column indicates whether a collection is managed by configuration files (true) or user-created (false)\n-- Managed collections cannot be edited through the admin UI\n-- Use a safe approach to add the column only if it doesn't exist\nALTER TABLE collections ADD COLUMN managed INTEGER DEFAULT 0 NOT NULL;\n\n-- Create an index on the managed column for faster queries\nCREATE INDEX IF NOT EXISTS idx_collections_managed ON collections(managed);\n\n-- Create an index on managed + is_active for efficient filtering\nCREATE INDEX IF NOT EXISTS idx_collections_managed_active ON collections(managed, is_active);\n"
  },
  {
    id: "012",
    name: "Testimonials Plugin",
    filename: "012_testimonials_plugin.sql",
    description: "Migration 012: Testimonials Plugin",
    sql: `-- Testimonials Plugin Migration
-- Creates testimonials table for the testimonials plugin
-- This demonstrates a code-based collection defined in src/plugins/core-plugins/testimonials-plugin.ts

CREATE TABLE IF NOT EXISTS testimonials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_name TEXT NOT NULL,
  author_title TEXT,
  author_company TEXT,
  testimonial_text TEXT NOT NULL,
  rating INTEGER CHECK(rating >= 1 AND rating <= 5),
  isPublished INTEGER NOT NULL DEFAULT 1,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_testimonials_published ON testimonials(isPublished);
CREATE INDEX IF NOT EXISTS idx_testimonials_sort_order ON testimonials(sortOrder);
CREATE INDEX IF NOT EXISTS idx_testimonials_rating ON testimonials(rating);

-- Create trigger to update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS testimonials_updated_at
  AFTER UPDATE ON testimonials
BEGIN
  UPDATE testimonials SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- Insert plugin record
INSERT OR IGNORE INTO plugins (name, display_name, description, version, status, category, settings) VALUES
('testimonials',
 'Customer Testimonials',
 'Manage customer testimonials and reviews with rating support. This is a code-based collection example.',
 '1.0.0',
 'active',
 'content',
 '{"defaultPublished": true, "requireRating": false}');

-- Insert sample testimonial data
INSERT OR IGNORE INTO testimonials (author_name, author_title, author_company, testimonial_text, rating, isPublished, sortOrder) VALUES
('Jane Smith',
 'CTO',
 'TechStartup Inc',
 'SonicJS AI has transformed how we manage our content. The plugin architecture is brilliant and the edge deployment is blazing fast.',
 5,
 1,
 1),

('Michael Chen',
 'Lead Developer',
 'Digital Agency Co',
 'We migrated from WordPress to SonicJS AI and couldn''t be happier. The TypeScript-first approach and modern tooling make development a joy.',
 5,
 1,
 2),

('Sarah Johnson',
 'Product Manager',
 'E-commerce Solutions',
 'The headless CMS approach combined with Cloudflare Workers gives us unmatched performance. Our content is served globally with minimal latency.',
 4,
 1,
 3),

('David Rodriguez',
 'Full Stack Developer',
 'Creative Studio',
 'Great CMS for modern web applications. The admin interface is clean and the API is well-designed. Plugin system is very flexible.',
 5,
 1,
 4),

('Emily Watson',
 'Technical Director',
 'Media Company',
 'SonicJS AI solved our content distribution challenges. The R2 integration for media storage works flawlessly and scales effortlessly.',
 4,
 1,
 5);
`
  },
  {
    id: "013",
    name: "Code Examples Plugin",
    filename: "013_code_examples_plugin.sql",
    description: "Migration 013: Code Examples Plugin",
    sql: `-- Code Examples Plugin Migration
-- Creates code_examples table for the code examples plugin
-- This demonstrates a code-based collection for storing and managing code snippets

CREATE TABLE IF NOT EXISTS code_examples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  code TEXT NOT NULL,
  language TEXT NOT NULL,
  category TEXT,
  tags TEXT,
  isPublished INTEGER NOT NULL DEFAULT 1,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_code_examples_published ON code_examples(isPublished);
CREATE INDEX IF NOT EXISTS idx_code_examples_sort_order ON code_examples(sortOrder);
CREATE INDEX IF NOT EXISTS idx_code_examples_language ON code_examples(language);
CREATE INDEX IF NOT EXISTS idx_code_examples_category ON code_examples(category);

-- Create trigger to update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS code_examples_updated_at
  AFTER UPDATE ON code_examples
BEGIN
  UPDATE code_examples SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- Insert plugin record
INSERT OR IGNORE INTO plugins (name, display_name, description, version, status, category, settings) VALUES
('code-examples',
 'Code Examples',
 'Manage code snippets and examples with syntax highlighting support. Perfect for documentation and tutorials.',
 '1.0.0',
 'active',
 'content',
 '{"defaultPublished": true, "supportedLanguages": ["javascript", "typescript", "python", "go", "rust", "java", "php", "ruby", "sql"]}');

-- Insert sample code examples
INSERT OR IGNORE INTO code_examples (title, description, code, language, category, tags, isPublished, sortOrder) VALUES
('React useState Hook',
 'Basic example of using the useState hook in React for managing component state.',
 'import { useState } from ''react'';

function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(count + 1)}>
        Increment
      </button>
    </div>
  );
}

export default Counter;',
 'javascript',
 'frontend',
 'react,hooks,state',
 1,
 1),

('TypeScript Interface Example',
 'Defining a TypeScript interface for type-safe objects.',
 'interface User {
  id: string;
  email: string;
  name: string;
  role: ''admin'' | ''editor'' | ''viewer'';
  createdAt: Date;
}

function greetUser(user: User): string {
  return \`Hello, \${user.name}!\`;
}

const user: User = {
  id: ''123'',
  email: ''user@example.com'',
  name: ''John Doe'',
  role: ''admin'',
  createdAt: new Date()
};

console.log(greetUser(user));',
 'typescript',
 'backend',
 'typescript,types,interface',
 1,
 2),

('Python List Comprehension',
 'Elegant way to create lists in Python using list comprehensions.',
 '# Basic list comprehension
squares = [x**2 for x in range(10)]
print(squares)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# With condition
even_squares = [x**2 for x in range(10) if x % 2 == 0]
print(even_squares)  # [0, 4, 16, 36, 64]

# Nested list comprehension
matrix = [[i+j for j in range(3)] for i in range(3)]
print(matrix)  # [[0, 1, 2], [1, 2, 3], [2, 3, 4]]',
 'python',
 'general',
 'python,lists,comprehension',
 1,
 3),

('SQL Join Example',
 'Common SQL JOIN patterns for combining data from multiple tables.',
 '-- INNER JOIN: Returns only matching rows
SELECT users.name, orders.total
FROM users
INNER JOIN orders ON users.id = orders.user_id;

-- LEFT JOIN: Returns all users, even without orders
SELECT users.name, orders.total
FROM users
LEFT JOIN orders ON users.id = orders.user_id;

-- Multiple JOINs
SELECT
  users.name,
  orders.order_date,
  products.name AS product_name
FROM users
INNER JOIN orders ON users.id = orders.user_id
INNER JOIN order_items ON orders.id = order_items.order_id
INNER JOIN products ON order_items.product_id = products.id;',
 'sql',
 'database',
 'sql,joins,queries',
 1,
 4),

('Go Error Handling',
 'Idiomatic error handling pattern in Go.',
 'package main

import (
	"errors"
	"fmt"
)

func divide(a, b float64) (float64, error) {
	if b == 0 {
		return 0, errors.New("division by zero")
	}
	return a / b, nil
}

func main() {
	result, err := divide(10, 2)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Result: %.2f\\n", result)

	// This will error
	_, err = divide(10, 0)
	if err != nil {
		fmt.Println("Error:", err)
	}
}',
 'go',
 'backend',
 'go,error-handling,functions',
 1,
 5);
`
  },
  {
    id: "014",
    name: "Fix Plugin Registry",
    filename: "014_fix_plugin_registry.sql",
    description: "Migration 014: Fix Plugin Registry",
    sql: `-- Fix Plugin Registry
-- Migration: 014_fix_plugin_registry
-- Description: Add missing plugins and fix plugin name mismatches

-- Note: Cannot easily update plugin names as they may be referenced elsewhere
-- Instead we'll add the missing plugins with correct names

-- Insert missing plugins

-- Core Analytics Plugin
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'core-analytics',
    'core-analytics',
    'Analytics & Tracking',
    'Core analytics tracking and reporting plugin with page views and event tracking',
    '1.0.0',
    'SonicJS Team',
    'seo',
    '\u{1F4CA}',
    'active',
    TRUE,
    '["view:analytics", "manage:tracking"]',
    unixepoch(),
    unixepoch()
);

-- FAQ Plugin
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'faq-plugin',
    'faq-plugin',
    'FAQ Management',
    'Frequently Asked Questions management plugin with categories, search, and custom styling',
    '1.0.0',
    'SonicJS',
    'content',
    '\u2753',
    'active',
    FALSE,
    '["manage:faqs"]',
    unixepoch(),
    unixepoch()
);

-- Seed Data Plugin
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'seed-data',
    'seed-data',
    'Seed Data Generator',
    'Generate realistic example users and content for testing and development',
    '1.0.0',
    'SonicJS Team',
    'development',
    '\u{1F331}',
    'inactive',
    FALSE,
    '["admin"]',
    unixepoch(),
    unixepoch()
);

-- Database Tools Plugin
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'database-tools',
    'database-tools',
    'Database Tools',
    'Database management tools including truncate, backup, and validation',
    '1.0.0',
    'SonicJS Team',
    'system',
    '\u{1F5C4}\uFE0F',
    'active',
    FALSE,
    '["manage:database", "admin"]',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "015",
    name: "Add Remaining Plugins",
    filename: "015_add_remaining_plugins.sql",
    description: "Migration 015: Add Remaining Plugins",
    sql: `-- Add Remaining Plugins
-- Migration: 015_add_remaining_plugins
-- Description: Add all remaining core plugins that were missing from the registry

-- Testimonials Plugin (with correct name)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'testimonials-plugin',
    'testimonials-plugin',
    'Customer Testimonials',
    'Manage customer testimonials and reviews with rating support',
    '1.0.0',
    'SonicJS',
    'content',
    '\u2B50',
    'active',
    FALSE,
    '["manage:testimonials"]',
    '[]',
    '{"defaultPublished": true, "requireRating": false}',
    unixepoch(),
    unixepoch()
);

-- Code Examples Plugin (with correct name)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'code-examples-plugin',
    'code-examples-plugin',
    'Code Examples',
    'Manage code snippets and examples with syntax highlighting support',
    '1.0.0',
    'SonicJS',
    'content',
    '\u{1F4BB}',
    'active',
    FALSE,
    '["manage:code-examples"]',
    '[]',
    '{"defaultPublished": true, "supportedLanguages": ["javascript", "typescript", "python", "go", "rust", "java", "php", "ruby", "sql"]}',
    unixepoch(),
    unixepoch()
);

-- Workflow Plugin (with correct name)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, installed_at, last_updated
) VALUES (
    'workflow-plugin',
    'workflow-plugin',
    'Workflow Engine',
    'Content workflow management with approval chains, scheduling, and automation',
    '1.0.0',
    'SonicJS Team',
    'content',
    '\u{1F504}',
    'active',
    TRUE,
    '["manage:workflows", "approve:content"]',
    '[]',
    unixepoch(),
    unixepoch()
);

-- Demo Login Plugin (already exists with correct name from migration 007, but let's ensure it's there)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, installed_at, last_updated
) VALUES (
    'demo-login-plugin',
    'demo-login-plugin',
    'Demo Login Prefill',
    'Prefills login form with demo credentials for easy site demonstration',
    '1.0.0',
    'SonicJS',
    'demo',
    '\u{1F3AF}',
    'active',
    FALSE,
    '[]',
    '[]',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "016",
    name: "Remove Duplicate Cache Plugin",
    filename: "016_remove_duplicate_cache_plugin.sql",
    description: "Migration 016: Remove Duplicate Cache Plugin",
    sql: "-- Migration: Remove duplicate cache plugin entry\n-- Description: Removes the old 'cache' plugin (id: 'cache') that is a duplicate of 'core-cache'\n-- This fixes the issue where Cache System appears twice in the plugins list\n-- Created: 2025-10-14\n\n-- Remove the old 'cache' plugin entry if it exists\n-- The correct plugin is 'core-cache' which is managed by plugin-bootstrap.ts\nDELETE FROM plugins WHERE id = 'cache' AND name = 'cache';\n\n-- Clean up any related entries in plugin activity log\nDELETE FROM plugin_activity_log WHERE plugin_id = 'cache';\n\n-- Clean up any related entries in plugin hooks\nDELETE FROM plugin_hooks WHERE plugin_id = 'cache';\n\n-- Clean up any related entries in plugin routes\nDELETE FROM plugin_routes WHERE plugin_id = 'cache';\n"
  },
  {
    id: "017",
    name: "Auth Configurable Fields",
    filename: "017_auth_configurable_fields.sql",
    description: "Migration 017: Auth Configurable Fields",
    sql: `-- Migration: Make authentication fields configurable
-- This migration updates the core-auth plugin to support configurable required fields

-- The settings will be stored in the plugins table as JSON
-- Default settings for core-auth plugin include:
-- {
--   "requiredFields": {
--     "email": { "required": true, "minLength": 5 },
--     "password": { "required": true, "minLength": 8 },
--     "username": { "required": true, "minLength": 3 },
--     "firstName": { "required": true, "minLength": 1 },
--     "lastName": { "required": true, "minLength": 1 }
--   },
--   "validation": {
--     "emailFormat": true,
--     "allowDuplicateUsernames": false
--   }
-- }

-- Update core-auth plugin settings with configurable field requirements
UPDATE plugins
SET settings = json_object(
  'requiredFields', json_object(
    'email', json_object('required', 1, 'minLength', 5, 'label', 'Email', 'type', 'email'),
    'password', json_object('required', 1, 'minLength', 8, 'label', 'Password', 'type', 'password'),
    'username', json_object('required', 1, 'minLength', 3, 'label', 'Username', 'type', 'text'),
    'firstName', json_object('required', 1, 'minLength', 1, 'label', 'First Name', 'type', 'text'),
    'lastName', json_object('required', 1, 'minLength', 1, 'label', 'Last Name', 'type', 'text')
  ),
  'validation', json_object(
    'emailFormat', 1,
    'allowDuplicateUsernames', 0,
    'passwordRequirements', json_object(
      'requireUppercase', 0,
      'requireLowercase', 0,
      'requireNumbers', 0,
      'requireSpecialChars', 0
    )
  ),
  'registration', json_object(
    'enabled', 1,
    'requireEmailVerification', 0,
    'defaultRole', 'viewer'
  )
)
WHERE id = 'core-auth';

-- If core-auth plugin doesn't exist, this migration will be handled by bootstrap
-- No need to insert here as plugin bootstrap handles initial plugin creation
`
  },
  {
    id: "018",
    name: "Settings Table",
    filename: "018_settings_table.sql",
    description: "Migration 018: Settings Table",
    sql: `-- Create settings table for storing application settings
CREATE TABLE IF NOT EXISTS settings (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL, -- 'general', 'appearance', 'security', etc.
  key TEXT NOT NULL,
  value TEXT NOT NULL, -- JSON value
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(category, key)
);

-- Insert default general settings
INSERT OR IGNORE INTO settings (id, category, key, value, created_at, updated_at)
VALUES
  (lower(hex(randomblob(16))), 'general', 'siteName', '"SonicJS AI"', unixepoch() * 1000, unixepoch() * 1000),
  (lower(hex(randomblob(16))), 'general', 'siteDescription', '"A modern headless CMS powered by AI"', unixepoch() * 1000, unixepoch() * 1000),
  (lower(hex(randomblob(16))), 'general', 'timezone', '"UTC"', unixepoch() * 1000, unixepoch() * 1000),
  (lower(hex(randomblob(16))), 'general', 'language', '"en"', unixepoch() * 1000, unixepoch() * 1000),
  (lower(hex(randomblob(16))), 'general', 'maintenanceMode', 'false', unixepoch() * 1000, unixepoch() * 1000);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);
CREATE INDEX IF NOT EXISTS idx_settings_category_key ON settings(category, key);
`
  },
  {
    id: "019",
    name: "Remove Blog Posts Collection",
    filename: "019_remove_blog_posts_collection.sql",
    description: "Migration 019: Remove Blog Posts Collection",
    sql: "-- Migration: Remove blog_posts from database-managed collections\n-- Description: Remove blog-posts-collection from the database so it can be managed by code-based collection\n-- Created: 2025-11-04\n\n-- Delete content associated with blog-posts-collection\nDELETE FROM content WHERE collection_id = 'blog-posts-collection';\n\n-- Delete content fields for blog-posts-collection\nDELETE FROM content_fields WHERE collection_id = 'blog-posts-collection';\n\n-- Delete the blog-posts collection itself\nDELETE FROM collections WHERE id = 'blog-posts-collection';\n\n-- The blog-posts collection will now be managed by the code-based collection\n-- in src/collections/blog-posts.collection.ts\n"
  },
  {
    id: "020",
    name: "Add Email Plugin",
    filename: "020_add_email_plugin.sql",
    description: "Migration 020: Add Email Plugin",
    sql: `-- Add Email Plugin
-- Migration: 020_add_email_plugin
-- Description: Add email plugin for transactional emails via Resend

INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'email',
    'email',
    'Email',
    'Send transactional emails using Resend',
    '1.0.0-beta.1',
    'SonicJS Team',
    'utilities',
    '\u{1F4E7}',
    'inactive',
    TRUE,
    '["email:manage", "email:send", "email:view-logs"]',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "021",
    name: "Add Magic Link Auth Plugin",
    filename: "021_add_magic_link_auth_plugin.sql",
    description: "Migration 021: Add Magic Link Auth Plugin",
    sql: `-- Add Magic Link Authentication Plugin
-- Migration: 021_add_magic_link_auth_plugin
-- Description: Add magic link authentication plugin for passwordless login

-- Create magic_links table
CREATE TABLE IF NOT EXISTS magic_links (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token);
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(user_email);
CREATE INDEX IF NOT EXISTS idx_magic_links_expires ON magic_links(expires_at);

-- Register the plugin
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, installed_at, last_updated
) VALUES (
    'magic-link-auth',
    'magic-link-auth',
    'Magic Link Authentication',
    'Passwordless authentication via email magic links. Users receive a secure one-time link to sign in without entering a password.',
    '1.0.0',
    'SonicJS Team',
    'security',
    '\u{1F517}',
    'inactive',
    FALSE,
    '["auth:manage", "auth:magic-link"]',
    '["email"]',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "022",
    name: "Add Tinymce Plugin",
    filename: "022_add_tinymce_plugin.sql",
    description: "Migration 022: Add Tinymce Plugin",
    sql: `-- Add TinyMCE Rich Text Editor Plugin
-- Migration: 022_add_tinymce_plugin
-- Description: Add TinyMCE plugin for WYSIWYG rich text editing

-- Register the plugin (active by default since it replaces hardcoded TinyMCE)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'tinymce-plugin',
    'tinymce-plugin',
    'TinyMCE Rich Text Editor',
    'Powerful WYSIWYG rich text editor for content creation. Provides a full-featured editor with formatting, media embedding, and customizable toolbars for richtext fields.',
    '1.0.0',
    'SonicJS Team',
    'editor',
    '\u270F\uFE0F',
    'active',
    FALSE,
    '[]',
    '[]',
    '{"apiKey":"no-api-key","defaultHeight":300,"defaultToolbar":"full","skin":"oxide-dark"}',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "023",
    name: "Add Easy Mdx Plugin",
    filename: "023_add_easy_mdx_plugin.sql",
    description: "Migration 023: Add Easy Mdx Plugin",
    sql: `-- Add EasyMDE Markdown Editor Plugin
-- Migration: 023_add_easy_mdx_plugin
-- Description: Add EasyMDE plugin for lightweight markdown editing

-- Register the plugin (active by default)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'easy-mdx',
    'easy-mdx',
    'EasyMDE Markdown Editor',
    'Lightweight markdown editor with live preview. Provides a simple and efficient editor with markdown support for richtext fields.',
    '1.0.0',
    'SonicJS Team',
    'editor',
    '\u{1F4DD}',
    'active',
    FALSE,
    '[]',
    '[]',
    '{"defaultHeight":400,"theme":"dark","toolbar":"full","placeholder":"Start writing your content..."}',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "024",
    name: "Add Quill Editor Plugin",
    filename: "024_add_quill_editor_plugin.sql",
    description: "Migration 024: Add Quill Editor Plugin",
    sql: `-- Add Quill Rich Text Editor Plugin
-- Migration: 024_add_quill_editor_plugin
-- Description: Add Quill plugin for modern rich text editing

-- Register the plugin (active by default)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'quill-editor',
    'quill-editor',
    'Quill Rich Text Editor',
    'Modern rich text editor for content creation. Provides a clean, intuitive WYSIWYG editor with customizable toolbars for richtext fields.',
    '1.0.0',
    'SonicJS Team',
    'editor',
    '\u270D\uFE0F',
    'active',
    FALSE,
    '[]',
    '[]',
    '{"theme":"snow","defaultHeight":300,"defaultToolbar":"full","placeholder":"Start writing your content..."}',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "025",
    name: "Add Easymde Plugin",
    filename: "025_add_easymde_plugin.sql",
    description: "Migration 025: Add Easymde Plugin",
    sql: `-- Add EasyMDE Rich Text Editor Plugin
-- Migration: 025_add_easymde_plugin
-- Description: Add EasyMDE plugin for markdown-based rich text editing

-- Register the plugin (inactive by default, replacing MDXEditor)
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, dependencies, settings, installed_at, last_updated
) VALUES (
    'easymde-editor',
    'easymde-editor',
    'EasyMDE Editor',
    'Lightweight markdown editor for content creation. Simple, elegant WYSIWYG markdown editor with live preview, toolbar, and dark mode support for richtext fields.',
    '1.0.0',
    'SonicJS Team',
    'editor',
    '\u270D\uFE0F',
    'inactive',
    TRUE,
    '[]',
    '[]',
    '{"theme":"dark","defaultHeight":300,"toolbar":"full","spellChecker":false,"placeholder":"Start writing your content..."}',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "026",
    name: "Add Otp Login",
    filename: "026_add_otp_login.sql",
    description: "Migration 026: Add Otp Login",
    sql: `-- Add OTP Login Plugin
-- Migration: 021_add_otp_login
-- Description: Add OTP login plugin for passwordless authentication via email codes

-- Create table for OTP codes
CREATE TABLE IF NOT EXISTS otp_codes (
  id TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  used_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  attempts INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_otp_email_code ON otp_codes(user_email, code);
CREATE INDEX IF NOT EXISTS idx_otp_expires ON otp_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_used ON otp_codes(used);

-- Add plugin record
INSERT OR IGNORE INTO plugins (
    id, name, display_name, description, version, author, category, icon,
    status, is_core, permissions, installed_at, last_updated
) VALUES (
    'otp-login',
    'otp-login',
    'OTP Login',
    'Passwordless authentication via email one-time codes',
    '1.0.0-beta.1',
    'SonicJS Team',
    'security',
    '\u{1F522}',
    'inactive',
    TRUE,
    '["otp:manage", "otp:request", "otp:verify"]',
    unixepoch(),
    unixepoch()
);
`
  },
  {
    id: "027",
    name: "Fix Slug Field Type",
    filename: "027_fix_slug_field_type.sql",
    description: "Migration 027: Fix Slug Field Type",
    sql: "-- Migration: Fix slug field type\n-- Description: Update slug fields to use 'slug' field type instead of 'text' for proper auto-generation\n-- Created: 2026-01-10\n\n-- Update pages collection slug field to use 'slug' field type\nUPDATE content_fields \nSET field_type = 'slug'\nWHERE field_name = 'slug' AND collection_id = 'pages-collection';\n\n-- Update blog posts slug field if it exists\nUPDATE content_fields \nSET field_type = 'slug'\nWHERE field_name = 'slug' AND collection_id = 'blog-posts-collection';\n\n-- Update news slug field if it exists\nUPDATE content_fields \nSET field_type = 'slug'\nWHERE field_name = 'slug' AND collection_id = 'news-collection';\n"
  },
  {
    id: "028",
    name: "Fix Slug Field Type In Schemas",
    filename: "028_fix_slug_field_type_in_schemas.sql",
    description: "Migration 028: Fix Slug Field Type In Schemas",
    sql: `-- Migration: Fix slug field type in collection schemas
-- Description: Update slug fields in collection schemas to use 'slug' type instead of 'string'
-- Created: 2026-01-10

-- Update pages-collection schema
UPDATE collections 
SET schema = REPLACE(
  schema,
  '"slug":{"type":"string"',
  '"slug":{"type":"slug"'
)
WHERE id = 'pages-collection' AND schema LIKE '%"slug":{"type":"string"%';

-- Update blog-posts-collection schema if it exists
UPDATE collections 
SET schema = REPLACE(
  schema,
  '"slug":{"type":"string"',
  '"slug":{"type":"slug"'
)
WHERE id = 'blog-posts-collection' AND schema LIKE '%"slug":{"type":"string"%';

-- Update news-collection schema if it exists
UPDATE collections 
SET schema = REPLACE(
  schema,
  '"slug":{"type":"string"',
  '"slug":{"type":"slug"'
)
WHERE id = 'news-collection' AND schema LIKE '%"slug":{"type":"string"%';
`
  },
  {
    id: "029",
    name: "Add Forms System",
    filename: "029_add_forms_system.sql",
    description: "Migration 029: Add Forms System",
    sql: `-- Migration: 029_add_forms_system.sql
-- Description: Add Form.io integration for advanced form building
-- Date: January 23, 2026
-- Phase: 1 - Database Schema

-- =====================================================
-- Table: forms
-- Description: Stores form definitions and configuration
-- =====================================================

CREATE TABLE IF NOT EXISTS forms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,              -- Machine name (e.g., "contact-form")
  display_name TEXT NOT NULL,             -- Human name (e.g., "Contact Form")
  description TEXT,                       -- Optional description
  category TEXT DEFAULT 'general',        -- Form category (contact, survey, registration, etc.)
  
  -- Form.io schema (JSON)
  formio_schema TEXT NOT NULL,            -- Complete Form.io JSON schema
  
  -- Settings
  settings TEXT,                          -- JSON: {
                                          --   emailNotifications: true,
                                          --   notifyEmail: "admin@example.com",
                                          --   successMessage: "Thank you!",
                                          --   redirectUrl: "/thank-you",
                                          --   allowAnonymous: true,
                                          --   requireAuth: false,
                                          --   maxSubmissions: null,
                                          --   submitButtonText: "Submit",
                                          --   saveProgress: true,
                                          --   webhookUrl: null
                                          -- }
  
  -- Status & Management
  is_active INTEGER DEFAULT 1,            -- Active/inactive flag
  is_public INTEGER DEFAULT 1,            -- Public (anyone) vs private (auth required)
  managed INTEGER DEFAULT 0,              -- Code-managed (like collections)
  
  -- Metadata
  icon TEXT,                              -- Optional icon for admin UI
  color TEXT,                             -- Optional color (hex) for admin UI
  tags TEXT,                              -- JSON array of tags
  
  -- Stats
  submission_count INTEGER DEFAULT 0,     -- Total submissions received
  view_count INTEGER DEFAULT 0,           -- Form views (optional tracking)
  
  -- Ownership
  created_by TEXT REFERENCES users(id),   -- User who created the form
  updated_by TEXT REFERENCES users(id),   -- User who last updated
  
  -- Timestamps
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Indexes for forms
CREATE INDEX IF NOT EXISTS idx_forms_name ON forms(name);
CREATE INDEX IF NOT EXISTS idx_forms_category ON forms(category);
CREATE INDEX IF NOT EXISTS idx_forms_active ON forms(is_active);
CREATE INDEX IF NOT EXISTS idx_forms_public ON forms(is_public);
CREATE INDEX IF NOT EXISTS idx_forms_created_by ON forms(created_by);

-- =====================================================
-- Table: form_submissions
-- Description: Stores submitted form data
-- =====================================================

CREATE TABLE IF NOT EXISTS form_submissions (
  id TEXT PRIMARY KEY,
  form_id TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
  
  -- Submission data
  submission_data TEXT NOT NULL,          -- JSON: The actual form data submitted
  
  -- Submission metadata
  status TEXT DEFAULT 'pending',          -- pending, reviewed, approved, rejected, spam
  submission_number INTEGER,              -- Sequential number per form
  
  -- User information (if authenticated)
  user_id TEXT REFERENCES users(id),      -- Submitter user ID (if logged in)
  user_email TEXT,                        -- Email from form (or user account)
  
  -- Tracking information
  ip_address TEXT,                        -- IP address of submitter
  user_agent TEXT,                        -- Browser user agent
  referrer TEXT,                          -- Page that referred to form
  utm_source TEXT,                        -- UTM tracking params
  utm_medium TEXT,
  utm_campaign TEXT,
  
  -- Review/Processing
  reviewed_by TEXT REFERENCES users(id),  -- Admin who reviewed
  reviewed_at INTEGER,                    -- Review timestamp
  review_notes TEXT,                      -- Admin notes
  
  -- Flags
  is_spam INTEGER DEFAULT 0,              -- Spam flag
  is_archived INTEGER DEFAULT 0,          -- Archived flag
  
  -- Timestamps
  submitted_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Indexes for submissions
CREATE INDEX IF NOT EXISTS idx_form_submissions_form_id ON form_submissions(form_id);
CREATE INDEX IF NOT EXISTS idx_form_submissions_status ON form_submissions(status);
CREATE INDEX IF NOT EXISTS idx_form_submissions_user_id ON form_submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_form_submissions_email ON form_submissions(user_email);
CREATE INDEX IF NOT EXISTS idx_form_submissions_submitted_at ON form_submissions(submitted_at);
CREATE INDEX IF NOT EXISTS idx_form_submissions_spam ON form_submissions(is_spam);

-- Trigger to auto-increment submission_number per form
CREATE TRIGGER IF NOT EXISTS set_submission_number
AFTER INSERT ON form_submissions
BEGIN
  UPDATE form_submissions 
  SET submission_number = (
    SELECT COUNT(*) 
    FROM form_submissions 
    WHERE form_id = NEW.form_id 
    AND id <= NEW.id
  )
  WHERE id = NEW.id;
END;

-- Trigger to update form submission_count
CREATE TRIGGER IF NOT EXISTS increment_form_submission_count
AFTER INSERT ON form_submissions
BEGIN
  UPDATE forms 
  SET submission_count = submission_count + 1,
      updated_at = unixepoch() * 1000
  WHERE id = NEW.form_id;
END;

-- =====================================================
-- Table: form_files (Optional)
-- Description: Link form submissions to uploaded files
-- =====================================================

CREATE TABLE IF NOT EXISTS form_files (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL REFERENCES form_submissions(id) ON DELETE CASCADE,
  media_id TEXT NOT NULL REFERENCES media(id) ON DELETE CASCADE,
  field_name TEXT NOT NULL,               -- Form field that uploaded this file
  uploaded_at INTEGER NOT NULL
);

-- Indexes for form files
CREATE INDEX IF NOT EXISTS idx_form_files_submission ON form_files(submission_id);
CREATE INDEX IF NOT EXISTS idx_form_files_media ON form_files(media_id);

-- =====================================================
-- Sample Data: Create a default contact form
-- =====================================================

INSERT OR IGNORE INTO forms (
  id,
  name,
  display_name,
  description,
  category,
  formio_schema,
  settings,
  is_active,
  is_public,
  created_at,
  updated_at
) VALUES (
  'default-contact-form',
  'contact',
  'Contact Form',
  'A simple contact form for getting in touch',
  'contact',
  '{"components":[]}',
  '{"emailNotifications":false,"successMessage":"Thank you for your submission!","submitButtonText":"Submit","requireAuth":false}',
  1,
  1,
  unixepoch() * 1000,
  unixepoch() * 1000
);
`
  },
  {
    id: "030",
    name: "Add Turnstile To Forms",
    filename: "030_add_turnstile_to_forms.sql",
    description: "Migration 030: Add Turnstile To Forms",
    sql: `-- Add Turnstile configuration to forms table
-- This allows per-form Turnstile settings with global fallback

-- Add columns (D1 may not support CHECK constraints in ALTER TABLE)
ALTER TABLE forms ADD COLUMN turnstile_enabled INTEGER DEFAULT 0;
ALTER TABLE forms ADD COLUMN turnstile_settings TEXT;

-- Set default to inherit global settings for existing forms
UPDATE forms 
SET turnstile_settings = '{"inherit":true}' 
WHERE turnstile_settings IS NULL;

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_forms_turnstile ON forms(turnstile_enabled);
`
  },
  {
    id: "031",
    name: "Ai Search Plugin",
    filename: "031_ai_search_plugin.sql",
    description: "Migration 031: Ai Search Plugin",
    sql: "-- AI Search plugin settings\nCREATE TABLE IF NOT EXISTS ai_search_settings (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  enabled BOOLEAN DEFAULT 0,\n  ai_mode_enabled BOOLEAN DEFAULT 1,\n  selected_collections TEXT, -- JSON array of collection IDs to index\n  dismissed_collections TEXT, -- JSON array of collection IDs user chose not to index\n  autocomplete_enabled BOOLEAN DEFAULT 1,\n  cache_duration INTEGER DEFAULT 1, -- hours\n  results_limit INTEGER DEFAULT 20,\n  index_media BOOLEAN DEFAULT 0,\n  index_status TEXT, -- JSON object with status per collection\n  last_indexed_at INTEGER,\n  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),\n  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)\n);\n\n-- Search history/analytics\nCREATE TABLE IF NOT EXISTS ai_search_history (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  query TEXT NOT NULL,\n  mode TEXT, -- 'ai' or 'keyword'\n  results_count INTEGER,\n  user_id INTEGER,\n  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)\n);\n\n-- Index metadata tracking (per collection)\nCREATE TABLE IF NOT EXISTS ai_search_index_meta (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  collection_id INTEGER NOT NULL,\n  collection_name TEXT NOT NULL, -- Cache collection name for display\n  total_items INTEGER DEFAULT 0,\n  indexed_items INTEGER DEFAULT 0,\n  last_sync_at INTEGER,\n  status TEXT DEFAULT 'pending', -- 'pending', 'indexing', 'completed', 'error'\n  error_message TEXT,\n  UNIQUE(collection_id)\n);\n\n-- Indexes for performance\nCREATE INDEX IF NOT EXISTS idx_ai_search_history_created_at ON ai_search_history(created_at);\nCREATE INDEX IF NOT EXISTS idx_ai_search_history_mode ON ai_search_history(mode);\nCREATE INDEX IF NOT EXISTS idx_ai_search_index_meta_collection_id ON ai_search_index_meta(collection_id);\nCREATE INDEX IF NOT EXISTS idx_ai_search_index_meta_status ON ai_search_index_meta(status);\n"
  },
  {
    id: "032",
    name: "Form Content Integration",
    filename: "032_form_content_integration.sql",
    description: "Migration 032: Form Content Integration",
    sql: "-- Migration 032: Form-Content Integration\n-- Adds bridge columns to link forms to collections and submissions to content items\n\n-- Add source_type and source_id to collections for form-derived collections\nALTER TABLE collections ADD COLUMN source_type TEXT DEFAULT 'user';\nALTER TABLE collections ADD COLUMN source_id TEXT;\n\n-- Index for efficient lookup of form-derived collections\nCREATE INDEX IF NOT EXISTS idx_collections_source ON collections(source_type, source_id);\n\n-- Add content_id to form_submissions for linking to content items\nALTER TABLE form_submissions ADD COLUMN content_id TEXT REFERENCES content(id);\n\n-- Index for efficient lookup by content_id\nCREATE INDEX IF NOT EXISTS idx_form_submissions_content_id ON form_submissions(content_id);\n\n-- Create system user for anonymous form submissions\nINSERT OR IGNORE INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, created_at, updated_at)\nVALUES ('system-form-submission', 'system-forms@sonicjs.internal', 'system-forms', 'Form', 'Submission', NULL, 'viewer', 0, strftime('%s','now') * 1000, strftime('%s','now') * 1000);\n"
  }
];
var migrationsByIdMap = new Map(
  bundledMigrations.map((m) => [m.id, m])
);
function getMigrationSQLById(id) {
  return migrationsByIdMap.get(id)?.sql ?? null;
}

// src/services/migrations.ts
var MigrationService = class {
  constructor(db) {
    this.db = db;
  }
  /**
   * Initialize the migrations tracking table
   */
  async initializeMigrationsTable() {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS migrations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        filename TEXT NOT NULL,
        applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        checksum TEXT
      )
    `;
    await this.db.prepare(createTableQuery).run();
  }
  /**
   * Get all available migrations from the bundled migrations
   */
  async getAvailableMigrations() {
    const migrations = [];
    const appliedResult = await this.db.prepare(
      "SELECT id, name, filename, applied_at FROM migrations ORDER BY applied_at ASC"
    ).all();
    const appliedMigrations = new Map(
      appliedResult.results?.map((row) => [row.id, row]) || []
    );
    await this.autoDetectAppliedMigrations(appliedMigrations);
    for (const bundled of bundledMigrations) {
      const applied = appliedMigrations.has(bundled.id);
      const appliedData = appliedMigrations.get(bundled.id);
      migrations.push({
        id: bundled.id,
        name: bundled.name,
        filename: bundled.filename,
        description: bundled.description,
        applied,
        appliedAt: applied ? appliedData?.applied_at : void 0,
        size: bundled.sql.length
      });
    }
    return migrations;
  }
  /**
   * Auto-detect applied migrations by checking if their tables exist
   */
  async autoDetectAppliedMigrations(appliedMigrations) {
    if (!appliedMigrations.has("001")) {
      const hasBasicTables = await this.checkTablesExist(["users", "content", "collections", "media"]);
      if (hasBasicTables) {
        appliedMigrations.set("001", {
          id: "001",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Initial Schema",
          filename: "001_initial_schema.sql"
        });
        await this.markMigrationApplied("001", "Initial Schema", "001_initial_schema.sql");
      }
    }
    if (!appliedMigrations.has("002")) {
      const hasFaqTables = await this.checkTablesExist(["faqs"]);
      if (hasFaqTables) {
        appliedMigrations.set("002", {
          id: "002",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Faq Plugin",
          filename: "002_faq_plugin.sql"
        });
        await this.markMigrationApplied("002", "Faq Plugin", "002_faq_plugin.sql");
      }
    }
    if (!appliedMigrations.has("003")) {
      const hasStage5Tables = await this.checkTablesExist(["content_fields", "content_relationships", "workflow_templates"]);
      if (hasStage5Tables) {
        appliedMigrations.set("003", {
          id: "003",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Stage 5 Enhancements",
          filename: "003_stage5_enhancements.sql"
        });
        await this.markMigrationApplied("003", "Stage 5 Enhancements", "003_stage5_enhancements.sql");
      }
    }
    if (!appliedMigrations.has("012")) {
      const hasTestimonialsTables = await this.checkTablesExist(["testimonials"]);
      if (hasTestimonialsTables) {
        appliedMigrations.set("012", {
          id: "012",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Testimonials Plugin",
          filename: "012_testimonials_plugin.sql"
        });
        await this.markMigrationApplied("012", "Testimonials Plugin", "012_testimonials_plugin.sql");
      }
    }
    if (!appliedMigrations.has("013")) {
      const hasCodeExamplesTables = await this.checkTablesExist(["code_examples"]);
      if (hasCodeExamplesTables) {
        appliedMigrations.set("013", {
          id: "013",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Code Examples Plugin",
          filename: "013_code_examples_plugin.sql"
        });
        await this.markMigrationApplied("013", "Code Examples Plugin", "013_code_examples_plugin.sql");
      }
    }
    if (!appliedMigrations.has("004")) {
      const hasUserTables = await this.checkTablesExist(["api_tokens", "workflow_history"]);
      if (hasUserTables) {
        appliedMigrations.set("004", {
          id: "004",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "User Management",
          filename: "004_stage6_user_management.sql"
        });
        await this.markMigrationApplied("004", "User Management", "004_stage6_user_management.sql");
      }
    }
    if (!appliedMigrations.has("006")) {
      const hasPluginTables = await this.checkTablesExist(["plugins", "plugin_hooks"]);
      if (hasPluginTables) {
        appliedMigrations.set("006", {
          id: "006",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Plugin System",
          filename: "006_plugin_system.sql"
        });
        await this.markMigrationApplied("006", "Plugin System", "006_plugin_system.sql");
      }
    }
    const hasManagedColumn = await this.checkColumnExists("collections", "managed");
    if (!appliedMigrations.has("011") && hasManagedColumn) {
      appliedMigrations.set("011", {
        id: "011",
        applied_at: (/* @__PURE__ */ new Date()).toISOString(),
        name: "Config Managed Collections",
        filename: "011_config_managed_collections.sql"
      });
      await this.markMigrationApplied("011", "Config Managed Collections", "011_config_managed_collections.sql");
    } else if (appliedMigrations.has("011") && !hasManagedColumn) {
      console.log("[Migration] Migration 011 marked as applied but managed column missing - will re-run");
      appliedMigrations.delete("011");
      await this.removeMigrationApplied("011");
    }
    if (!appliedMigrations.has("009")) {
      const hasLoggingTables = await this.checkTablesExist(["system_logs", "log_config"]);
      if (hasLoggingTables) {
        appliedMigrations.set("009", {
          id: "009",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "System Logging",
          filename: "009_system_logging.sql"
        });
        await this.markMigrationApplied("009", "System Logging", "009_system_logging.sql");
      }
    }
    if (!appliedMigrations.has("018")) {
      const hasSettingsTable = await this.checkTablesExist(["settings"]);
      if (hasSettingsTable) {
        appliedMigrations.set("018", {
          id: "018",
          applied_at: (/* @__PURE__ */ new Date()).toISOString(),
          name: "Settings Table",
          filename: "018_settings_table.sql"
        });
        await this.markMigrationApplied("018", "Settings Table", "018_settings_table.sql");
      }
    }
  }
  /**
   * Check if specific tables exist in the database
   */
  async checkTablesExist(tableNames) {
    try {
      for (const tableName of tableNames) {
        const result = await this.db.prepare(
          `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
        ).bind(tableName).first();
        if (!result) {
          return false;
        }
      }
      return true;
    } catch (error) {
      return false;
    }
  }
  /**
   * Check if a specific column exists in a table
   */
  async checkColumnExists(tableName, columnName) {
    try {
      const result = await this.db.prepare(
        `SELECT * FROM pragma_table_info(?) WHERE name = ?`
      ).bind(tableName, columnName).first();
      return !!result;
    } catch (error) {
      return false;
    }
  }
  /**
   * Get migration status summary
   */
  async getMigrationStatus() {
    await this.initializeMigrationsTable();
    const migrations = await this.getAvailableMigrations();
    const appliedMigrations = migrations.filter((m) => m.applied);
    const pendingMigrations = migrations.filter((m) => !m.applied);
    const lastApplied = appliedMigrations.length > 0 ? appliedMigrations[appliedMigrations.length - 1]?.appliedAt : void 0;
    return {
      totalMigrations: migrations.length,
      appliedMigrations: appliedMigrations.length,
      pendingMigrations: pendingMigrations.length,
      lastApplied,
      migrations
    };
  }
  /**
   * Mark a migration as applied
   */
  async markMigrationApplied(migrationId, name, filename) {
    await this.initializeMigrationsTable();
    await this.db.prepare(
      "INSERT OR REPLACE INTO migrations (id, name, filename, applied_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(migrationId, name, filename).run();
  }
  /**
   * Remove a migration from the applied list (so it can be re-run)
   */
  async removeMigrationApplied(migrationId) {
    await this.initializeMigrationsTable();
    await this.db.prepare(
      "DELETE FROM migrations WHERE id = ?"
    ).bind(migrationId).run();
  }
  /**
   * Check if a specific migration has been applied
   */
  async isMigrationApplied(migrationId) {
    await this.initializeMigrationsTable();
    const result = await this.db.prepare(
      "SELECT COUNT(*) as count FROM migrations WHERE id = ?"
    ).bind(migrationId).first();
    return result?.count > 0;
  }
  /**
   * Get the last applied migration
   */
  async getLastAppliedMigration() {
    await this.initializeMigrationsTable();
    const result = await this.db.prepare(
      "SELECT id, name, filename, applied_at FROM migrations ORDER BY applied_at DESC LIMIT 1"
    ).first();
    if (!result) return null;
    return {
      id: result.id,
      name: result.name,
      filename: result.filename,
      applied: true,
      appliedAt: result.applied_at
    };
  }
  /**
   * Run pending migrations
   */
  async runPendingMigrations() {
    await this.initializeMigrationsTable();
    const status = await this.getMigrationStatus();
    const pendingMigrations = status.migrations.filter((m) => !m.applied);
    if (pendingMigrations.length === 0) {
      return {
        success: true,
        message: "All migrations are up to date",
        applied: []
      };
    }
    const applied = [];
    const errors = [];
    for (const migration of pendingMigrations) {
      try {
        console.log(`[Migration] Applying ${migration.id}: ${migration.name}`);
        await this.applyMigration(migration);
        await this.markMigrationApplied(migration.id, migration.name, migration.filename);
        applied.push(migration.id);
        console.log(`[Migration] Successfully applied ${migration.id}`);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`[Migration] Failed to apply migration ${migration.id}:`, errorMessage);
        errors.push(`${migration.id}: ${errorMessage}`);
      }
    }
    if (errors.length > 0 && applied.length === 0) {
      return {
        success: false,
        message: `Failed to apply migrations: ${errors.join("; ")}`,
        applied
      };
    }
    return {
      success: true,
      message: applied.length > 0 ? `Applied ${applied.length} migration(s)${errors.length > 0 ? ` (${errors.length} failed)` : ""}` : "No migrations applied",
      applied
    };
  }
  /**
   * Apply a specific migration
   */
  async applyMigration(migration) {
    const migrationSQL = getMigrationSQLById(migration.id);
    if (migrationSQL === null) {
      throw new Error(`Migration SQL not found for ${migration.id}`);
    }
    if (migrationSQL.trim() === "") {
      console.log(`[Migration] Skipping empty migration ${migration.id}`);
      return;
    }
    const statements = this.splitSQLStatements(migrationSQL);
    for (const statement of statements) {
      if (statement.trim()) {
        try {
          await this.db.prepare(statement).run();
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          if (errorMessage.includes("already exists") || errorMessage.includes("duplicate column name") || errorMessage.includes("UNIQUE constraint failed")) {
            console.log(`[Migration] Skipping (already exists): ${statement.substring(0, 50)}...`);
            continue;
          }
          console.error(`[Migration] Error executing statement: ${statement.substring(0, 100)}...`);
          throw error;
        }
      }
    }
  }
  /**
   * Split SQL into statements, handling CREATE TRIGGER properly
   */
  splitSQLStatements(sql) {
    const statements = [];
    let current = "";
    let inTrigger = false;
    const lines = sql.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("--") || trimmed.length === 0) {
        continue;
      }
      if (trimmed.toUpperCase().includes("CREATE TRIGGER")) {
        inTrigger = true;
      }
      current += line + "\n";
      if (inTrigger && trimmed.toUpperCase() === "END;") {
        statements.push(current.trim());
        current = "";
        inTrigger = false;
      } else if (!inTrigger && trimmed.endsWith(";")) {
        statements.push(current.trim());
        current = "";
      }
    }
    if (current.trim()) {
      statements.push(current.trim());
    }
    return statements.filter((s) => s.length > 0);
  }
  /**
   * Validate database schema
   */
  async validateSchema() {
    const issues = [];
    const requiredTables = [
      "users",
      "content",
      "collections",
      "media"
    ];
    for (const table of requiredTables) {
      try {
        await this.db.prepare(`SELECT COUNT(*) FROM ${table} LIMIT 1`).first();
      } catch (error) {
        issues.push(`Missing table: ${table}`);
      }
    }
    const hasManagedColumn = await this.checkColumnExists("collections", "managed");
    if (!hasManagedColumn) {
      issues.push("Missing column: collections.managed");
    }
    return {
      valid: issues.length === 0,
      issues
    };
  }
};

exports.MigrationService = MigrationService;
//# sourceMappingURL=chunk-SZJ5JZ2Q.cjs.map
//# sourceMappingURL=chunk-SZJ5JZ2Q.cjs.map