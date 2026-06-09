-- Migration 0002: Document Schema (v3 greenfield)
-- Contains only the new document data model tables, generated columns, and indexes.

-- Document type registry
CREATE TABLE IF NOT EXISTS document_types (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  schema TEXT NOT NULL DEFAULT '{}',
  queryable_fields TEXT NOT NULL DEFAULT '[]',
  settings TEXT NOT NULL DEFAULT '{}',
  plugin_id TEXT,
  source TEXT NOT NULL DEFAULT 'code' CHECK (source IN ('code', 'plugin', 'system')),
  schema_version INTEGER NOT NULL DEFAULT 1,
  is_system INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_document_types_plugin ON document_types(plugin_id);
CREATE INDEX IF NOT EXISTS idx_document_types_active ON document_types(is_active);

-- Documents: canonical document rows and historical versions.
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  root_id TEXT NOT NULL,
  type_id TEXT NOT NULL REFERENCES document_types(id),
  type_version INTEGER NOT NULL DEFAULT 1,

  version_of_id TEXT REFERENCES documents(id),
  version_number INTEGER NOT NULL DEFAULT 1,

  is_current_draft INTEGER NOT NULL DEFAULT 1,
  is_published INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),

  parent_root_id TEXT NOT NULL DEFAULT '',
  slug TEXT,
  path TEXT,
  title TEXT,
  zone TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  visible INTEGER NOT NULL DEFAULT 1,

  published_at INTEGER,
  scheduled_at INTEGER,
  expires_at INTEGER,
  deleted_at INTEGER,

  tenant_id TEXT NOT NULL DEFAULT 'default',
  locale TEXT NOT NULL DEFAULT 'default',
  translation_group_id TEXT NOT NULL DEFAULT '',

  data TEXT NOT NULL DEFAULT '{}',
  metadata TEXT NOT NULL DEFAULT '{}',

  owner_id TEXT,
  created_by TEXT,
  updated_by TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Queryable scalar fields as VIRTUAL generated columns (no write cost, no drift).

-- FAQ
ALTER TABLE documents ADD COLUMN q_faq_category   TEXT    AS (json_extract(data, '$.category'))  VIRTUAL;
ALTER TABLE documents ADD COLUMN q_faq_sort_order  INTEGER AS (json_extract(data, '$.sortOrder')) VIRTUAL;

-- Testimonial
ALTER TABLE documents ADD COLUMN q_tst_rating      INTEGER AS (json_extract(data, '$.rating'))        VIRTUAL;
ALTER TABLE documents ADD COLUMN q_tst_company     TEXT    AS (json_extract(data, '$.authorCompany')) VIRTUAL;
ALTER TABLE documents ADD COLUMN q_tst_sort_order  INTEGER AS (json_extract(data, '$.sortOrder'))     VIRTUAL;

-- Contact Message
ALTER TABLE documents ADD COLUMN q_msg_review      TEXT    AS (json_extract(data, '$.reviewStatus')) VIRTUAL;
ALTER TABLE documents ADD COLUMN q_msg_email       TEXT    AS (json_extract(data, '$.email'))        VIRTUAL;

-- Media Asset
ALTER TABLE documents ADD COLUMN q_media_mime      TEXT    AS (json_extract(data, '$.mimeType')) VIRTUAL;
ALTER TABLE documents ADD COLUMN q_media_folder    TEXT    AS (json_extract(data, '$.folder'))   VIRTUAL;
ALTER TABLE documents ADD COLUMN q_media_size      INTEGER AS (json_extract(data, '$.size'))     VIRTUAL;

-- Blog Post
ALTER TABLE documents ADD COLUMN q_blog_difficulty TEXT AS (json_extract(data, '$.difficulty')) VIRTUAL;
ALTER TABLE documents ADD COLUMN q_blog_author     TEXT AS (json_extract(data, '$.author'))     VIRTUAL;

-- Plugin (managed via document model)
ALTER TABLE documents ADD COLUMN q_plugin_status   TEXT    AS (json_extract(data, '$.status'))   VIRTUAL;
ALTER TABLE documents ADD COLUMN q_plugin_category TEXT    AS (json_extract(data, '$.category')) VIRTUAL;
ALTER TABLE documents ADD COLUMN q_plugin_is_core  INTEGER AS (json_extract(data, '$.isCore'))   VIRTUAL;

-- Revision chain
CREATE INDEX IF NOT EXISTS idx_documents_root ON documents(root_id, version_number DESC);

-- List / lifecycle
CREATE INDEX IF NOT EXISTS idx_documents_published ON documents(tenant_id, type_id, locale, is_published)
  WHERE is_published = 1 AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_documents_drafts ON documents(tenant_id, type_id, status, is_current_draft)
  WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_documents_parent ON documents(tenant_id, parent_root_id, sort_order, is_published);
CREATE INDEX IF NOT EXISTS idx_documents_path ON documents(tenant_id, path);
CREATE INDEX IF NOT EXISTS idx_documents_translation ON documents(translation_group_id, locale);
CREATE INDEX IF NOT EXISTS idx_documents_deleted ON documents(deleted_at);
CREATE INDEX IF NOT EXISTS idx_documents_scheduled ON documents(scheduled_at) WHERE scheduled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_documents_expires ON documents(expires_at) WHERE expires_at IS NOT NULL;

-- Stable keyset/cursor pagination for published lists
CREATE INDEX IF NOT EXISTS idx_documents_published_cursor
  ON documents(tenant_id, type_id, updated_at DESC, id DESC)
  WHERE is_published = 1 AND deleted_at IS NULL;

-- Generated-column filter indexes
CREATE INDEX IF NOT EXISTS idx_q_faq_category ON documents(tenant_id, type_id, q_faq_category, q_faq_sort_order) WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_tst_rating   ON documents(tenant_id, type_id, q_tst_rating, q_tst_sort_order)   WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_tst_company  ON documents(tenant_id, type_id, q_tst_company, q_tst_sort_order)  WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_media_mime   ON documents(tenant_id, type_id, q_media_mime)   WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_media_folder ON documents(tenant_id, type_id, q_media_folder) WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_media_size   ON documents(tenant_id, type_id, q_media_size)   WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_msg_review   ON documents(tenant_id, type_id, q_msg_review) WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_q_msg_email    ON documents(tenant_id, type_id, q_msg_email)  WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_q_blog_difficulty ON documents(tenant_id, type_id, q_blog_difficulty) WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_q_blog_author ON documents(tenant_id, type_id, q_blog_author) WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_q_blog_difficulty_pub ON documents(tenant_id, type_id, q_blog_difficulty) WHERE is_published = 1;
CREATE INDEX IF NOT EXISTS idx_q_plugin_status   ON documents(tenant_id, type_id, q_plugin_status)   WHERE is_current_draft = 1;
CREATE INDEX IF NOT EXISTS idx_q_plugin_category ON documents(tenant_id, type_id, q_plugin_category) WHERE is_current_draft = 1;

-- Partial unique indexes: the hard concurrency guarantees for draft/publish invariants.
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_one_current_draft
  ON documents(root_id) WHERE is_current_draft = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_one_published
  ON documents(root_id) WHERE is_published = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_unique_version
  ON documents(root_id, version_number);
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_unique_slug
  ON documents(tenant_id, locale, type_id, parent_root_id, slug)
  WHERE is_current_draft = 1 AND deleted_at IS NULL AND slug IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_one_translation_per_locale
  ON documents(tenant_id, translation_group_id, locale)
  WHERE is_current_draft = 1 AND translation_group_id <> '';

-- Document references: typed document-to-document edges.
CREATE TABLE IF NOT EXISTS document_references (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  from_root_id TEXT NOT NULL,
  from_document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  field_name TEXT NOT NULL,
  ordinal INTEGER NOT NULL DEFAULT 0,
  to_root_id TEXT NOT NULL,
  ref_strength TEXT NOT NULL DEFAULT 'weak' CHECK (ref_strength IN ('strong', 'weak')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_docref_to   ON document_references(tenant_id, to_root_id);
CREATE INDEX IF NOT EXISTS idx_docref_from ON document_references(from_document_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_docref_unique
  ON document_references(from_document_id, field_name, ordinal);

-- Document facets: indexed rows for multi-valued scalar fields (e.g. tags arrays).
CREATE TABLE IF NOT EXISTS document_facets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  root_id TEXT NOT NULL,
  type_id TEXT NOT NULL,
  field_name TEXT NOT NULL,
  ordinal INTEGER NOT NULL DEFAULT 0,
  value_text TEXT,
  value_number REAL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_facets_lookup ON document_facets(tenant_id, type_id, field_name, value_text);
CREATE INDEX IF NOT EXISTS idx_facets_doc    ON document_facets(document_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_facets_unique
  ON document_facets(document_id, field_name, ordinal);

-- Document permissions: per-document ACL overrides.
CREATE TABLE IF NOT EXISTS document_permissions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  root_id TEXT NOT NULL,
  principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'role', 'group', 'public', 'token')),
  principal_id TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('read', 'create', 'update', 'delete', 'publish', 'manage')),
  effect TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
  inherited INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_document_permissions_root ON document_permissions(tenant_id, root_id);
CREATE INDEX IF NOT EXISTS idx_document_permissions_principal
  ON document_permissions(tenant_id, principal_type, principal_id, permission);
CREATE UNIQUE INDEX IF NOT EXISTS idx_document_permissions_unique
  ON document_permissions(root_id, principal_type, principal_id, permission);
