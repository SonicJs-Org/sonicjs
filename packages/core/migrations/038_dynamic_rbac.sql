-- Dynamic RBAC: roles, verbs, and a (role × resource × verb) grant matrix.
-- Roles and verbs are editable at runtime via the admin UI. Resources are
-- computed (system resources + one per collection), not stored — so new
-- collections automatically gain permissions.

CREATE TABLE IF NOT EXISTS rbac_roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  is_system INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

CREATE TABLE IF NOT EXISTS rbac_verbs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  is_system INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 100
);

-- One row per granted (role, resource, verb). resource/verb support wildcards:
--   resource '*'           → all resources
--   resource 'collection:*' → all collections
--   verb '*'               → all verbs
--   verb 'manage'          → implies every verb on that resource
CREATE TABLE IF NOT EXISTS rbac_role_grants (
  role_id TEXT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
  resource TEXT NOT NULL,
  verb TEXT NOT NULL,
  PRIMARY KEY (role_id, resource, verb)
);

CREATE TABLE IF NOT EXISTS rbac_user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- Seed system roles
INSERT OR IGNORE INTO rbac_roles (id, name, display_name, description, is_system) VALUES
  ('role-admin','admin','Administrator','Full access to everything',1),
  ('role-editor','editor','Editor','Manage content and media across collections',1),
  ('role-author','author','Author','Create and edit own content',1),
  ('role-viewer','viewer','Viewer','Read-only access',1);

-- Seed system verbs
INSERT OR IGNORE INTO rbac_verbs (id, name, description, is_system, sort_order) VALUES
  ('verb-read','read','View a resource',1,10),
  ('verb-create','create','Create a resource',1,20),
  ('verb-update','update','Edit a resource',1,30),
  ('verb-delete','delete','Remove a resource',1,40),
  ('verb-manage','manage','Full control (implies all verbs)',1,50);

-- Default grants
-- admin: everything (resource '*' = all resources, verb 'manage' = all verbs)
INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES ('role-admin','*','manage');
-- editor: full content/media + all collections CRUD + read settings
INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES
  ('role-editor','content','manage'),
  ('role-editor','media','manage'),
  ('role-editor','collection:*','read'),
  ('role-editor','collection:*','create'),
  ('role-editor','collection:*','update'),
  ('role-editor','collection:*','delete'),
  ('role-editor','settings','read');
-- author: create/edit content + read media + read collections
INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES
  ('role-author','content','read'),
  ('role-author','content','create'),
  ('role-author','content','update'),
  ('role-author','media','read'),
  ('role-author','media','create'),
  ('role-author','collection:*','read');
-- viewer: read-only
INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES
  ('role-viewer','content','read'),
  ('role-viewer','media','read'),
  ('role-viewer','collection:*','read');

-- Backfill user→role from the legacy users.role string column
INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u JOIN rbac_roles r ON r.name = u.role;
