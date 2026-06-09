export const workflowMigration = `
-- Workflow Plugin Migration
-- This migration adds workflow and automation capabilities

-- Workflow States Table
CREATE TABLE IF NOT EXISTS workflow_states (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  description TEXT,
  color TEXT DEFAULT '#6B7280',
  is_initial INTEGER DEFAULT 0,
  is_final INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default workflow states
INSERT OR IGNORE INTO workflow_states (id, name, description, color, is_initial, is_final) VALUES
('draft', 'Draft', 'Content is being worked on', '#F59E0B', 1, 0),
('pending-review', 'Pending Review', 'Content is waiting for review', '#3B82F6', 0, 0),
('approved', 'Approved', 'Content has been approved', '#10B981', 0, 0),
('published', 'Published', 'Content is live', '#059669', 0, 1),
('rejected', 'Rejected', 'Content was rejected', '#EF4444', 0, 1),
('archived', 'Archived', 'Content has been archived', '#6B7280', 0, 1);

-- Workflows Table
CREATE TABLE IF NOT EXISTS workflows (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  description TEXT,
  collection_id TEXT,
  is_active INTEGER DEFAULT 1,
  auto_publish INTEGER DEFAULT 0,
  require_approval INTEGER DEFAULT 1,
  approval_levels INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);

-- Workflow Transitions Table
CREATE TABLE IF NOT EXISTS workflow_transitions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workflow_id TEXT NOT NULL,
  from_state_id TEXT NOT NULL,
  to_state_id TEXT NOT NULL,
  required_permission TEXT,
  auto_transition INTEGER DEFAULT 0,
  transition_conditions TEXT, -- JSON
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE,
  FOREIGN KEY (from_state_id) REFERENCES workflow_states(id),
  FOREIGN KEY (to_state_id) REFERENCES workflow_states(id)
);

-- Content Workflow Status Table
CREATE TABLE IF NOT EXISTS content_workflow_status (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  content_id TEXT NOT NULL, -- holds a document root_id (decoupled from the legacy content table)
  workflow_id TEXT NOT NULL,
  current_state_id TEXT NOT NULL,
  assigned_to TEXT,
  due_date DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workflow_id) REFERENCES workflows(id),
  FOREIGN KEY (current_state_id) REFERENCES workflow_states(id),
  FOREIGN KEY (assigned_to) REFERENCES users(id),
  UNIQUE(content_id, workflow_id)
);

-- Workflow History Table
CREATE TABLE IF NOT EXISTS workflow_history (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  content_id TEXT NOT NULL, -- holds a document root_id (decoupled from the legacy content table)
  workflow_id TEXT NOT NULL,
  from_state_id TEXT,
  to_state_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  comment TEXT,
  metadata TEXT, -- JSON
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (workflow_id) REFERENCES workflows(id),
  FOREIGN KEY (from_state_id) REFERENCES workflow_states(id),
  FOREIGN KEY (to_state_id) REFERENCES workflow_states(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Scheduled Content Table
CREATE TABLE IF NOT EXISTS scheduled_content (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  content_id TEXT NOT NULL, -- holds a document root_id (decoupled from the legacy content table)
  action TEXT NOT NULL, -- 'publish', 'unpublish', 'archive'
  scheduled_at DATETIME NOT NULL,
  timezone TEXT DEFAULT 'UTC',
  user_id TEXT NOT NULL,
  status TEXT DEFAULT 'pending', -- 'pending', 'completed', 'failed', 'cancelled'
  executed_at DATETIME,
  error_message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_content_workflow_status_content_id ON content_workflow_status(content_id);
CREATE INDEX IF NOT EXISTS idx_content_workflow_status_workflow_id ON content_workflow_status(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_history_content_id ON workflow_history(content_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_content_scheduled_at ON scheduled_content(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_scheduled_content_status ON scheduled_content(status);
-- (Removed idx_content_workflow_state ON content(workflow_state_id): the content table is being
--  decommissioned and the canonical draft/published state is documents.is_published/is_current_draft.)

-- Insert default workflow for collections (if collections exist)
INSERT OR IGNORE INTO workflows (id, name, description, collection_id, is_active, require_approval, approval_levels) 
SELECT 
  'default-' || id,
  'Default Workflow for ' || name,
  'Standard content approval workflow',
  id,
  1,
  1,
  1
FROM collections WHERE EXISTS (SELECT 1 FROM collections);

-- Insert default workflow transitions
INSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) 
SELECT 
  w.id,
  'draft',
  'pending-review',
  'content:submit'
FROM workflows w;

INSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) 
SELECT 
  w.id,
  'pending-review',
  'approved',
  'content:approve'
FROM workflows w;

INSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) 
SELECT 
  w.id,
  'approved',
  'published',
  'content:publish'
FROM workflows w;

INSERT OR IGNORE INTO workflow_transitions (workflow_id, from_state_id, to_state_id, required_permission) 
SELECT 
  w.id,
  'pending-review',
  'rejected',
  'content:approve'
FROM workflows w;
`