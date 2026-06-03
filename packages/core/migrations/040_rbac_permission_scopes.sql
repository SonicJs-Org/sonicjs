-- Add constrained permission scopes to RBAC grants.
--
-- Existing grants become `any`, preserving current behavior. New grants can use
-- `own` for content/collection read, update, and delete checks where ownership
-- is enforced against content.author_id.

ALTER TABLE rbac_role_grants ADD COLUMN scope TEXT NOT NULL DEFAULT 'any';

UPDATE rbac_role_grants
SET scope = 'any'
WHERE scope IS NULL OR scope = '';
