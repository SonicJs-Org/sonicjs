-- Portal access migrates backend entry from the legacy users.role string to
-- dynamic RBAC. A user can enter /admin/* if any assigned RBAC role grants
-- portal:access.

INSERT OR IGNORE INTO rbac_verbs (id, name, description, is_system, sort_order) VALUES
  ('verb-access','access','Enter or use a portal/resource',1,5);

-- Admin already has *:manage, which implies portal:access. Keep an explicit
-- grant too so the matrix makes backend entry easy to see and reason about.
INSERT OR IGNORE INTO rbac_role_grants (role_id, resource, verb) VALUES
  ('role-admin','portal','access'),
  ('role-admin','rbac','manage'),
  ('role-admin','collections','manage'),
  ('role-admin','email','manage'),
  ('role-admin','users','manage');
