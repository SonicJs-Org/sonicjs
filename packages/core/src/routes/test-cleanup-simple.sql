-- Simple cleanup script that can be run directly
-- This avoids SQL variable limits by using pattern matching

-- Step 1: Delete child data for content that matches test patterns
DELETE FROM content_versions
WHERE content_id IN (
  SELECT id FROM content
  WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
);

DELETE FROM workflow_history
WHERE content_id IN (
  SELECT id FROM content
  WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
);

DELETE FROM content_data
WHERE content_id IN (
  SELECT id FROM content
  WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%'
);

-- Step 2: Delete test content
DELETE FROM content
WHERE title LIKE 'Test %' OR title LIKE '%E2E%' OR title LIKE '%Playwright%' OR title LIKE '%Sample%';

-- Step 3: Delete test user data
DELETE FROM api_tokens WHERE user_id IN (
  SELECT id FROM users WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')
);

DELETE FROM media WHERE uploaded_by IN (
  SELECT id FROM users WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%')
);

-- Step 4: Delete test users
DELETE FROM users WHERE email != 'admin@sonicjs.com' AND (email LIKE '%test%' OR email LIKE '%example.com%');

-- Step 5: Delete test collection data
DELETE FROM collection_fields WHERE collection_id IN (
  SELECT id FROM collections WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
);

DELETE FROM content WHERE collection_id IN (
  SELECT id FROM collections WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles')
);

-- Step 6: Delete test collections
DELETE FROM collections WHERE name LIKE 'test_%' OR name IN ('test_collection', 'products', 'articles');

-- Step 7: Clean orphans
DELETE FROM content_data WHERE content_id NOT IN (SELECT id FROM content);
DELETE FROM collection_fields WHERE collection_id NOT IN (SELECT id FROM collections);
DELETE FROM content_versions WHERE content_id NOT IN (SELECT id FROM content);
DELETE FROM workflow_history WHERE content_id NOT IN (SELECT id FROM content);
