-- Migration 0011: Add custom data column to user_profiles
-- Stores plugin-defined custom profile fields as JSON
-- Used by the user-profiles plugin for developer-defined fields

ALTER TABLE user_profiles ADD COLUMN data TEXT DEFAULT '{}';
