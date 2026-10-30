/**
 * Events Collection
 *
 * Stores all telemetry events from SonicJS installations
 */

import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "events",
  displayName: "Events",
  description: "Telemetry events",
  icon: "📊",

  schema: {
    type: "object",
    properties: {
      installation_id: {
        type: "string",
        title: "Installation ID",
        required: true,
        maxLength: 100,
        helpText: "Anonymous UUID of the installation",
      },
      event_type: {
        type: "select",
        title: "Event Type",
        required: true,
        enum: ["installation_started", "installation_completed", "installation_failed", "error_occurred", "project_snapshot"],
        enumLabels: ["Installation Started", "Installation Completed", "Installation Failed", "Error Occurred", "Project Snapshot"],
      },
      error_code: {
        type: "string",
        title: "Error Code",
        maxLength: 100,
        helpText: "Machine-readable error identifier (e.g. db_timeout, migration_failed)",
      },
      error_message: {
        type: "string",
        title: "Error Message",
        maxLength: 1000,
        helpText: "Human-readable error description",
      },
      step: {
        type: "select",
        title: "Failed Step",
        enum: ["db_migrate", "seed", "boot", "config", "network", "unknown"],
        enumLabels: ["DB Migrate", "Seed", "Boot", "Config", "Network", "Unknown"],
        helpText: "Which install step failed (only for installation_failed events)",
      },
      sonicjs_version: {
        type: "string",
        title: "SonicJS Version",
        maxLength: 50,
        helpText: "Version of SonicJS being installed",
      },
      properties: {
        type: "json",
        title: "Properties",
        helpText: "JSON object with additional event-specific data",
      },
      timestamp: {
        type: "string",
        title: "Timestamp",
        helpText: "ISO timestamp of the event",
      },
    },
    required: ["installation_id", "event_type"],
  },

  listFields: ["installation_id", "event_type", "step", "error_code", "timestamp", "createdAt"],
  searchFields: ["installation_id", "event_type", "error_code", "step"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",

  managed: true,
  isActive: true,
} satisfies CollectionConfig;
