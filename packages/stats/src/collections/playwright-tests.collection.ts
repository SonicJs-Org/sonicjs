/**
 * Playwright Tests Collection
 *
 * Stores one row per test result per run, including retry information.
 */
import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "playwright_tests",
  displayName: "Playwright Tests",
  description: "Individual Playwright test results per run",
  icon: "🧪",

  schema: {
    type: "object",
    properties: {
      run_id: {
        type: "string",
        title: "Run ID",
        required: true,
        maxLength: 200,
        helpText: "FK to playwright_runs",
      },
      test_id: {
        type: "string",
        title: "Test ID",
        maxLength: 500,
        helpText: "Playwright stable test ID (consistent across runs)",
      },
      test_title: {
        type: "string",
        title: "Test Title",
        maxLength: 500,
      },
      test_file: {
        type: "string",
        title: "Test File",
        maxLength: 300,
      },
      project_name: {
        type: "string",
        title: "Playwright Project",
        maxLength: 100,
        helpText: "e.g. chromium, firefox, webkit",
      },
      status: {
        type: "select",
        title: "Status",
        required: true,
        enum: ["passed", "failed", "skipped", "timedOut", "interrupted"],
        enumLabels: ["Passed", "Failed", "Skipped", "Timed Out", "Interrupted"],
      },
      duration_ms: { type: "number", title: "Duration (ms)" },
      retry: {
        type: "number",
        title: "Retry Attempt",
        helpText: "0 = first attempt, 1 = first retry, etc.",
      },
      is_flaky: {
        type: "boolean",
        title: "Is Flaky",
        helpText: "True if test failed on earlier attempt but passed on retry",
      },
      error_message: {
        type: "string",
        title: "Error Message",
        maxLength: 500,
      },
      error_snippet: {
        type: "string",
        title: "Error Snippet",
        maxLength: 300,
      },
    },
    required: ["run_id", "status"],
  },

  listFields: ["run_id", "test_title", "status", "duration_ms", "retry", "is_flaky"],
  searchFields: ["run_id", "test_id", "test_title", "test_file"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",
  managed: true,
  isActive: true,
} satisfies CollectionConfig;
