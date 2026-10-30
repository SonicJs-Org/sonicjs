/**
 * Playwright Runs Collection
 *
 * Stores one row per Playwright CI/CD run with aggregated results.
 */
import type { CollectionConfig } from "@sonicjs-cms/core";

export default {
  name: "playwright_runs",
  displayName: "Playwright Runs",
  description: "CI/CD Playwright test run summaries",
  icon: "🎭",

  schema: {
    type: "object",
    properties: {
      run_id: {
        type: "string",
        title: "Run ID",
        required: true,
        maxLength: 200,
        helpText: "Unique identifier for this CI run",
      },
      project: {
        type: "string",
        title: "Project",
        maxLength: 100,
        helpText: "Project name (e.g. sonicjs)",
      },
      branch: {
        type: "string",
        title: "Branch",
        maxLength: 200,
      },
      commit_sha: {
        type: "string",
        title: "Commit SHA",
        maxLength: 40,
      },
      commit_message: {
        type: "string",
        title: "Commit Message",
        maxLength: 200,
      },
      ci_provider: {
        type: "string",
        title: "CI Provider",
        maxLength: 50,
      },
      ci_run_url: {
        type: "string",
        title: "CI Run URL",
        maxLength: 500,
      },
      triggered_by: {
        type: "string",
        title: "Triggered By",
        maxLength: 50,
      },
      total: { type: "number", title: "Total Tests" },
      passed: { type: "number", title: "Passed" },
      failed: { type: "number", title: "Failed" },
      skipped: { type: "number", title: "Skipped" },
      flaky: { type: "number", title: "Flaky" },
      duration_ms: { type: "number", title: "Duration (ms)" },
      started_at: { type: "string", title: "Started At" },
      finished_at: { type: "string", title: "Finished At" },
    },
    required: ["run_id"],
  },

  listFields: ["run_id", "branch", "total", "passed", "failed", "flaky", "started_at"],
  searchFields: ["run_id", "branch", "commit_sha"],
  defaultSort: "createdAt",
  defaultSortOrder: "desc",
  managed: true,
  isActive: true,
} satisfies CollectionConfig;
