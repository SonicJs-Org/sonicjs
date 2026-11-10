import type { ArtifactSnapshots, ValidatedProducerProvenance, UploadSnapshot } from './validate-flakiness-artifacts.mjs';

export interface UploadConfig {
  /** Trusted workflow project slug. Never copied from artifact fields. */
  project?: string;
  /** Path to installed independent CLI runtime; resolved before the child changes cwd (must have node_modules/.bin/flakiness and package-lock.json). */
  runtimeDir: string;
  /** Absolute private path for durable ledger entries; must already exist and be outside any snapshot dir. */
  ledgerDir: string;
  /** Absolute caller-owned private scratch root, separate from ledgerDir (including symlinks). No system temp fallback. */
  privateScratchDir: string;
  /** Max milliseconds per CLI child. Defaults to 120000. Must be a positive finite number. */
  timeoutMs?: number;
}

export type UploadState =
  | 'validation-only'   // No CLI or auth attempted; returned when enableUpload is not true
  | 'blocked'           // Prior ledger state prevents re-upload (ambiguous, started, accepted-unverified, or content mismatch)
  | 'not-started'       // OS spawn error proves no child ran; sealed consumer rerun may retry identical content
  | 'failed'            // CLI exited non-zero; delivery not established; may have reached server; no automatic retry
  | 'ambiguous'         // Lost response or timeout; delivery status unknown; DO NOT retry automatically
  | 'accepted-unverified'; // CLI exited 0 with valid receipt URL; not independently verified

export interface UploadResult {
  invocationId: string;
  suite: 'core-unit' | 'cms-e2e';
  /** Repo/runId/runAttempt/jobId/suite/invocation — identity-based, not content-based. */
  logicalKey: string;
  state: UploadState;
  /** Only present on accepted-unverified; server-provided URL, not independently verified. */
  receiptUrl?: string;
  /** Safe diagnostic text; never contains credential values. */
  error?: string;
}

export interface UploadSummary {
  provenance: Readonly<{
    repository: string;
    runId: number;
    runAttempt: number;
    workflowId: number;
    /** Producer-reported SHA; passes through unchanged regardless of local git HEAD. */
    testedSha: string;
  }>;
  results: UploadResult[];
  anyAmbiguous: boolean;
  anyFailed: boolean;
}

/**
 * Validate-only: returns validation-only results for previously validated snapshots.
 * No auth, CLI, or ledger access; always safe to call.
 */
export function validateOnly(snapshots: ArtifactSnapshots): Promise<UploadSummary>;

/**
 * Execute upload with durable ledger.
 * Without options.enableUpload === true, behaves identically to validateOnly.
 * With enableUpload: verifies all snapshots before auth, writes atomic ledger entries,
 * spawns CLI with isolated env, and records partial/ambiguous/accepted-unverified state.
 *
 * NEVER retry an ambiguous or accepted-unverified result automatically.
 * Real reconciliation and delivery verification belong to Task 7.
 */
export function executeUpload(
  snapshots: ArtifactSnapshots,
  config: UploadConfig,
  auth: { accessToken: string } | { githubOidcUrl: string; githubOidcToken: string },
  options?: { enableUpload?: boolean }
): Promise<UploadSummary>;
