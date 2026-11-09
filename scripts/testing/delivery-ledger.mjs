import { readFile, writeFile, unlink, rename } from 'node:fs/promises';
import { join } from 'node:path';

/** Bind a persisted checkpoint to its exact producer and consumer attempts. */
function checkpoint(options, attempt) {
  return { version: 1, producerRunId: options.producerRunId, producerAttempt: options.producerAttempt,
    consumerRunId: options.consumerRunId, consumerAttempt: attempt };
}

/**
 * Require the previous consumer attempt's immutable ledger artifact on rerun.
 * No artifact, incomplete checkpoint, or mismatched history means fail closed.
 * Remove the seal before any work so an abrupt termination cannot preserve a
 * stale safe-to-retry assertion. Individual started/accepted/failed entries
 * independently prevent resubmission, even after a completed checkpoint.
 */
export async function beginDeliveryAttempt(options) {
  for (const key of ['producerRunId', 'producerAttempt', 'consumerRunId', 'consumerAttempt']) {
    if (!Number.isSafeInteger(options[key]) || options[key] <= 0) throw new Error('Invalid delivery attempt');
  }
  const path = join(options.ledgerDir, 'checkpoint.json');
  if (options.consumerAttempt > 1) {
    let prior;
    try { prior = JSON.parse(await readFile(path, 'utf8')); }
    catch { throw new Error('Prior delivery checkpoint unavailable; rerun blocked to prevent duplicate submission'); }
    if (JSON.stringify(prior) !== JSON.stringify(checkpoint(options, options.consumerAttempt - 1))) throw new Error('Prior delivery checkpoint mismatch');
  }
  await unlink(path).catch(error => { if (error.code !== 'ENOENT') throw error; });
}

/** Seal only after normal control flow completes; always preserve ledger on failure. */
export async function finishDeliveryAttempt(options) {
  const path = join(options.ledgerDir, 'checkpoint.json');
  await writeFile(`${path}.new`, JSON.stringify(checkpoint(options, options.consumerAttempt)), { mode: 0o600 });
  await rename(`${path}.new`, path);
}
