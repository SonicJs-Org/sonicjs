import { constants } from 'node:fs';
import { writeFile, unlink, rename, open, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const recordPattern = /^[a-f0-9]{64}\.json$/;

/** Recognized records must never disappear through filtering or link traversal. */
export async function readLedgerFile(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.nlink !== 1) throw new Error('Delivery checkpoint/record must be a single-link regular file');
    return await file.readFile();
  } finally { await file.close(); }
}

/** Exact sorted inventory of durable record bytes, including all delivery states. */
export async function ledgerInventory(ledgerDir) {
  const records = [];
  for (const name of (await readdir(ledgerDir)).filter(name => recordPattern.test(name)).sort()) {
    const bytes = await readLedgerFile(join(ledgerDir, name));
    records.push({ name, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  return records;
}

/** Reject partial exports/restores, stale seals and unrecognized seal formats. */
export function verifyLedgerInventory(seal, records) {
  if (seal.version !== 2 || JSON.stringify(seal.records) !== JSON.stringify(records)) {
    throw new Error('Prior delivery checkpoint record inventory mismatch');
  }
}

/** Bind a persisted checkpoint to its exact identities and complete record set. */
function checkpoint(options, attempt, records) {
  return { version: 2, producerRunId: options.producerRunId, producerAttempt: options.producerAttempt,
    consumerRunId: options.consumerRunId, consumerAttempt: attempt, records };
}

/**
 * Require the previous consumer attempt's complete immutable ledger on rerun.
 * Verify before removing the seal; abrupt termination must not leave a retry seal.
 * Individual started/accepted/failed entries independently prevent resubmission.
 */
export async function beginDeliveryAttempt(options) {
  for (const key of ['producerRunId', 'producerAttempt', 'consumerRunId', 'consumerAttempt']) {
    if (!Number.isSafeInteger(options[key]) || options[key] <= 0) throw new Error('Invalid delivery attempt');
  }
  const path = join(options.ledgerDir, 'checkpoint.json');
  if (options.consumerAttempt > 1) {
    let prior;
    try { prior = JSON.parse(await readLedgerFile(path)); }
    catch { throw new Error('Prior delivery checkpoint unavailable; rerun blocked to prevent duplicate submission'); }
    const records = await ledgerInventory(options.ledgerDir);
    verifyLedgerInventory(prior, records);
    if (JSON.stringify(prior) !== JSON.stringify(checkpoint(options, options.consumerAttempt - 1, records))) throw new Error('Prior delivery checkpoint mismatch');
  }
  await unlink(path).catch(error => { if (error.code !== 'ENOENT') throw error; });
}

/** Seal only after normal control flow completes; preserve ledger on failure. */
export async function finishDeliveryAttempt(options) {
  const path = join(options.ledgerDir, 'checkpoint.json');
  const records = await ledgerInventory(options.ledgerDir);
  await writeFile(`${path}.new`, JSON.stringify(checkpoint(options, options.consumerAttempt, records)), { mode: 0o600 });
  await rename(`${path}.new`, path);
}
