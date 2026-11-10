/** Export durable records only; credential-bearing scratch is never an artifact. */
import { readdir, mkdir, mkdtemp, rm, realpath, lstat, writeFile, rename } from 'node:fs/promises';
import { join, resolve, relative, isAbsolute, sep, dirname, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readLedgerFile, ledgerInventory, verifyLedgerInventory } from './delivery-ledger.mjs';

/**
 * Fresh flat export, not a recursive copy. Reject unsafe recognized records; ignore
 * checkpoint temporary writes and unknown names. Source records remain intact.
 * @param {string} ledgerDir
 * @param {string} exportDir
 */
export async function exportDeliveryLedger(ledgerDir, exportDir) {
  const source = await realpath(ledgerDir);
  const exportPath = resolve(exportDir);
  await mkdir(dirname(exportPath), { recursive: true, mode: 0o700 });
  const parent = await realpath(dirname(exportPath));
  const target = join(parent, basename(exportPath));
  const overlaps = (a, b) => { const rel = relative(a, b); return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`)); };
  if (overlaps(source, target) || overlaps(target, source)) throw new Error('Ledger export must be separate from ledger');
  const existing = await lstat(target).catch(error => { if (error.code !== 'ENOENT') throw error; });
  if (existing?.isSymbolicLink()) throw new Error('Ledger export cannot be a symlink');
  await rm(target, { recursive: true, force: true });
  // Publish the whole filtered directory atomically. A killed/failed exporter
  // must never expose a checkpoint without all delivery records beside it.
  const staged = await mkdtemp(join(parent, '.ledger-export-'));
  try {
    for (const name of await readdir(source)) {
      if (!/^(?:checkpoint|[a-f0-9]{64})\.json$/.test(name)) continue;
      // Any error on a recognized name invalidates the entire export, including
      // nonregular entries, symlinks and hardlinks; never silently drop history.
      await writeFile(join(staged, name), await readLedgerFile(join(source, name)), { flag: 'wx', mode: 0o600 });
    }
    const seal = await readLedgerFile(join(staged, 'checkpoint.json')).catch(error => {
      if (error.code !== 'ENOENT') throw error;
    });
    if (seal) verifyLedgerInventory(JSON.parse(seal), await ledgerInventory(staged));
    await rename(staged, target);
  } finally { await rm(staged, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (!process.env.LEDGER_DIR || !process.env.LEDGER_EXPORT_DIR) throw new Error('Ledger source and export directories required');
  await exportDeliveryLedger(process.env.LEDGER_DIR, process.env.LEDGER_EXPORT_DIR);
}
