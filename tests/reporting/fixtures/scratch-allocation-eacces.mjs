/** Test-only: make the second allocation fail through actual POSIX permissions. */
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';

const mkdtemp = fs.mkdtemp;
fs.mkdtemp = async (prefix, options) => {
  if (prefix !== join(process.env.CLI_SCRATCH_DIR, 'cli-tmp-')) return mkdtemp(prefix, options);
  // HOME already exists. Restore owned-root permissions before caller cleanup.
  await fs.chmod(process.env.CLI_SCRATCH_DIR, 0o500);
  try { return await mkdtemp(prefix, options); }
  finally { await fs.chmod(process.env.CLI_SCRATCH_DIR, 0o700); }
};
syncBuiltinESMExports();
