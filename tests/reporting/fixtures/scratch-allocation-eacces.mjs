/** Test-only OS allocation boundary. Production never preloads this fixture. */
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';

// Controlled fixture mode exercises the UID-0 branch on ordinary hosted runners.
// Only this disposable fixture process changes getuid; production is untouched.
const nativeGetuid = process.getuid;
if (process.env.SCRATCH_TEST_UID_ZERO === '1') process.getuid = () => 0;
const uidZero = process.getuid?.() === 0;
process.getuid = nativeGetuid; // Consumer intake must retain the actual owner UID.
const allocation = process.env.SCRATCH_FAIL_ALLOCATION === 'first' ? 'cli-home-' : 'cli-tmp-';
const mkdtemp = fs.mkdtemp;
fs.mkdtemp = async (prefix, options) => {
  if (prefix !== join(process.env.CLI_SCRATCH_DIR, allocation)) return mkdtemp(prefix, options);
  if (uidZero) {
    // CAP_DAC_OVERRIDE can bypass chmod(0500). Inject the native error at the
    // allocation boundary, never simulate a CLI exit or change host privileges.
    console.error('Test-only boundary: synthetic UID 0 allocation EACCES (permission bypass)');
    throw Object.assign(new Error('EACCES: permission denied, mkdtemp'), { code: 'EACCES', syscall: 'mkdtemp' });
  }
  console.error('Test-only boundary: real POSIX allocation EACCES');
  // Mutate only this fixture-owned root, restoring before caller cleanup.
  await fs.chmod(process.env.CLI_SCRATCH_DIR, 0o500);
  try { return await mkdtemp(prefix, options); }
  finally { await fs.chmod(process.env.CLI_SCRATCH_DIR, 0o700); }
};
syncBuiltinESMExports();
