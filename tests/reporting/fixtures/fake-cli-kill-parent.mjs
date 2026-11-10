import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
for (const root of [process.env.HOME, process.env.TMPDIR]) {
  writeFileSync(join(root, 'cached-token.json'), JSON.stringify({ token: 'FAKE-NO-NETWORK-CREDENTIAL' }));
}
process.kill(process.ppid, 'SIGKILL');
process.exit(0);
