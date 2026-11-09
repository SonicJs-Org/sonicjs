/**
 * Fake CLI: records argv and filtered env to ${HOME}/received.json, then prints a receipt URL.
 * Used by upload tests to assert arg isolation and env allowlist.
 */
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

const received = {
  argv: process.argv.slice(2), // skip node + script
  envKeys: Object.keys(process.env).sort(),
  home: process.env.HOME,
  tmpdir: process.env.TMPDIR,
  hasFlakinessVars: Object.keys(process.env).some(k => k.startsWith('FLAKINESS_') && k !== 'FLAKINESS_ACCESS_TOKEN' && k !== 'FLAKINESS_DISABLE_UPLOAD'),
  hasActionsOidcVars: Object.keys(process.env).some(k => k.startsWith('ACTIONS_ID_TOKEN_') && k !== 'ACTIONS_ID_TOKEN_REQUEST_URL' && k !== 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'),
  hasNodeOptions: 'NODE_OPTIONS' in process.env,
  hasNodePath: 'NODE_PATH' in process.env,
}
writeFileSync(join(process.env.HOME ?? '.', 'received.json'), JSON.stringify(received, null, 2))
console.log('[flakiness.io] ✓ Uploaded to https://flakiness.io/r/recorded-args')
