import { isAbsolute } from 'node:path';
import { request } from 'node:https';
import { Socket } from 'node:net';
// Offline fakes must run behind transport denial even though production strips NODE_OPTIONS.
if (globalThis.fetch.name !== 'deny' || request.name !== 'deny' || Socket.prototype.connect.name !== 'deny') process.exit(6);
const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== 'upload' || args[1] !== '--project' || !['SonicJs/sonicjs', 'Configured/project'].includes(args[2]) || args[3] !== '--endpoint' || args[4] !== 'https://flakiness.io' || !isAbsolute(args[5])) process.exit(2);
if (process.env.NODE_OPTIONS || process.env.NODE_PATH || process.env.GITHUB_TOKEN || process.env.CLOUDFLARE_API_TOKEN || process.env.FLAKINESS_PROJECT) process.exit(3);
if (!isAbsolute(process.env.HOME) || !isAbsolute(process.env.TMPDIR) || process.cwd() !== process.env.TMPDIR) process.exit(4);

// Pinned SDK 3.6.0 initializes OIDC from these two variables alone. No ambient
// GitHub context, producer opt-out or network is needed for this offline contract.
const authKeys = Object.keys(process.env).filter(k => k.startsWith('FLAKINESS_') || k.startsWith('ACTIONS_') || k.startsWith('GITHUB_')).sort();
const expected = process.env.FLAKINESS_ACCESS_TOKEN ? ['FLAKINESS_ACCESS_TOKEN'] : ['ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL'];
if (JSON.stringify(authKeys) !== JSON.stringify(expected)) process.exit(5);
console.log(`https://flakiness.io/r/${args[2] === 'Configured/project' ? 'configured' : 'upload-command'}`);
