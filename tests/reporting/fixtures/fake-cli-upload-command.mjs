import { isAbsolute } from 'node:path';
const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== 'upload' || args[1] !== '--project' || !['SonicJs/sonicjs', 'Configured/project'].includes(args[2]) || args[3] !== '--endpoint' || args[4] !== 'https://flakiness.io' || !isAbsolute(args[5])) process.exit(2);
if (process.env.NODE_OPTIONS || process.env.NODE_PATH || process.env.GITHUB_TOKEN || process.env.CLOUDFLARE_API_TOKEN || process.env.FLAKINESS_PROJECT) process.exit(3);
if (!isAbsolute(process.env.HOME) || !isAbsolute(process.env.TMPDIR) || process.cwd() !== process.env.TMPDIR) process.exit(4);
console.log(`https://flakiness.io/r/${args[2] === 'Configured/project' ? 'configured' : 'upload-command'}`);
