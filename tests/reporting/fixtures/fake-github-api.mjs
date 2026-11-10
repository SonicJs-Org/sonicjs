// Trusted subprocess fixture only. Production workflows never preload this module.
import { readFileSync } from 'node:fs';
const fixtures = JSON.parse(readFileSync(process.env.PUBLISH_API_FIXTURE, 'utf8'));
globalThis.fetch = async url => {
  const path = String(url).replace('https://api.github.com', '');
  if (!(path in fixtures)) throw new Error('Unexpected API access in offline publishing fixture');
  return { ok: true, json: async () => structuredClone(fixtures[path]) };
};
