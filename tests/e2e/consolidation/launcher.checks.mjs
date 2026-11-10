import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const cli = fileURLToPath(new URL('../../../node_modules/playwright/cli.js', import.meta.url))

test('installed primary Playwright package declares the resolved CLI', () => {
  const pkg = JSON.parse(readFileSync(new URL('../../../node_modules/playwright/package.json', import.meta.url), 'utf8'))
  assert.equal(pkg.bin.playwright, 'cli.js')
  assert.match(execFileSync(process.execPath, [cli, '--version'], { encoding: 'utf8' }), new RegExp(pkg.version.replaceAll('.', '\\.')))
})

test('selection launcher uses Node and the primary CLI with original arguments and environment', () => {
  const result = execFileSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import childProcess from 'node:child_process';
    import { syncBuiltinESMExports } from 'node:module';
    const calls = [];
    childProcess.execFileSync = (binary, args, options) => {
      calls.push({ binary, args, options });
      throw new Error('captured launcher');
    };
    syncBuiltinESMExports();
    try { await import(${JSON.stringify(new URL('./selection-guard.mjs', import.meta.url).href)}); }
    catch (error) { assert.equal(error.message, 'captured launcher'); }
    assert.equal(calls.length, 1);
    const { binary, args, options } = calls[0];
    assert.equal(binary, process.execPath);
    assert.deepEqual(args, [${JSON.stringify(cli)}, 'test', '--config=tests/playwright.smoke.config.ts', '--list', '--reporter=json']);
    for (const key of ['CI', 'BASE_URL', 'E2E_REUSE_SERVER', 'PLAYWRIGHT_STATS_API_KEY']) assert.equal(options.env[key], undefined);
    assert.equal(options.env.PATH, process.env.PATH);
    assert.equal(options.encoding, 'utf8');
    assert.equal(options.maxBuffer, 20_000_000);
    process.stdout.write('launcher verified');
  `], { cwd: root, encoding: 'utf8', env: { ...process.env, CI: '1', BASE_URL: 'https://remote.invalid', E2E_REUSE_SERVER: '1', PLAYWRIGHT_STATS_API_KEY: 'unused-test-marker' } })
  assert.equal(result, 'launcher verified')
})
