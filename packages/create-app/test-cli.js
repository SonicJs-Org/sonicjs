#!/usr/bin/env node

// Simple test script to verify the CLI works end-to-end
// This bypasses interactive prompts by passing a project name and using all flags

import { execa } from 'execa'
import fs from 'fs-extra'
import path from 'path'

const TEST_PROJECT = 'test-sonicjs-project'
const testDir = path.resolve(process.cwd(), TEST_PROJECT)

console.log('🧪 Testing create-sonicjs-app CLI\n')

async function cleanup() {
  if (fs.existsSync(testDir)) {
    console.log('🧹 Cleaning up previous test directory...')
    await fs.remove(testDir)
  }
}

async function runTest() {
  try {
    await cleanup()

    console.log('📦 Running create-sonicjs-app...')
    console.log(`   Command: node bin/create-sonicjs-app.js ${TEST_PROJECT}`)
    console.log('   Flags: --template=starter --database=test-db --bucket=test-media --include-example --skip-install --skip-git --skip-cloudflare\n')

    // Run the CLI with all flags to skip interactive prompts entirely
    const { stdout, stderr } = await execa('node', [
      'bin/create-sonicjs-app.js',
      TEST_PROJECT,
      '--template=starter',
      '--database=test-db',
      '--bucket=test-media',
      '--include-example',
      '--skip-install',
      '--skip-git',
      '--skip-cloudflare'
    ], {
      cwd: process.cwd(),
      timeout: 60000 // 60 second timeout
    })

    console.log(stdout)
    if (stderr) console.error('STDERR:', stderr)

    // Verify the project was created
    console.log('\n✅ Verifying project structure...')

    const checks = [
      'package.json',
      'wrangler.toml',
      'tsconfig.json',
      'src/index.ts',
      'src/collections/blog-posts.collection.ts',
      'README.md'
    ]

    let allPass = true
    for (const file of checks) {
      const filePath = path.join(testDir, file)
      const exists = fs.existsSync(filePath)
      console.log(`   ${exists ? '✓' : '✗'} ${file}`)
      if (!exists) allPass = false
    }

    // Verify package.json content
    const pkgJson = await fs.readJson(path.join(testDir, 'package.json'))
    console.log('\n📋 Verifying package.json...')
    console.log(`   Name: ${pkgJson.name} (expected: ${TEST_PROJECT})`)
    console.log(`   Private: ${pkgJson.private} (expected: true)`)
    console.log(`   Has @sonicjs-cms/core: ${!!pkgJson.dependencies['@sonicjs-cms/core']}`)

    // Verify wrangler.toml content
    const wranglerContent = await fs.readFile(path.join(testDir, 'wrangler.toml'), 'utf-8')
    console.log('\n⚙️  Verifying wrangler.toml...')
    const hasDb = wranglerContent.includes('database_name')
    const hasBucket = wranglerContent.includes('bucket_name')
    // CACHE_KV binding is required for the bootstrap fast-path — without it every
    // cold isolate re-runs the full D1 bootstrap and TTFB balloons to ~10s+.
    const hasCacheKv =
      wranglerContent.includes('binding = "CACHE_KV"') &&
      wranglerContent.includes('[[kv_namespaces]]')
    console.log(`   Has database config: ${hasDb}`)
    console.log(`   Has bucket config: ${hasBucket}`)
    console.log(`   ${hasCacheKv ? '✓' : '✗'} Has CACHE_KV binding`)
    if (!hasDb || !hasBucket || !hasCacheKv) allPass = false

    if (allPass) {
      console.log('\n✅ All checks passed!')
      console.log('\n🎉 CLI test successful!\n')
    } else {
      console.log('\n❌ Some checks failed\n')
      process.exit(1)
    }

    // Cleanup
    await cleanup()
    console.log('🧹 Cleaned up test directory\n')

  } catch (error) {
    console.error('\n❌ Test failed:', error.message)
    if (error.stdout) console.log('STDOUT:', error.stdout)
    if (error.stderr) console.error('STDERR:', error.stderr)
    await cleanup()
    process.exit(1)
  }
}

runTest()
