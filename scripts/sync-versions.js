#!/usr/bin/env node

/**
 * Sync versions script
 *
 * This script syncs the @sonicjs-cms/core version across the monorepo:
 * 1. Reads the version from packages/core/package.json
 * 2. Updates the version in packages/create-app/src/cli.js
 * 3. Syncs the create-sonicjs package version to match core version
 * 4. Syncs the root package.json version to match core version
 * 5. Syncs the www documentation site version
 */

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const rootDir = path.join(__dirname, '..')
const rootPackageJsonPath = path.join(rootDir, 'package.json')
const corePackageJsonPath = path.join(rootDir, 'packages/core/package.json')
const sdkPackageJsonPath = path.join(rootDir, 'packages/sdk/package.json')
const createAppCliPath = path.join(rootDir, 'packages/create-app/src/cli.js')
const createAppPackageJsonPath = path.join(rootDir, 'packages/create-app/package.json')
const wwwVersionPath = path.join(rootDir, 'www/src/lib/version.ts')

async function syncVersions() {
  try {
    // Read core version
    const corePackageJson = JSON.parse(fs.readFileSync(corePackageJsonPath, 'utf8'))
    const coreVersion = corePackageJson.version

    console.log(`📦 Core version: ${coreVersion}`)

    // Update create-app CLI to use the new core version
    let cliContent = fs.readFileSync(createAppCliPath, 'utf8')
    const versionRegex = /'@sonicjs-cms\/core': '\^[\d.]+(-[\w.]+)?'/
    const newVersionString = `'@sonicjs-cms/core': '^${coreVersion}'`

    if (versionRegex.test(cliContent)) {
      cliContent = cliContent.replace(versionRegex, newVersionString)
      fs.writeFileSync(createAppCliPath, cliContent, 'utf8')
      console.log(`✓ Updated create-app CLI to use @sonicjs-cms/core@^${coreVersion}`)
    } else {
      console.warn('⚠ Could not find version string in CLI file to update')
    }

    // Sync SDK version to match core version
    if (fs.existsSync(sdkPackageJsonPath)) {
      const sdkPackageJson = JSON.parse(fs.readFileSync(sdkPackageJsonPath, 'utf8'))
      const oldSdkVersion = sdkPackageJson.version
      sdkPackageJson.version = coreVersion
      fs.writeFileSync(sdkPackageJsonPath, JSON.stringify(sdkPackageJson, null, 2) + '\n', 'utf8')
      console.log(`✓ Synced @sonicjs-cms/sdk from ${oldSdkVersion} to ${coreVersion}`)
    }

    // Sync create-sonicjs version to match core version
    const createAppPackageJson = JSON.parse(fs.readFileSync(createAppPackageJsonPath, 'utf8'))
    const oldCreateAppVersion = createAppPackageJson.version

    createAppPackageJson.version = coreVersion
    fs.writeFileSync(createAppPackageJsonPath, JSON.stringify(createAppPackageJson, null, 2) + '\n', 'utf8')

    console.log(`✓ Synced create-sonicjs from ${oldCreateAppVersion} to ${coreVersion}`)

    // Sync root package.json version to match core version
    const rootPackageJson = JSON.parse(fs.readFileSync(rootPackageJsonPath, 'utf8'))
    const oldRootVersion = rootPackageJson.version

    rootPackageJson.version = coreVersion
    fs.writeFileSync(rootPackageJsonPath, JSON.stringify(rootPackageJson, null, 2) + '\n', 'utf8')

    console.log(`✓ Synced root package.json from ${oldRootVersion} to ${coreVersion}`)

    // Sync www documentation site version
    if (fs.existsSync(wwwVersionPath)) {
      let wwwVersionContent = fs.readFileSync(wwwVersionPath, 'utf8')
      const wwwVersionRegex = /export const VERSION = '[^']+'/
      const newWwwVersionString = `export const VERSION = '${coreVersion}'`

      if (wwwVersionRegex.test(wwwVersionContent)) {
        wwwVersionContent = wwwVersionContent.replace(wwwVersionRegex, newWwwVersionString)
        fs.writeFileSync(wwwVersionPath, wwwVersionContent, 'utf8')
        console.log(`✓ Synced www documentation version to ${coreVersion}`)
      } else {
        console.warn('⚠ Could not find VERSION export in www/src/lib/version.ts')
      }
    } else {
      console.warn('⚠ www/src/lib/version.ts not found, skipping www version sync')
    }

    console.log('\n✅ Version sync complete!')
    console.log('\nNext steps:')
    console.log('  1. Review the changes: git diff')
    console.log('  2. Commit the version changes: git add . && git commit -m "chore: bump versions"')
    console.log('  3. Publish packages: npm run publish:all')
    console.log('  4. Create git tag: git tag v' + coreVersion)
    console.log('  5. Push changes: git push && git push --tags')

  } catch (error) {
    console.error('❌ Error syncing versions:', error)
    process.exit(1)
  }
}

syncVersions()
