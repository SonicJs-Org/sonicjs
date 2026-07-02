/**
 * update-plugin.ts
 *
 * Downloads the latest version of a bundled plugin from the SonicJS starter
 * template on GitHub and overwrites the local copies.
 *
 * Usage:
 *   npx tsx scripts/update-plugin.ts [plugin-name]
 *   npx tsx scripts/update-plugin.ts example        # default
 *   npx tsx scripts/update-plugin.ts example --dry-run
 *
 * Why this exists:
 *   `create-sonicjs` scaffolds plugin source files into your project — they are
 *   your code, not a package dependency. Running `npm install` updates
 *   @sonicjs-cms/core but leaves the plugin files untouched. This script pulls
 *   the latest files from the canonical starter template on GitHub main and
 *   overwrites your local copies, giving you bug fixes and improvements without
 *   starting a fresh project.
 *
 * Caution:
 *   This overwrites the plugin files — commit or stash local changes first.
 *   Custom modifications you've made will be lost.
 */

import { writeFileSync, mkdirSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = join(__dirname, '..')

const GITHUB_RAW_BASE =
  'https://raw.githubusercontent.com/SonicJs-Org/sonicjs/main/packages/create-app/templates/starter/src/plugins'

// Map of plugin name → files relative to its plugin directory.
// Add new plugins here as they are added to the starter template.
const PLUGIN_MANIFEST: Record<string, string[]> = {
  example: [
    'index.ts',
    'routes/api.ts',
    'routes/admin.ts',
    'collections/moods.collection.ts',
  ],
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`)
  return res.text()
}

async function updatePlugin(pluginName: string, dryRun: boolean) {
  const files = PLUGIN_MANIFEST[pluginName]
  if (!files) {
    console.error(
      `Unknown plugin "${pluginName}". Available: ${Object.keys(PLUGIN_MANIFEST).join(', ')}`
    )
    process.exit(1)
  }

  console.log(
    `\n${dryRun ? '[dry-run] ' : ''}Updating plugin: ${pluginName} from SonicJS main branch\n`
  )

  for (const file of files) {
    const url = `${GITHUB_RAW_BASE}/${pluginName}/${file}`
    const localPath = join(PROJECT_ROOT, 'src', 'plugins', pluginName, file)

    process.stdout.write(`  fetching ${file} ... `)

    try {
      const content = await fetchText(url)
      if (!dryRun) {
        mkdirSync(dirname(localPath), { recursive: true })
        writeFileSync(localPath, content, 'utf8')
      }
      console.log('✓')
    } catch (err) {
      console.log('✗')
      console.error(`    Error: ${(err as Error).message}`)
      process.exit(1)
    }
  }

  console.log(
    `\n${dryRun ? '[dry-run] no files written — ' : ''}Done. ${files.length} file(s) updated.\n`
  )

  if (!dryRun) {
    console.log('Next steps:')
    console.log('  1. Review the changes:  git diff src/plugins/' + pluginName)
    console.log('  2. Run type check:      npm run type-check')
    console.log('  3. Commit if happy:     git add src/plugins/' + pluginName + ' && git commit -m "chore(plugins): update ' + pluginName + ' plugin"\n')
  }
}

const args = process.argv.slice(2)
const pluginName = args.find(a => !a.startsWith('--')) ?? 'example'
const dryRun = args.includes('--dry-run')

updatePlugin(pluginName, dryRun)
