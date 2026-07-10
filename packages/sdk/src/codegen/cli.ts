import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { fetchSchemaFromUrl, fetchSchemaFromConfig } from './fetch-schema'
import { emitCollections } from './emit'

function getArg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag)
  return i !== -1 ? args[i + 1] : undefined
}

async function main(): Promise<void> {
  const args = process.argv.slice(2)

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: sonicjs-sdk codegen [options]

Options:
  --url <cms-url>         Base URL of the SonicJS instance (e.g. https://cms.example.com)
  --api-key <sk_...>      API key for authenticated /api/collections access
  --out <file>            Output path for generated types (default: sonicjs.d.ts)
  --from-config <path>    Use a local collection config file instead of a live instance

Examples:
  sonicjs-sdk codegen --url https://cms.example.com --api-key sk_xxx --out src/sonicjs.d.ts
  sonicjs-sdk codegen --from-config ./collections.ts --out src/sonicjs.d.ts
`.trim())
    process.exit(0)
  }

  const url = getArg(args, '--url')
  const apiKey = getArg(args, '--api-key')
  const out = getArg(args, '--out') ?? 'sonicjs.d.ts'
  const fromConfig = getArg(args, '--from-config')

  if (!url && !fromConfig) {
    console.error('Error: provide --url <cms-url> or --from-config <path>')
    console.error('Run with --help for usage.')
    process.exit(1)
  }

  try {
    const collections = fromConfig
      ? await fetchSchemaFromConfig(fromConfig)
      : await fetchSchemaFromUrl(url!, apiKey)

    const output = emitCollections(collections)

    const outDir = dirname(out)
    if (outDir && outDir !== '.') mkdirSync(outDir, { recursive: true })
    writeFileSync(out, output, 'utf8')

    console.log(`✓ Generated ${collections.length} collection type${collections.length !== 1 ? 's' : ''} → ${out}`)
  } catch (e) {
    console.error(`Error: ${(e instanceof Error ? e.message : String(e))}`)
    process.exit(1)
  }
}

main()
