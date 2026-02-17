#!/usr/bin/env npx tsx
/**
 * BEIR Benchmark Data Generator — Downloads datasets and uploads to KV
 *
 * Downloads BEIR benchmark datasets, parses them, and uploads corpus/queries/qrels
 * as JSON to Cloudflare KV for use by the Benchmark tab in the Search admin.
 *
 * Supported datasets:
 *   - scifact:  5,183 docs, 1,109 queries (scientific fact verification)
 *   - nfcorpus: 3,633 docs, 323 queries (biomedical IR)
 *   - fiqa:     57,638 docs, 648 queries (financial Q&A)
 *
 * Usage:
 *   npx tsx scripts/generate-benchmark-data.ts                    # all datasets
 *   npx tsx scripts/generate-benchmark-data.ts --dataset scifact  # single dataset
 *   npx tsx scripts/generate-benchmark-data.ts --dataset fiqa --subset  # subset only
 *
 * The KV namespace ID is read from wrangler.toml (CACHE_KV binding).
 *
 * License: BEIR datasets are CC BY-SA 4.0 or mixed per dataset.
 * Citation: Thakur et al., "BEIR: A Heterogeneous Benchmark for Zero-shot
 *           Evaluation of Information Retrieval Models", NeurIPS 2021
 */

import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'
import { createWriteStream } from 'fs'
import { pipeline } from 'stream/promises'
import { Readable } from 'stream'
import { execSync } from 'child_process'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// --- Dataset Configuration ---

interface DatasetConfig {
  id: string
  name: string
  url: string
  dirName: string // directory name inside the zip
}

const DATASETS: Record<string, DatasetConfig> = {
  scifact: {
    id: 'scifact',
    name: 'BEIR SciFact',
    url: 'https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip',
    dirName: 'scifact',
  },
  nfcorpus: {
    id: 'nfcorpus',
    name: 'BEIR NFCorpus',
    url: 'https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/nfcorpus.zip',
    dirName: 'nfcorpus',
  },
  fiqa: {
    id: 'fiqa',
    name: 'BEIR FiQA-2018',
    url: 'https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/fiqa.zip',
    dirName: 'fiqa',
  },
}

const TEMP_DIR = path.join(__dirname, '..', '.benchmark-temp')
const WRANGLER_TOML = path.join(__dirname, '..', '..', '..', 'my-sonicjs-app', 'wrangler.toml')

// --- CLI Args ---

const args = process.argv.slice(2)
const datasetArg = args.includes('--dataset')
  ? args[args.indexOf('--dataset') + 1]
  : null
const USE_SUBSET = args.includes('--subset')

// --- Types ---

interface CorpusDoc {
  _id: string
  title: string
  text: string
}

interface Query {
  _id: string
  text: string
}

interface Qrel {
  query_id: string
  doc_id: string
  score: number
}

// --- Helpers ---

function parseWranglerConfig(): { kvNamespaceId: string; accountId?: string } {
  let kvNamespaceId = ''
  let accountId = ''

  if (fs.existsSync(WRANGLER_TOML)) {
    const content = fs.readFileSync(WRANGLER_TOML, 'utf-8')
    const kvMatch = content.match(/binding\s*=\s*"CACHE_KV"\s*\n\s*id\s*=\s*"([^"]+)"/)
    if (kvMatch) kvNamespaceId = kvMatch[1]
    const accountMatch = content.match(/account_id\s*=\s*"([^"]+)"/)
    if (accountMatch) accountId = accountMatch[1]
  }

  // Environment variable overrides
  if (process.env.KV_NAMESPACE_ID) kvNamespaceId = process.env.KV_NAMESPACE_ID
  if (process.env.CLOUDFLARE_ACCOUNT_ID) accountId = process.env.CLOUDFLARE_ACCOUNT_ID

  if (!kvNamespaceId) {
    throw new Error(
      'Could not find KV namespace ID. Ensure wrangler.toml has a CACHE_KV binding or set KV_NAMESPACE_ID env var.'
    )
  }

  return { kvNamespaceId, accountId: accountId || undefined }
}

async function downloadFile(url: string, destPath: string): Promise<void> {
  console.log(`  Downloading ${url}...`)
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status} ${response.statusText}`)
  }

  const fileStream = createWriteStream(destPath)
  const body = response.body
  if (!body) throw new Error('No response body')

  const nodeStream = Readable.fromWeb(body as any)
  await pipeline(nodeStream, fileStream)

  const stats = fs.statSync(destPath)
  console.log(`  Downloaded ${(stats.size / 1024 / 1024).toFixed(1)}MB`)
}

function unzipFile(zipPath: string, destDir: string): void {
  console.log(`  Extracting...`)
  execSync(`unzip -o "${zipPath}" -d "${destDir}"`, { stdio: 'pipe' })
}

function parseJSONL<T>(filePath: string): T[] {
  const content = fs.readFileSync(filePath, 'utf-8')
  const lines = content.trim().split('\n').filter((line) => line.trim())
  return lines.map((line) => JSON.parse(line) as T)
}

function parseQrelsTSV(filePath: string): Qrel[] {
  const content = fs.readFileSync(filePath, 'utf-8')
  const lines = content.trim().split('\n')
  const qrels: Qrel[] = []

  for (const line of lines) {
    if (line.startsWith('query-id') || line.startsWith('query_id')) continue
    const parts = line.split('\t')
    if (parts.length >= 3) {
      qrels.push({
        query_id: parts[0].trim(),
        doc_id: parts[1].trim(),
        score: parseInt(parts[2].trim(), 10),
      })
    }
  }

  return qrels
}

const KV_MAX_BYTES = 25 * 1024 * 1024 // 25 MiB per KV value

function uploadSingleKV(namespaceId: string, key: string, jsonPath: string, accountId?: string): void {
  const envPrefix = accountId ? `CLOUDFLARE_ACCOUNT_ID="${accountId}" ` : ''
  execSync(
    `${envPrefix}npx wrangler kv key put "${key}" --namespace-id="${namespaceId}" --path="${jsonPath}" --remote`,
    { stdio: 'inherit', shell: '/bin/bash' }
  )
}

/**
 * Upload data to KV. If the JSON exceeds 25 MiB, automatically split the
 * array into multiple chunk keys and write a metadata key so the Worker
 * can reassemble them.
 *
 * Single value:  key -> JSON array
 * Chunked:       key:meta -> { chunks: N, total: M }
 *                key:0    -> first slice
 *                key:1    -> second slice
 *                ...
 */
function uploadToKV(namespaceId: string, key: string, data: any, accountId?: string): void {
  const jsonPath = path.join(TEMP_DIR, `${key.replace(/:/g, '_')}.json`)
  fs.writeFileSync(jsonPath, JSON.stringify(data))
  const stats = fs.statSync(jsonPath)
  const sizeMB = (stats.size / 1024 / 1024).toFixed(1)

  if (stats.size <= KV_MAX_BYTES) {
    // Fits in a single key
    console.log(`  Uploading ${key} (${sizeMB}MB)...`)
    uploadSingleKV(namespaceId, key, jsonPath, accountId)
    return
  }

  // Too large — split array into chunks
  if (!Array.isArray(data)) {
    throw new Error(`KV value too large and not an array: ${key} is ${sizeMB}MB (max 25MB)`)
  }

  console.log(`  ${key} is ${sizeMB}MB — splitting into chunks...`)

  // Binary search for chunk size: find how many items fit in ~20 MiB (with margin)
  const targetChunkBytes = 20 * 1024 * 1024 // 20 MiB target per chunk (safe margin)
  const totalItems = data.length
  const avgItemBytes = stats.size / totalItems
  const itemsPerChunk = Math.floor(targetChunkBytes / avgItemBytes)

  let chunkIndex = 0
  let offset = 0

  while (offset < totalItems) {
    const slice = data.slice(offset, offset + itemsPerChunk)
    const chunkKey = `${key}:${chunkIndex}`
    const chunkPath = path.join(TEMP_DIR, `${chunkKey.replace(/:/g, '_')}.json`)
    fs.writeFileSync(chunkPath, JSON.stringify(slice))
    const chunkStats = fs.statSync(chunkPath)
    const chunkMB = (chunkStats.size / 1024 / 1024).toFixed(1)

    if (chunkStats.size > KV_MAX_BYTES) {
      throw new Error(`Chunk ${chunkKey} is still ${chunkMB}MB after splitting. Reduce itemsPerChunk.`)
    }

    console.log(`  Uploading ${chunkKey} (${chunkMB}MB, ${slice.length} items)...`)
    uploadSingleKV(namespaceId, chunkKey, chunkPath, accountId)

    offset += itemsPerChunk
    chunkIndex++
  }

  // Write metadata key so the Worker knows how to reassemble
  const metaKey = `${key}:meta`
  const metaPath = path.join(TEMP_DIR, `${metaKey.replace(/:/g, '_')}.json`)
  const meta = { chunks: chunkIndex, total: totalItems }
  fs.writeFileSync(metaPath, JSON.stringify(meta))
  console.log(`  Uploading ${metaKey} (${chunkIndex} chunks, ${totalItems} items total)...`)
  uploadSingleKV(namespaceId, metaKey, metaPath, accountId)

  // Delete the old single key if it exists (cleanup from previous subset upload)
  try {
    const envPrefix = accountId ? `CLOUDFLARE_ACCOUNT_ID="${accountId}" ` : ''
    execSync(
      `echo y | ${envPrefix}npx wrangler kv key delete "${key}" --namespace-id="${namespaceId}" --remote`,
      { stdio: 'pipe', shell: '/bin/bash' }
    )
    console.log(`  Cleaned up old single key: ${key}`)
  } catch {
    // Key didn't exist, that's fine
  }
}

function applySubset(corpus: CorpusDoc[], qrels: Qrel[]): CorpusDoc[] {
  const relevantDocIds = new Set(qrels.map((qr) => qr.doc_id))
  const relevantDocs = corpus.filter((doc) => relevantDocIds.has(doc._id))
  // Deterministic noise: sorted by ID, take first 200 non-relevant
  const noiseDocs = corpus
    .filter((doc) => !relevantDocIds.has(doc._id))
    .slice(0, 200)
  return [...relevantDocs, ...noiseDocs]
}

// --- Main ---

async function processDataset(config: DatasetConfig, namespaceId: string, accountId?: string): Promise<void> {
  console.log(`\n=== ${config.name} (${config.id}) ===`)

  const zipPath = path.join(TEMP_DIR, `${config.id}.zip`)
  const extractDir = TEMP_DIR
  const datasetDir = path.join(extractDir, config.dirName)

  // Download if not cached
  if (!fs.existsSync(zipPath)) {
    await downloadFile(config.url, zipPath)
  } else {
    console.log('  Using cached download')
  }

  // Extract if not cached
  if (!fs.existsSync(datasetDir)) {
    unzipFile(zipPath, extractDir)
  } else {
    console.log('  Using cached extraction')
  }

  // Parse files
  console.log('  Parsing...')

  const corpusPath = path.join(datasetDir, 'corpus.jsonl')
  const queriesPath = path.join(datasetDir, 'queries.jsonl')
  // qrels might be in qrels/test.tsv or qrels/dev.tsv
  let qrelsPath = path.join(datasetDir, 'qrels', 'test.tsv')
  if (!fs.existsSync(qrelsPath)) {
    qrelsPath = path.join(datasetDir, 'qrels', 'dev.tsv')
  }

  if (!fs.existsSync(corpusPath)) throw new Error(`corpus.jsonl not found at ${corpusPath}`)
  if (!fs.existsSync(queriesPath)) throw new Error(`queries.jsonl not found at ${queriesPath}`)
  if (!fs.existsSync(qrelsPath)) throw new Error(`qrels not found at ${qrelsPath}`)

  let corpus = parseJSONL<CorpusDoc>(corpusPath)
  const queries = parseJSONL<Query>(queriesPath)
  const qrels = parseQrelsTSV(qrelsPath)

  console.log(`  Corpus: ${corpus.length.toLocaleString()} documents`)
  console.log(`  Queries: ${queries.length.toLocaleString()}`)
  console.log(`  Qrels: ${qrels.length.toLocaleString()}`)

  // Apply subset if requested
  if (USE_SUBSET) {
    const relevantDocIds = new Set(qrels.map((qr) => qr.doc_id))
    console.log(`  Applying subset filter (${relevantDocIds.size} relevant + 200 noise)...`)
    corpus = applySubset(corpus, qrels)
    console.log(`  Subset: ${corpus.length.toLocaleString()} documents`)
  }

  // Upload to KV
  console.log('  Uploading to KV...')
  uploadToKV(namespaceId, `benchmark:${config.id}:corpus`, corpus, accountId)
  uploadToKV(namespaceId, `benchmark:${config.id}:queries`, queries, accountId)
  uploadToKV(namespaceId, `benchmark:${config.id}:qrels`, qrels, accountId)

  console.log(`  Done: ${config.name}`)
}

async function main(): Promise<void> {
  console.log('=== BEIR Benchmark Data Generator (KV Upload) ===')
  console.log(`Mode: ${USE_SUBSET ? 'Subset (relevant + noise)' : 'Full dataset'}`)

  // Determine KV namespace and account
  const { kvNamespaceId: namespaceId, accountId } = parseWranglerConfig()
  console.log(`KV namespace: ${namespaceId}`)
  if (accountId) console.log(`Account ID: ${accountId}`)

  // Create temp directory
  if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true })
  }

  // Determine which datasets to process
  const datasetsToProcess = datasetArg
    ? [DATASETS[datasetArg]]
    : Object.values(DATASETS)

  if (datasetArg && !DATASETS[datasetArg]) {
    console.error(`Unknown dataset: ${datasetArg}`)
    console.error(`Available: ${Object.keys(DATASETS).join(', ')}`)
    process.exit(1)
  }

  // Process each dataset
  for (const config of datasetsToProcess) {
    await processDataset(config, namespaceId, accountId)
  }

  // Cleanup
  console.log('\nCleaning up temp files...')
  fs.rmSync(TEMP_DIR, { recursive: true, force: true })

  console.log('\nAll done! Datasets uploaded to KV.')
  console.log('No rebuild needed — the Worker fetches data from KV on demand.')
}

main().catch((error) => {
  console.error('Error:', error)
  process.exit(1)
})
