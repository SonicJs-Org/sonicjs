/**
 * Benchmark Dataset Registry
 *
 * Lightweight metadata for all supported BEIR benchmark datasets.
 * Actual corpus/query/qrel data lives in KV (CACHE_KV), not in the Worker bundle.
 *
 * To add a new dataset:
 * 1. Add an entry here
 * 2. Run: npx tsx scripts/generate-benchmark-data.ts --dataset <id>
 * 3. No rebuild needed — the Worker fetches data from KV on demand
 */

export interface DatasetInfo {
  id: string
  name: string
  description: string
  corpus_size: number
  query_count: number
  avg_qrels_per_query: number
  license: string
  /** If true, the KV data is a subset of the full corpus (relevant docs + noise) */
  subset?: boolean
}

export interface BenchmarkDocument {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- BEIR dataset schema uses _id
  _id: string
  title: string
  text: string
}

export interface BenchmarkQuery {
  // eslint-disable-next-line @typescript-eslint/naming-convention -- BEIR dataset schema uses _id
  _id: string
  text: string
}

export interface BenchmarkQrel {
  query_id: string
  doc_id: string
  score: number
}

export const BENCHMARK_DATASETS: DatasetInfo[] = [
  {
    id: 'scifact',
    name: 'BEIR SciFact',
    description: 'Scientific fact verification — abstracts from S2ORC',
    corpus_size: 5183,
    query_count: 1109,
    avg_qrels_per_query: 1.1,
    license: 'CC BY-SA 4.0',
  },
  {
    id: 'nfcorpus',
    name: 'BEIR NFCorpus',
    description: 'Bio-medical IR — NutritionFacts clinical documents',
    corpus_size: 3633,
    query_count: 323,
    avg_qrels_per_query: 38.2,
    license: 'Mixed (see dataset)',
  },
  {
    id: 'fiqa',
    name: 'BEIR FiQA-2018',
    description: 'Financial Q&A — opinion-based questions from StackExchange/Reddit',
    corpus_size: 57638,
    query_count: 648,
    avg_qrels_per_query: 2.6,
    license: 'Mixed (see dataset)',
  },
]
