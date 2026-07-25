import { useState } from 'react'
import type { FilterState } from '../types'

interface Props {
  filters: FilterState
  page: number
  pageSize: number
}

function buildCode(filters: FilterState, page: number, pageSize: number): string {
  const whereLines: string[] = []
  if (filters.department) whereLines.push(`    department: { equals: '${filters.department}' },`)
  if (filters.region) whereLines.push(`    region: { equals: '${filters.region}' },`)

  const hasWhere = whereLines.length > 0
  const opts = [
    `  limit: ${pageSize},`,
    page > 0 ? `  offset: ${page * pageSize},` : null,
    hasWhere ? `  where: {` : null,
    ...whereLines,
    hasWhere ? `  },` : null,
  ].filter(Boolean).join('\n')

  return `import { createClient } from '@sonicjs-cms/sdk'

const sonic = createClient({
  url: 'https://cms.example.com',
  apiKey: process.env.SONICJS_API_KEY,
})

const { data, meta } = await sonic
  .collection('employees')
  .list({
${opts}
  })

console.log(\`Loaded \${meta.count} employees\`)`
}

export function CodeSnippet({ filters, page, pageSize }: Props) {
  const [copied, setCopied] = useState(false)
  const code = buildCode(filters, page, pageSize)

  const copy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/10">
        <span className="text-xs text-slate-400 font-medium">SDK Call</span>
        <button
          onClick={copy}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
        >
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 text-xs text-slate-300 overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}
