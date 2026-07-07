'use client'

import { useState } from 'react'

export function CopyCommand({
  command,
  className = '',
}: {
  command: string
  className?: string
}) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard unavailable — no-op
    }
  }

  return (
    <div
      className={`flex items-center justify-between gap-4 rounded-lg bg-white/5 px-4 py-3 font-mono text-sm text-gray-300 ring-1 ring-white/10 ${className}`}
    >
      <code className="truncate">
        <span className="select-none text-gray-500">$ </span>
        {command}
      </code>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? 'Copied' : 'Copy command'}
        className="-my-1 flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium text-gray-400 transition-colors hover:bg-white/5 hover:text-white"
      >
        {copied ? (
          <>
            <svg viewBox="0 0 20 20" fill="currentColor" className="size-4 text-emerald-400">
              <path
                fillRule="evenodd"
                d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                clipRule="evenodd"
              />
            </svg>
            <span className="text-emerald-400">Copied</span>
          </>
        ) : (
          <>
            <svg viewBox="0 0 20 20" fill="currentColor" className="size-4">
              <path d="M7 3.5A1.5 1.5 0 0 1 8.5 2h3.879a1.5 1.5 0 0 1 1.06.44l3.122 3.12A1.5 1.5 0 0 1 17 6.622V12.5a1.5 1.5 0 0 1-1.5 1.5h-1v-3.379a3 3 0 0 0-.879-2.121L10.5 5.379A3 3 0 0 0 8.379 4.5H7v-1Z" />
              <path d="M4.5 6A1.5 1.5 0 0 0 3 7.5v9A1.5 1.5 0 0 0 4.5 18h7a1.5 1.5 0 0 0 1.5-1.5v-5.879a1.5 1.5 0 0 0-.44-1.06L9.44 6.439A1.5 1.5 0 0 0 8.378 6H4.5Z" />
            </svg>
            <span>Copy</span>
          </>
        )}
      </button>
    </div>
  )
}
