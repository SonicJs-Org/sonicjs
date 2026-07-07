'use client'

import Link from 'next/link'
import { useState } from 'react'

import { Button } from '@/components/Button'
import { Logo } from '@/components/Logo'
import { ThemeToggle } from '@/components/ThemeToggle'
import { VERSION } from '@/lib/version'

function GitHubIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true" {...props}>
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M10 1.667c-4.605 0-8.334 3.823-8.334 8.544 0 3.78 2.385 6.974 5.698 8.106.417.075.573-.182.573-.406 0-.203-.011-.875-.011-1.592-2.093.397-2.635-.522-2.802-1.002-.094-.246-.5-1.005-.854-1.207-.291-.16-.708-.556-.01-.567.656-.01 1.124.62 1.281.876.75 1.292 1.948.93 2.427.705.073-.555.291-.93.531-1.143-1.854-.213-3.791-.95-3.791-4.218 0-.929.322-1.698.854-2.296-.083-.214-.375-1.09.083-2.265 0 0 .698-.224 2.292.876a7.576 7.576 0 0 1 2.083-.288c.709 0 1.417.096 2.084.288 1.593-1.11 2.291-.875 2.291-.875.459 1.174.167 2.05.084 2.263.53.599.854 1.357.854 2.297 0 3.278-1.948 4.005-3.802 4.219.302.266.563.78.563 1.58 0 1.143-.011 2.061-.011 2.35 0 .224.156.491.573.405a8.365 8.365 0 0 0 4.11-3.116 8.707 8.707 0 0 0 1.567-4.99c0-4.721-3.73-8.545-8.334-8.545Z"
      />
    </svg>
  )
}

function DiscordIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true" {...props}>
      <path d="M16.238 4.515a14.842 14.842 0 0 0-3.664-1.136.055.055 0 0 0-.059.027 10.35 10.35 0 0 0-.456.938 13.702 13.702 0 0 0-4.115 0 9.479 9.479 0 0 0-.464-.938.058.058 0 0 0-.058-.027c-1.266.218-2.497.6-3.664 1.136a.052.052 0 0 0-.024.02C1.4 8.023.76 11.424 1.074 14.782a.062.062 0 0 0 .024.042 14.923 14.923 0 0 0 4.494 2.272.058.058 0 0 0 .064-.02c.346-.473.654-.972.92-1.496a.057.057 0 0 0-.032-.08 9.83 9.83 0 0 1-1.404-.669.058.058 0 0 1-.029-.046.058.058 0 0 1 .023-.05c.094-.07.189-.144.279-.218a.056.056 0 0 1 .058-.008c2.946 1.345 6.135 1.345 9.046 0a.056.056 0 0 1 .059.007c.09.074.184.149.28.22a.058.058 0 0 1 .023.049.059.059 0 0 1-.028.046 9.224 9.224 0 0 1-1.405.669.058.058 0 0 0-.033.033.056.056 0 0 0 .002.047c.27.523.58 1.022.92 1.495a.056.056 0 0 0 .062.021 14.878 14.878 0 0 0 4.502-2.272.055.055 0 0 0 .016-.018.056.056 0 0 0 .008-.023c.375-3.883-.63-7.256-2.662-10.246a.046.046 0 0 0-.023-.021Zm-9.223 8.221c-.887 0-1.618-.814-1.618-1.814s.717-1.814 1.618-1.814c.908 0 1.632.821 1.618 1.814 0 1-.717 1.814-1.618 1.814Zm5.981 0c-.887 0-1.618-.814-1.618-1.814s.717-1.814 1.618-1.814c.908 0 1.632.821 1.618 1.814 0 1-.71 1.814-1.618 1.814Z" />
    </svg>
  )
}

const navLinks = [
  { href: '/quickstart', label: 'Docs' },
  { href: '/blog', label: 'Blog' },
  { href: '/compare', label: 'Compare' },
]

export function MarketingNav() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header
      className="sticky top-0 z-50 border-b border-zinc-900/10 bg-white/90 backdrop-blur-sm dark:border-white/10 dark:bg-zinc-900/90"
      data-marketing-nav
    >
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Logo + version */}
        <div className="flex items-center gap-3">
          <Link href="/" aria-label="SonicJS Home">
            <Logo className="h-6" />
          </Link>
          <span className="inline-flex items-center rounded-md bg-pink-50 px-2 py-1 text-xs font-medium text-pink-700 ring-1 ring-inset ring-pink-700/10 dark:bg-pink-500/10 dark:text-pink-300 dark:ring-pink-400/20">
            v{VERSION}
          </span>
        </div>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-8 md:flex">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="text-sm font-medium text-zinc-600 transition hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white"
            >
              {link.label}
            </Link>
          ))}
          <Link
            href="https://github.com/lane711/sonicjs"
            target="_blank"
            rel="noopener noreferrer"
            className="group"
            aria-label="GitHub"
          >
            <GitHubIcon className="h-5 w-5 fill-zinc-600 transition group-hover:fill-zinc-900 dark:fill-zinc-400 dark:group-hover:fill-white" />
          </Link>
          <Link
            href="https://discord.gg/8bMy6bv3sZ"
            target="_blank"
            rel="noopener noreferrer"
            className="group"
            aria-label="Discord"
          >
            <DiscordIcon className="h-5 w-5 fill-zinc-600 transition group-hover:fill-zinc-900 dark:fill-zinc-400 dark:group-hover:fill-white" />
          </Link>
        </nav>

        {/* Right: CTA + theme */}
        <div className="flex items-center gap-4">
          <ThemeToggle />
          <Button href="/quickstart" className="hidden sm:inline-flex">
            Getting Started
          </Button>
          {/* Mobile hamburger */}
          <button
            type="button"
            className="inline-flex items-center justify-center rounded-md p-2 text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 md:hidden dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-white"
            aria-label="Toggle menu"
            onClick={() => setMobileOpen((v) => !v)}
          >
            {mobileOpen ? (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="border-t border-zinc-900/10 bg-white px-4 pb-4 dark:border-white/10 dark:bg-zinc-900 md:hidden">
          <nav className="flex flex-col gap-1 pt-2">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="rounded-md px-3 py-2 text-sm font-medium text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-white"
                onClick={() => setMobileOpen(false)}
              >
                {link.label}
              </Link>
            ))}
            <div className="mt-2 flex items-center gap-4 px-3 py-2">
              <Link
                href="https://github.com/lane711/sonicjs"
                target="_blank"
                rel="noopener noreferrer"
                className="group"
                aria-label="GitHub"
              >
                <GitHubIcon className="h-5 w-5 fill-zinc-600 group-hover:fill-zinc-900 dark:fill-zinc-400 dark:group-hover:fill-white" />
              </Link>
              <Link
                href="https://discord.gg/8bMy6bv3sZ"
                target="_blank"
                rel="noopener noreferrer"
                className="group"
                aria-label="Discord"
              >
                <DiscordIcon className="h-5 w-5 fill-zinc-600 group-hover:fill-zinc-900 dark:fill-zinc-400 dark:group-hover:fill-white" />
              </Link>
            </div>
            <div className="mt-2 px-3">
              <Button href="/quickstart" className="w-full justify-center">
                Getting Started
              </Button>
            </div>
          </nav>
        </div>
      )}
    </header>
  )
}
