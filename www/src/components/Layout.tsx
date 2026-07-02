'use client'

import { motion } from 'framer-motion'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

import { Breadcrumbs } from '@/components/Breadcrumbs'
import { Footer } from '@/components/Footer'
import { MarketingFooter } from '@/components/MarketingFooter'
import { Header } from '@/components/Header'
import { Logo } from '@/components/Logo'
import { MarketingNav } from '@/components/MarketingNav'
import { Navigation } from '@/components/Navigation'
import { SectionProvider, type Section } from '@/components/SectionProvider'
import { VERSION } from '@/lib/version'

export function Layout({
  children,
  allSections,
}: {
  children: React.ReactNode
  allSections: Record<string, Array<Section>>
}) {
  let pathname = usePathname()

  if (pathname === '/') {
    return (
      <div className="flex min-h-full flex-col">
        <MarketingNav />
        <main className="flex-auto">{children}</main>
        <MarketingFooter />
      </div>
    )
  }

  return (
    <SectionProvider sections={allSections[pathname] ?? []}>
      <div className="h-full lg:ml-72 xl:ml-80">
        <motion.header
          layoutScroll
          className="contents lg:pointer-events-none lg:fixed lg:inset-0 lg:z-40 lg:flex"
        >
          <div className="contents lg:pointer-events-auto lg:block lg:w-72 lg:overflow-y-auto lg:border-r lg:border-zinc-900/10 lg:px-6 lg:pt-4 lg:pb-8 xl:w-80 lg:dark:border-white/10">
            <div className="hidden lg:flex lg:items-center lg:gap-3">
              <Link href="/" aria-label="Home">
                <Logo className="h-6" />
              </Link>
              <span className="inline-flex items-center rounded-md bg-pink-50 px-2 py-1 text-xs font-medium text-pink-700 ring-1 ring-inset ring-pink-700/10 dark:bg-pink-500/10 dark:text-pink-300 dark:ring-pink-400/20">
                v{VERSION}
              </span>
            </div>
            <Header />
            <Navigation className="hidden lg:mt-10 lg:block" />
          </div>
        </motion.header>
        <div className="relative flex h-full flex-col px-4 pt-14 sm:px-6 lg:px-8">
          <Breadcrumbs />
          <main className="flex-auto">{children}</main>
          <Footer />
        </div>
      </div>
    </SectionProvider>
  )
}
