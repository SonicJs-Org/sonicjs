'use client'

import clsx from 'clsx'
import { AnimatePresence, motion, useIsPresent } from 'framer-motion'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useRef } from 'react'

import { Button } from '@/components/Button'
import { useIsInsideMobileNavigation } from '@/components/MobileNavigation'
import { useSectionStore } from '@/components/SectionProvider'
import { Tag } from '@/components/Tag'
import { remToPx } from '@/lib/remToPx'
import { CloseButton } from '@headlessui/react'

interface NavGroup {
  title: string
  links: Array<{
    title: string
    href: string
  }>
}

function useInitialValue<T>(value: T, condition = true) {
  let initialValue = useRef(value).current
  return condition ? initialValue : value
}

function TopLevelNavItem({
  href,
  children,
}: {
  href: string
  children: React.ReactNode
}) {
  return (
    <li className="md:hidden">
      <CloseButton
        as={Link}
        href={href}
        className="block py-1 text-sm text-zinc-600 transition hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white"
      >
        {children}
      </CloseButton>
    </li>
  )
}

function NavLink({
  href,
  children,
  tag,
  active = false,
  isAnchorLink = false,
}: {
  href: string
  children: React.ReactNode
  tag?: string
  active?: boolean
  isAnchorLink?: boolean
}) {
  return (
    <CloseButton
      as={Link}
      href={href}
      aria-current={active ? 'page' : undefined}
      className={clsx(
        'flex justify-between gap-2 py-1 pr-3 text-sm transition',
        isAnchorLink ? 'pl-7' : 'pl-4',
        active
          ? 'text-zinc-900 dark:text-white'
          : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white',
      )}
    >
      <span className="truncate">{children}</span>
      {tag && (
        <Tag variant="small" color="zinc">
          {tag}
        </Tag>
      )}
    </CloseButton>
  )
}

function VisibleSectionHighlight({
  group,
  pathname,
}: {
  group: NavGroup
  pathname: string
}) {
  let [sections, visibleSections] = useInitialValue(
    [
      useSectionStore((s) => s.sections),
      useSectionStore((s) => s.visibleSections),
    ],
    useIsInsideMobileNavigation(),
  )

  let isPresent = useIsPresent()
  let firstVisibleSectionIndex = Math.max(
    0,
    [{ id: '_top' }, ...sections].findIndex(
      (section) => section.id === visibleSections[0],
    ),
  )
  let itemHeight = remToPx(2)
  let height = isPresent
    ? Math.max(1, visibleSections.length) * itemHeight
    : itemHeight
  let top =
    group.links.findIndex((link) => link.href === pathname) * itemHeight +
    firstVisibleSectionIndex * itemHeight

  return (
    <motion.div
      layout
      initial={{ opacity: 0 }}
      animate={{ opacity: 1, transition: { delay: 0.2 } }}
      exit={{ opacity: 0 }}
      className="absolute inset-x-0 top-0 bg-zinc-800/2.5 will-change-transform dark:bg-white/2.5"
      style={{ borderRadius: 8, height, top }}
    />
  )
}

function ActivePageMarker({
  group,
  pathname,
}: {
  group: NavGroup
  pathname: string
}) {
  let itemHeight = remToPx(2)
  let offset = remToPx(0.25)
  let activePageIndex = group.links.findIndex((link) => link.href === pathname)
  let top = offset + activePageIndex * itemHeight

  return (
    <motion.div
      layout
      className="absolute left-2 h-6 w-px bg-emerald-500"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1, transition: { delay: 0.2 } }}
      exit={{ opacity: 0 }}
      style={{ top }}
    />
  )
}

function NavigationGroup({
  group,
  className,
}: {
  group: NavGroup
  className?: string
}) {
  // If this is the mobile navigation then we always render the initial
  // state, so that the state does not change during the close animation.
  // The state will still update when we re-open (re-render) the navigation.
  let isInsideMobileNavigation = useIsInsideMobileNavigation()
  let [pathname, sections] = useInitialValue(
    [usePathname(), useSectionStore((s) => s.sections)],
    isInsideMobileNavigation,
  )

  let isActiveGroup =
    group.links.findIndex((link) => link.href === pathname) !== -1

  return (
    <li className={clsx('relative mt-6', className)}>
      <motion.h2
        layout="position"
        className="text-xs font-semibold text-zinc-900 dark:text-white"
      >
        {group.title}
      </motion.h2>
      <div className="relative mt-3 pl-2">
        <AnimatePresence initial={!isInsideMobileNavigation}>
          {isActiveGroup && (
            <VisibleSectionHighlight group={group} pathname={pathname} />
          )}
        </AnimatePresence>
        <motion.div
          layout
          className="absolute inset-y-0 left-2 w-px bg-zinc-900/10 dark:bg-white/5"
        />
        <AnimatePresence initial={false}>
          {isActiveGroup && (
            <ActivePageMarker group={group} pathname={pathname} />
          )}
        </AnimatePresence>
        <ul role="list" className="border-l border-transparent">
          {group.links.map((link) => (
            <motion.li key={link.href} layout="position" className="relative">
              <NavLink href={link.href} active={link.href === pathname}>
                {link.title}
              </NavLink>
              <AnimatePresence mode="popLayout" initial={false}>
                {link.href === pathname && sections.length > 0 && (
                  <motion.ul
                    role="list"
                    initial={{ opacity: 0 }}
                    animate={{
                      opacity: 1,
                      transition: { delay: 0.1 },
                    }}
                    exit={{
                      opacity: 0,
                      transition: { duration: 0.15 },
                    }}
                  >
                    {sections.map((section) => (
                      <li key={section.id}>
                        <NavLink
                          href={`${link.href}#${section.id}`}
                          tag={section.tag}
                          isAnchorLink
                        >
                          {section.title}
                        </NavLink>
                      </li>
                    ))}
                  </motion.ul>
                )}
              </AnimatePresence>
            </motion.li>
          ))}
        </ul>
      </div>
    </li>
  )
}

export const navigation: Array<NavGroup> = [
  {
    title: 'Getting Started',
    links: [
      { title: 'Introduction', href: '/' },
      { title: 'Quickstart', href: '/quickstart' },
    ],
  },
  {
    title: 'Core Concepts',
    links: [
      { title: 'Architecture', href: '/architecture' },
      { title: 'Collections', href: '/collections' },
      { title: 'Caching', href: '/caching' },
      { title: 'Authentication', href: '/authentication' },
    ],
  },
  {
    title: 'Developer Guide',
    links: [
      { title: 'API Reference', href: '/api' },
      { title: 'Database', href: '/database' },
      { title: 'Templating', href: '/templating' },
      { title: 'Routing & Middleware', href: '/routing' },
    ],
  },
  {
    title: 'Plugin System',
    links: [
      { title: 'Overview', href: '/plugins' },
      { title: 'Development Guide', href: '/plugins/development' },
      { title: 'Core Plugins', href: '/plugins/core' },
      { title: 'AI Search', href: '/plugins/ai-search' },
      { title: 'Analytics', href: '/plugins/analytics' },
      { title: 'Workflow', href: '/plugins/workflow' },
      { title: 'Stripe Subscriptions', href: '/plugins/stripe' },
      { title: 'Turnstile (Bot Protection)', href: '/plugins/turnstile' },
      { title: 'Email Templates', href: '/plugins/email-templates' },
    ],
  },
  {
    title: 'Reference',
    links: [
      { title: 'Configuration', href: '/configuration' },
      { title: 'Hook Reference', href: '/hooks' },
      { title: 'Field Types', href: '/field-types' },
      { title: 'Security', href: '/security' },
      { title: 'Troubleshooting', href: '/troubleshooting' },
    ],
  },
  {
    title: 'Deployment',
    links: [
      { title: 'Production Deployment', href: '/deployment' },
      { title: 'Testing', href: '/testing' },
    ],
  },
  {
    title: 'Integrations',
    links: [
      { title: 'Astro', href: '/integrations/astro' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { title: 'Blog', href: '/blog' },
      { title: 'Compare', href: '/compare' },
      { title: 'Roadmap', href: '/roadmap' },
      { title: 'Examples', href: '/examples' },
      { title: 'FAQ', href: '/faq' },
      { title: 'Changelog', href: '/changelog' },
      { title: 'Community', href: '/community' },
      { title: 'Sponsor', href: '/sponsor' },
      { title: 'Contributing', href: '/contributing' },
      { title: 'AI Agents', href: '/ai-agents' },
      { title: 'Coding Standards', href: '/coding-standards' },
      { title: 'Telemetry', href: '/telemetry' },
    ],
  },
]

export function Navigation(props: React.ComponentPropsWithoutRef<'nav'>) {
  return (
    <nav {...props}>
      <ul role="list">
        <TopLevelNavItem href="/">Documentation</TopLevelNavItem>
        <TopLevelNavItem href="https://github.com/lane711/sonicjs">GitHub</TopLevelNavItem>
        <TopLevelNavItem href="https://github.com/lane711/sonicjs/discussions">Community</TopLevelNavItem>
        <li className="relative mb-3">
          <a
            href="https://github.com/lane711/sonicjs"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-zinc-900 to-zinc-800 dark:from-zinc-800 dark:to-zinc-700 px-4 py-3 text-sm font-semibold text-white shadow-lg hover:shadow-xl transition-all hover:scale-105"
          >
            <span>🙏 Star</span>
            <span>⭐</span>
            <span>us on Github</span>
            <svg className="w-4 h-4 ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </li>
        {navigation.map((group, groupIndex) => (
          <NavigationGroup
            key={group.title}
            group={group}
            className={groupIndex === 0 ? 'md:mt-0' : ''}
          />
        ))}
        <li className="sticky bottom-0 z-10 mt-6 min-[416px]:hidden">
          <Button href="/quickstart" variant="filled" className="w-full">
            Get Started
          </Button>
        </li>
      </ul>
    </nav>
  )
}
