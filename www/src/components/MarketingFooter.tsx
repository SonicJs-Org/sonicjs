import Link from 'next/link'

import { Logo } from '@/components/Logo'

const navigation = {
  product: [
    { name: 'Quickstart', href: '/quickstart' },
    { name: 'Compare', href: '/compare' },
    { name: 'Changelog', href: '/changelog' },
    { name: 'Plugins', href: '/plugins' },
    { name: 'Roadmap', href: '/roadmap' },
  ],
  docs: [
    { name: 'Introduction', href: '/introduction' },
    { name: 'Architecture', href: '/architecture' },
    { name: 'API Reference', href: '/api-reference' },
    { name: 'Deployment', href: '/deployment' },
    { name: 'Security', href: '/security' },
  ],
  community: [
    { name: 'GitHub', href: 'https://github.com/lane711/sonicjs' },
    { name: 'Discord', href: 'https://discord.gg/8bMy6bv3sZ' },
    { name: 'Blog', href: '/blog' },
    { name: 'Sponsor', href: '/sponsor' },
  ],
  legal: [
    { name: 'MIT License', href: 'https://github.com/lane711/sonicjs/blob/main/LICENSE' },
    { name: 'Privacy Policy', href: '/privacy' },
  ],
}

function GitHubIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      />
    </svg>
  )
}

function DiscordIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
    </svg>
  )
}

function XIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M13.6823 10.6218L20.2391 3H18.6854L12.9921 9.61788L8.44486 3H3.2002L10.0765 13.0074L3.2002 21H4.75404L10.7663 14.0113L15.5685 21H20.8131L13.6819 10.6218H13.6823Z" />
    </svg>
  )
}

export function MarketingFooter() {
  return (
    <footer className="bg-gray-900 border-t border-white/10">
      <div className="mx-auto max-w-7xl px-6 pb-8 pt-16 sm:pt-24 lg:px-8 lg:pt-32">
        <div className="xl:grid xl:grid-cols-3 xl:gap-8">
          {/* Brand column */}
          <div className="space-y-8">
            <Logo className="h-7" />
            <p className="text-balance text-sm/6 text-gray-400">
              Edge-native headless CMS built on Cloudflare Workers. MIT licensed, no paywalls, no
              lock-in.
            </p>
            <div className="flex gap-x-6">
              <a
                href="https://github.com/lane711/sonicjs"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-gray-300"
              >
                <span className="sr-only">GitHub</span>
                <GitHubIcon className="size-6" />
              </a>
              <a
                href="https://discord.gg/8bMy6bv3sZ"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-gray-300"
              >
                <span className="sr-only">Discord</span>
                <DiscordIcon className="size-6" />
              </a>
              <a
                href="https://twitter.com/SonicJsHeadless"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-gray-300"
              >
                <span className="sr-only">X (Twitter)</span>
                <XIcon className="size-6" />
              </a>
            </div>
          </div>

          {/* Link columns */}
          <div className="mt-16 grid grid-cols-2 gap-8 xl:col-span-2 xl:mt-0">
            <div className="md:grid md:grid-cols-2 md:gap-8">
              <div>
                <h3 className="text-sm/6 font-semibold text-white">Product</h3>
                <ul role="list" className="mt-6 space-y-4">
                  {navigation.product.map((item) => (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className="text-sm/6 text-gray-400 hover:text-gray-300 no-underline"
                      >
                        {item.name}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="mt-10 md:mt-0">
                <h3 className="text-sm/6 font-semibold text-white">Docs</h3>
                <ul role="list" className="mt-6 space-y-4">
                  {navigation.docs.map((item) => (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className="text-sm/6 text-gray-400 hover:text-gray-300 no-underline"
                      >
                        {item.name}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="md:grid md:grid-cols-2 md:gap-8">
              <div>
                <h3 className="text-sm/6 font-semibold text-white">Community</h3>
                <ul role="list" className="mt-6 space-y-4">
                  {navigation.community.map((item) => (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className="text-sm/6 text-gray-400 hover:text-gray-300 no-underline"
                      >
                        {item.name}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="mt-10 md:mt-0">
                <h3 className="text-sm/6 font-semibold text-white">Legal</h3>
                <ul role="list" className="mt-6 space-y-4">
                  {navigation.legal.map((item) => (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className="text-sm/6 text-gray-400 hover:text-gray-300 no-underline"
                      >
                        {item.name}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-16 border-t border-white/10 pt-8 sm:mt-20 lg:mt-24">
          <p className="text-sm/6 text-gray-400">
            &copy; {new Date().getFullYear()} SonicJS. MIT Licensed. No rights reserved — <a href="https://github.com/SonicJs-Org/sonicjs/fork" target="_blank" rel="noopener noreferrer" className="inline no-underline text-gray-400 hover:text-gray-300 transition-colors"><svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className="inline-block size-4 align-middle mr-1 text-white"><path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z" /></svg>fork it today.</a>
          </p>
        </div>
      </div>
    </footer>
  )
}
