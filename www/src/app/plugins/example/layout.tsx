import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Example Plugin - SonicJS',
  description:
    'The example plugin ships with every new SonicJS install. A complete reference demonstrating routes, collections, configSchema settings, hooks, and data seeding.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
