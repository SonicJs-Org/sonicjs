import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Self-Hosting SonicJS',
  description:
    'Run SonicJS on your own infrastructure with Docker or Node.js — no Cloudflare account required.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
