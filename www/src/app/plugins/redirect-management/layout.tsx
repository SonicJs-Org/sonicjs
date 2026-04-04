import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Redirect Management Plugin - SonicJS',
  description:
    'Manage URL redirects with exact, wildcard, and regex matching, CSV import/export, and Cloudflare Bulk Redirects integration.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
