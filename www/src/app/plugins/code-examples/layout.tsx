import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Code Examples Plugin - SonicJS',
  description:
    'Code snippets and examples library for SonicJS with syntax highlighting, categorization, and a full CRUD API.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
