import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Forms as Collections - SonicJS',
  description:
    'Build forms with a drag-and-drop builder. Forms are stored as collections and submissions become queryable content items.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
