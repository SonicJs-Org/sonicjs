import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Testimonials Plugin - SonicJS',
  description:
    'Customer testimonials and reviews management for SonicJS with ratings, display widgets, and a full CRUD API.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
