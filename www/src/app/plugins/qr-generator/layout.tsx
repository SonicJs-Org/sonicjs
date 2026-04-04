import { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'QR Code Generator Plugin - SonicJS',
  description:
    'Generate and manage QR codes with customizable styling, logo embedding, and redirect tracking in SonicJS.',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return children
}
