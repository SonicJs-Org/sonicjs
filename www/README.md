# SonicJS Documentation (www)

Official documentation website for SonicJS headless CMS. Built with Next.js 15, MDX, and Tailwind CSS.

## About

This documentation site provides comprehensive guides, API references, and tutorials for SonicJS - a modern, TypeScript-first headless CMS built for Cloudflare's edge platform.

## Getting Started

### Prerequisites

- Node.js >= 20.0.0
- npm >= 10.0.0

### Development

From the monorepo root:

```bash
# Start docs development server
npm run dev:www
```

Or from this directory:

```bash
npm run dev
```

The site will be available at [http://localhost:3010](http://localhost:3010)

### Building

```bash
# From monorepo root
npm run build:www

# From this directory
npm run build
```

## Features

- **MDX Content**: Write documentation in MDX with custom components
- **Full-Text Search**: Powered by FlexSearch with keyboard shortcuts (⌘K)
- **Responsive Design**: Mobile-first design with Tailwind CSS
- **Syntax Highlighting**: Code blocks with Shiki
- **Dark Mode**: System-aware theme switching
- **Cloudflare Deployment**: Optimized for Cloudflare Pages

## Project Structure

```
www/
├── src/
│   ├── app/              # Next.js app router pages (MDX)
│   ├── components/       # React components
│   ├── lib/             # Utility functions
│   ├── mdx/             # MDX processing plugins
│   └── styles/          # Global styles
├── public/              # Static assets
├── next.config.mjs      # Next.js configuration
└── package.json
```

## Deployment

This site is configured to deploy to Cloudflare Pages using OpenNext.

```bash
# From monorepo root
npm run deploy:www

# From this directory
npm run deploy
```

## Writing Documentation

Documentation pages are written in MDX and located in `src/app/`. Each directory represents a section of the docs.

### Creating a New Page

1. Create a new directory under `src/app/`
2. Add a `page.mdx` file with your content
3. The page will automatically be indexed for search

### Using Components

```mdx
import { Callout } from '@/components/Callout'

# My Documentation Page

<Callout type="warning">
  This is a warning callout
</Callout>
```

## Technologies

- [Next.js](https://nextjs.org/docs) - React framework
- [MDX](https://mdxjs.com/) - Markdown with JSX
- [Tailwind CSS](https://tailwindcss.com/docs) - Utility-first CSS
- [Headless UI](https://headlessui.dev) - Unstyled UI components
- [Framer Motion](https://www.framer.com/docs/) - Animation library
- [FlexSearch](https://github.com/nextapps-de/flexsearch) - Full-text search
- [Zustand](https://docs.pmnd.rs/zustand/getting-started/introduction) - State management

## License

This documentation is part of the SonicJS project and is licensed under the MIT License.

## Learn More

- [SonicJS Repository](https://github.com/SonicJs-Org/sonicjs)
- [SonicJS Homepage](https://sonicjs.com)
- [Report Issues](https://github.com/SonicJs-Org/sonicjs/issues)
