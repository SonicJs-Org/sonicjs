# create-sonicjs

> The easiest way to create a new SonicJS application

[![Version](https://img.shields.io/npm/v/create-sonicjs)](https://www.npmjs.com/package/create-sonicjs)
[![License](https://img.shields.io/npm/l/create-sonicjs)](./LICENSE)

## Quick Start

```bash
npx create-sonicjs my-app
```

That's it! Follow the interactive prompts and you'll have a running SonicJS application in minutes.

## What It Does

`create-sonicjs` sets up everything you need for a modern headless CMS on Cloudflare's edge:

- ✅ **Project scaffolding** - Complete project structure
- ✅ **Template selection** - Choose from pre-built templates
- ✅ **Cloudflare resources** - Optionally create D1 database and R2 bucket
- ✅ **Configuration** - Auto-configured wrangler.toml
- ✅ **Dependencies** - Installs all required packages
- ✅ **Git initialization** - Ready for version control
- ✅ **Example code** - Optional blog collection example

## Usage

### Interactive Mode (Recommended)

```bash
npx create-sonicjs
```

You'll be prompted for:
- Project name
- Template choice
- Database name
- R2 bucket name
- Whether to include examples
- Whether to create Cloudflare resources
- Whether to initialize git

### With Project Name

```bash
npx create-sonicjs my-blog
```

### Command Line Options

```bash
npx create-sonicjs my-app --template=starter --skip-install
```

**Available flags:**
- `--template=<name>` - Skip template selection (e.g., `--template=starter`)
- `--database=<name>` - Set database name without prompt
- `--bucket=<name>` - Set R2 bucket name without prompt
- `--include-example` - Include example blog collection (no prompt)
- `--skip-example` - Skip example blog collection (no prompt)
- `--skip-install` - Don't install dependencies
- `--skip-git` - Don't initialize git
- `--skip-cloudflare` - Don't prompt for Cloudflare resource creation

## Templates

### Starter (Default)
Perfect for blogs, documentation, and content sites.

Includes:
- Blog collection example
- Admin dashboard
- REST API
- Media management

**Coming Soon:**
- E-commerce template
- Documentation site template
- Portfolio template

## Requirements

- **Node.js** 18 or higher
- **npm** 7 or higher (or yarn/pnpm)
- **wrangler** (optional, for Cloudflare resources)

## What Gets Created

```
my-app/
├── src/
│   ├── index.ts              # Application entry point
│   └── collections/          # Content type definitions
│       └── blog-posts.collection.ts
├── wrangler.toml             # Cloudflare Workers config
├── package.json              # Dependencies
├── tsconfig.json             # TypeScript config
├── .gitignore
└── README.md
```

## After Creation

### 1. Navigate to your project

```bash
cd my-app
```

### 2. Create Cloudflare resources (if skipped)

```bash
wrangler d1 create my-app-db
# Copy the database_id to wrangler.toml

wrangler r2 bucket create my-app-media
```

### 3. Run database migrations

```bash
npm run db:migrate:local
```

### 4. Start development server

```bash
npm run dev
```

### 5. Open admin interface

Visit http://localhost:8787/admin

Default credentials:
- Email: `admin@sonicjs.com`
- Password: `admin`

## Package Managers

Works with all major package managers:

```bash
# npm
npx create-sonicjs my-app

# yarn
yarn create sonicjs my-app

# pnpm
pnpm create sonicjs my-app
```

The CLI automatically detects your package manager from lock files.

## Environment Variables

After creation, you may want to set up environment variables:

```bash
# .dev.vars (for local development)
ENVIRONMENT=development
# Better Auth (required for login/sign-up)
BETTER_AUTH_SECRET=your-min-32-char-secret-change-in-production
BETTER_AUTH_URL=http://localhost:8787
```

## Cloudflare Resources

### D1 Database

If you create resources during setup, a D1 database is automatically created and configured.

**Manual creation:**
```bash
wrangler d1 create my-app-db
```

### R2 Bucket

For media storage, an R2 bucket is created.

**Manual creation:**
```bash
wrangler r2 bucket create my-app-media
```

## Troubleshooting

### "wrangler is not installed"

Install wrangler globally:
```bash
npm install -g wrangler
```

### "Directory already exists"

Choose a different project name or remove the existing directory:
```bash
rm -rf my-app
```

### Dependencies fail to install

Try manually:
```bash
cd my-app
npm install
```

### Cloudflare resource creation fails

You can create resources manually after project creation. See the [After Creation](#after-creation) section.

## Advanced Usage

### Skip All Prompts (Non-Interactive Mode)

```bash
npx create-sonicjs my-app \
  --template=starter \
  --database=my-app-db \
  --bucket=my-app-media \
  --include-example \
  --skip-install \
  --skip-git \
  --skip-cloudflare
```

### Use in CI/CD

```bash
npx create-sonicjs test-app \
  --template=starter \
  --database=test-db \
  --bucket=test-bucket \
  --skip-example \
  --skip-install \
  --skip-cloudflare \
  --skip-git
```

## Features

- 🎨 **Beautiful CLI** - Colored output and progress indicators
- ⚡ **Fast** - Optimized for speed
- 🔒 **Type-safe** - Full TypeScript support
- 🌐 **Edge-first** - Built for Cloudflare Workers
- 📦 **Zero config** - Works out of the box
- 🔧 **Customizable** - Easy to extend

## Examples

### Create a blog

```bash
npx create-sonicjs my-blog
# Select "Starter" template
# Include example collection: Yes
```

### Create without examples

```bash
npx create-sonicjs my-app
# Include example collection: No
```

## Related

- [@sonicjs-cms/core](../core) - Core framework
- [SonicJS Documentation](https://sonicjs.com)
- [Cloudflare Workers](https://workers.cloudflare.com)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## License

MIT © SonicJS Team

## Support

- **Issues**: [GitHub Issues](https://github.com/lane711/sonicjs/issues)
- **Discord**: [Join our community](https://discord.gg/8bMy6bv3sZ)
- **Docs**: [sonicjs.com](https://sonicjs.com)

---

**Built with ❤️ for developers** | v2.0.0-alpha.1
