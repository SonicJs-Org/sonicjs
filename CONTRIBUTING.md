# Contributing to SonicJS

Thank you for your interest in contributing to SonicJS!

## Quick Links

- **[Full Contributing Guide](https://sonicjs.com/contributing)** - Detailed guide on how to contribute
- **[Project Governance](./GOVERNANCE.md)** - How decisions are made and who the maintainers are
- **[Good First Issues](https://github.com/lane711/sonicjs/labels/good%20first%20issue)** - Great starting points for new contributors
- **[Help Wanted](https://github.com/lane711/sonicjs/labels/help%20wanted)** - Issues where we need community help

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/sonicjs.git
   cd sonicjs
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Start development:**
   ```bash
   npm run dev
   ```

## Before You Start

We appreciate every developer who wants to contribute. To ensure the best experience for both contributors and maintainers:

- **Start with code, not meetings** - Submit at least one meaningful pull request before requesting deeper involvement
- **Find an issue** - Check our [issue tracker](https://github.com/lane711/sonicjs/issues) for something to work on
- **Claim the issue** - Comment on the issue to indicate you're working on it

## What Counts as a Meaningful Contribution?

- 🐛 **Bug Fixes** - Fix a bug with a well-tested solution
- ✨ **New Features** - Implement a feature that has been discussed and approved
- 📝 **Documentation** - Significantly improve or add documentation
- 🧪 **Test Coverage** - Add meaningful tests for untested functionality

## Code Standards

- **TypeScript**: All code must be in TypeScript with proper types
- **Testing**: New features must include tests
- **Documentation**: Public APIs must be documented
- **Formatting**: Use Prettier (runs automatically on commit)
- **Linting**: ESLint rules must pass (runs automatically on commit)
- **Naming Conventions**: See our [Coding Standards Guide](https://sonicjs.com/coding-standards) for detailed naming conventions and code style guidelines

### Running Lint

```bash
# Lint the core package
npm run lint --workspace=@sonicjs-cms/core

# Auto-fix lint issues
npm run lint:fix --workspace=@sonicjs-cms/core
```

## Pull Request Checklist

Before submitting a PR:

- [ ] All tests pass (`npm test`)
- [ ] Linting passes (`npm run lint --workspace=@sonicjs-cms/core`)
- [ ] Changes are documented if needed
- [ ] PR description explains the changes
- [ ] Related issue is referenced
- [ ] Commits are signed off (see DCO below)

## Developer Certificate of Origin (DCO)

By contributing to SonicJS, you certify that you wrote the code (or otherwise have the right to submit it) and agree to release it under the project's MIT license. This is formalized by the [Developer Certificate of Origin](https://developercertificate.org/).

To signal your agreement, add a `Signed-off-by` line to each commit:

```bash
git commit -s -m "your commit message"
```

This appends a line like `Signed-off-by: Your Name <your.email@example.com>` to the commit message using your configured `user.name` and `user.email`.

## Questions?

- Check [existing issues](https://github.com/lane711/sonicjs/issues) - your question may already be answered
- Ask in [GitHub Discussions](https://github.com/lane711/sonicjs/discussions) - for general questions
- Join our [Discord](https://discord.gg/8bMy6bv3sZ) - for real-time chat

We look forward to your contributions!
