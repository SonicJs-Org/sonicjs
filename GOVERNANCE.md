# SonicJS Governance

This document describes how decisions are made in the SonicJS project.

## Governance Model

SonicJS follows a **Benevolent Dictator for Life (BDFL)** model with trusted co-maintainers. The project lead has final authority on project direction, but day-to-day development is a shared responsibility among maintainers.

This model is intentionally lightweight. As the project and contributor base grow, we may adopt more formal structures (e.g., a Technical Steering Committee).

## Roles

### Project Lead (BDFL)

- **Current:** [@lane711](https://github.com/lane711) (Lane Campbell)
- Has final authority on all project decisions
- Owns the GitHub organization and related infrastructure
- Sets the project roadmap and long-term vision
- Can grant or revoke maintainer access

### Maintainers

- **Current:** [@lane711](https://github.com/lane711), [@mmcintosh](https://github.com/mmcintosh)
- Hold the GitHub "Maintain" role on the repository
- Can review, approve, and merge pull requests
- Triage issues and respond to community questions
- Help cut releases and maintain the changelog
- Expected to follow the decision-making process below

### Contributors

- Anyone who submits a pull request, opens an issue, or participates in discussions
- See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get involved

## Decision-Making Process

### What Maintainers Can Merge Independently

Maintainers may merge PRs without explicit sign-off from the project lead when the change is:

- A bug fix aligned with existing behavior
- A documentation improvement
- A test addition or improvement
- A dependency update (patch or minor version)
- A feature already discussed and approved in an issue or discussion
- A refactor that does not change public APIs

### What Requires Project Lead Sign-Off

The following changes require explicit approval from the project lead:

- **Breaking changes** to public APIs or plugin interfaces
- **New major features** not previously discussed
- **Licensing or governance changes** (this file, LICENSE, CONTRIBUTING.md)
- **Dependency additions** that introduce significant new surface area
- **Security-sensitive changes** (auth, permissions, secrets handling)
- **Release versioning decisions** (especially major version bumps)
- **Changes to the project's scope or direction**

### Disagreements

If maintainers disagree on a change:

1. Discuss it openly in the PR or a GitHub discussion
2. If consensus is not reached, the project lead has final say
3. The project lead may delegate decisions on specific areas to maintainers over time

## Becoming a Maintainer

Maintainers are invited by the project lead after sustained, high-quality contribution to the project. There is no formal application process.

Signals that someone is ready for maintainer status:

- Consistent, meaningful contributions over a period of months
- High-quality code review on others' PRs
- Good judgment on what fits the project's direction
- Responsiveness and helpfulness in issues and discussions
- Trust established with the existing maintainer team

## Inactivity

Maintainers who are inactive for **6+ months** without prior notice may have their maintainer role moved to "emeritus" status. This is not punitive — it reflects the reality that priorities change. Emeritus maintainers can rejoin active status at any time by resuming meaningful contributions.

## Funding and Financial Matters

SonicJS accepts funding through [GitHub Sponsors](https://github.com/sponsors/lane711) and other channels listed in [.github/FUNDING.yml](./.github/FUNDING.yml).

Financial arrangements between maintainers (e.g., sponsorship revenue sharing, commercial licensing revenue) are handled privately between the parties involved and are not part of this public governance document.

The project lead retains ownership of the GitHub organization and associated trademarks/brand assets.

## Changes to This Document

Changes to this governance document require approval from the project lead and should be discussed openly with the maintainer team before being merged.

## Questions

For questions about governance, open a [GitHub Discussion](https://github.com/lane711/sonicjs/discussions) or reach out to the project lead.
