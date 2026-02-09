# generate-soup-register

A GitHub Action that automatically generates a SOUP (Software of Unknown Provenance) register with risk analysis for JavaScript/TypeScript projects. Built for medical device software compliance (IEC 62304).

## Why

Without an automation like this, a SOUP register needs to be maintained as a manually updated list of external dependencies for each software system that is part of a medical device. This can be a very menial task, but more importantly it is very error prone and can easily get out of sync.

This action goes beyond simple dependency listing — it automatically analyzes each dependency for security vulnerabilities, maintenance status, license compliance, and version health, giving you a risk-scored register that highlights what needs human attention.

## What

The action scans all `package.json` files (supporting monorepos) and generates a `SOUP.md` markdown file with a comprehensive table for each direct dependency. It combines data from multiple sources:

- **NPM registry** — package metadata, license, deprecation status, last-modified timestamps
- **GitHub API** — programming languages, repository archived/maintenance status
- **OSV.dev** — known vulnerability database, filtered to the exact installed version
- **GitHub Security Advisories** — published advisories affecting the installed version
- **npm/yarn audit** — security audit findings for direct and transitive dependencies
- **Package integrity** — NPM registry signature verification and lockfile hash checks

### Risk Analysis

Each dependency is assigned a risk level based on automated checks:

| Level | Triggers |
|---|---|
| **Critical** | Deprecated, known vulnerabilities, archived repo, critical/high audit findings |
| **High** | Abandoned (>2yr no updates), open security advisories, 2+ major versions behind, strong copyleft license |
| **Medium** | Low maintenance (>1yr no commits), 1 major or >1 minor versions behind, weak copyleft/unknown license, integrity issues |
| **Low** | Passed all automated checks |

### Verification Persistence

Custom verification notes written by developers in the `SOUP.md` Verification column are preserved across regenerations. When a package's version, risk level, or risk details change, the entry is flagged with `⚠️ Re-assess needed` instead of being silently overwritten — ensuring human review of meaningful changes.

## Inputs

| Input | Default | Description |
|---|---|---|
| `token` | `${{ github.token }}` | GitHub token for API access |
| `flag-gpl-as-high-risk` | `'true'` | Treat GPL/AGPL licenses as High risk (relevant for proprietary medical devices) |
| `create-pr` | `'false'` | Create or update a pull request with SOUP.md changes |
| `pr-branch` | `'soup-register-update'` | Branch name for the SOUP update PR |
| `pr-title` | `'chore: update SOUP register'` | Title for the pull request |
| `pr-labels` | `''` | Comma-separated labels to apply (e.g. `'compliance,automated'`) |

## Outputs

| Output | Description |
|---|---|
| `pr-url` | URL of the created or updated pull request (empty if `create-pr` is false or no changes detected) |

## Usage

### Basic — generate SOUP.md on PRs

Generates `SOUP.md` in the workflow runner. Use a separate commit action to persist it.

```yml
name: Update SOUP register

on: pull_request

jobs:
  update-soup-register:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: yarn install

      - name: Generate SOUP register
        uses: tired-of-cancer/generate-soup-register@main

      - name: Commit SOUP.md if changed
        uses: stefanzweifel/git-auto-commit-action@v5
```

### Nightly PR workflow

Runs on a schedule, automatically creates or updates a PR for a developer to review. No extra actions needed.

```yml
name: SOUP Register

on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  soup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: yarn install --frozen-lockfile

      - name: Generate SOUP register and open PR
        uses: tired-of-cancer/generate-soup-register@main
        with:
          create-pr: 'true'
          pr-labels: 'compliance'
```

When `create-pr` is enabled:
- If `SOUP.md` has no changes, no PR is created
- If a PR already exists for the branch, it is updated via force-push
- The `pr-url` output contains the PR URL for use in downstream steps
