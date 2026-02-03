# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **GitHub Action** that automatically generates a SOUP (Software of Unknown Provenance) register for JavaScript/TypeScript projects. SOUP registers are required for medical device software compliance to document all third-party dependencies.

The action scans all `package.json` files (supporting monorepos), fetches metadata from NPM registry and GitHub API, and outputs a formatted `SOUP.md` markdown file.

## Commands

```bash
# Build TypeScript and bundle for GitHub Actions distribution
yarn build

# Run ESLint fixes and Prettier formatting
yarn lint

# Full pipeline: build, run the action locally, then lint
yarn soup
```

**Note:** There are no tests in this project. The CI workflow validates by running the action itself.

## Architecture

**Single-file TypeScript action** in `src/index.ts` with these key functions:

- `generateSoupRegister()` - Main orchestrator: finds package.json files, collects dependencies, writes SOUP.md
- `getSoupDataForPackage()` - Fetches NPM registry data and GitHub language info for a single dependency
- `generateSoupTable()` - Formats dependency data as a markdown table
- `findFilesRecursive()` - Recursively finds package.json files, skipping node_modules

**Data flow:**

1. Find all `package.json` files recursively
2. For each dependency, fetch from `https://registry.npmjs.org/{package}`
3. Parse GitHub repo URL from NPM data, fetch languages via Octokit
4. Filter languages to those >10% of codebase
5. Generate markdown table with columns: Name, Languages, Website, Version, Risk Level, Verification

**Build output:**

- `lib/` - TypeScript compiled output
- `dist/` - NCC-bundled single file for GitHub Actions (this is what `action.yml` references)

## Key Types

- `TSoupData` - Processed dependency info (name, version, languages, website)
- `TNpmData` - NPM registry response structure
- `TPackageJson` - Standard package.json shape
