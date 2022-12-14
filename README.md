# generate-soup-register

A GitHub Action to automatically generate a SOUP register for JS based projects

## Why

Without an automation like this, a SOUP register needs to be maintained as a manually updated list of external dependencies for each software system that is part of a medical device. This can be a very menial task, but more importantly it is very error prone and can easily get out of sync.

## What

This action generates a markdown formatted table of all direct JS dependencies currently bundled in the software system. To get all the needed information the script combines these sources:

- The `package.json` file included in the software system to extract all package names of SOUP dependencies bundled within the production builds of the software system product.
- https://registry.npmjs.org to fetch the official website and repository as communicated by the publisher of the SOUP dependency.
- [GitHub's Octokit](https://github.com/octokit/octokit.js) to fetch the code languages of the SOUP dependency.

## Implementation

The action can be run as part of a GitHub workflow. The result will be a file that is generated in the workflow runner environment. To persist the file, the workflow should do something with the generated file. For example, it could be committed to the main branch, the current PR branch or a new branch that is then opened as a new PR. Alternatively, it can be sent to an external system. The right way to handle this depends on your usecase and setup.

The following workflow is an example workflow that will commit the new file on the current PR:

```yml
name: Update SOUP register

on: pull_request

jobs:
  update-soup-register:
    runs-on: ubuntu-latest
    steps:
      - name: Check out Git repository
        uses: actions/checkout@v3

      - name: Setup node
        uses: actions/setup-node@v3

      - name: install dependencies
        run: yarn install

      - name: Generate SOUP register MD file
        uses: tired-of-cancer/generate-soup-register@main

      - name: Commit SOUP.md if changed
        id: auto-commit-soup-changes
        uses: stefanzweifel/git-auto-commit-action@v4
```
