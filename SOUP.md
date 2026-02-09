# SOUP Register

This document contains a list of all SOUP (Software of Unknown Provenance) dependencies used in this repository. SOUP is third-party software that is included in the project and is not developed by the project team.

Risk levels are automatically calculated based on:

- **Critical**: Package is deprecated, has known vulnerabilities, repository is archived, or has critical/high npm audit findings
- **High**: Package is abandoned (>2 years without updates), has open security advisories, is 2+ major versions behind latest, or GPL/AGPL licenses (copyleft - may require source disclosure)
- **Medium**: Low maintenance activity (>1 year without commits), 1 major version behind, >1 minor versions behind, weak copyleft license (LGPL/MPL), unknown license, or integrity verification issues
- **Low**: Passed all automated checks

License categories:

- **Permissive**: MIT, Apache-2.0, BSD-\*, ISC (Low risk)
- **Weak Copyleft**: MPL-2.0, LGPL-\* (Medium risk)
- **Strong Copyleft**: GPL-_, AGPL-_ (High risk)

The repository uses a total of 5 unique SOUP dependencies.

## generate-soup-register

| Package Name     | Programming Languages | Website                                                      | License | Version | Risk Level | Risk Details                                                               | Verification                            |
| ---------------- | --------------------- | ------------------------------------------------------------ | ------- | ------- | ---------- | -------------------------------------------------------------------------- | --------------------------------------- |
| @actions/core    | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/core   | MIT     | 1.10.1  | High       | Version lag: 2 major versions behind (1.10.1 → 3.0.0)                      | ⚠️ Risk to be analysed                  |
| @actions/github  | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/github | MIT     | 6.0.0   | High       | Version lag: 3 major versions behind (6.0.0 → 9.0.0)                       | ⚠️ Risk to be analysed                  |
| node-fetch       | JavaScript            | https://github.com/node-fetch/node-fetch                     | MIT     | 3.3.2   | High       | Abandoned: No updates in 2 years; Low maintenance: No commits in 17 months | ⚠️ Risk to be analysed                  |
| parse-github-url | JavaScript            | https://github.com/jonschlinkert/parse-github-url            | MIT     | 1.0.2   | Low        | Passed all automated checks                                                | SOUP analysed and accepted by developer |
| semver           | JavaScript            | https://github.com/npm/node-semver#readme                    | ISC     | ^7.7.3  | Low        | Passed all automated checks                                                | SOUP analysed and accepted by developer |
