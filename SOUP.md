# SOUP Register

This document contains a list of all SOUP (Software of Unknown Provenance) dependencies used in this repository. SOUP is third-party software that is included in the project and is not developed by the project team.

Risk levels are automatically calculated based on:

- **Critical**: Package is deprecated, has known vulnerabilities, or repository is archived
- **High**: Package is abandoned (>2 years without updates) or has open security advisories
- **Medium**: Low maintenance activity (>1 year without commits)
- **Low**: Passed all automated checks

The repository uses a total of 4 unique SOUP dependencies.

## generate-soup-register

| Package Name     | Programming Languages | Website                                                      | Version | Risk Level | Risk Details                                                                                            | Verification                            |
| ---------------- | --------------------- | ------------------------------------------------------------ | ------- | ---------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| @actions/core    | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/core   | 1.10.1  | High       | Security advisories: 3 open                                                                             | SOUP analysed and accepted by developer |
| @actions/github  | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/github | 6.0.0   | High       | Security advisories: 3 open                                                                             | SOUP analysed and accepted by developer |
| node-fetch       | JavaScript            | https://github.com/node-fetch/node-fetch                     | 3.3.2   | High       | Abandoned: No updates in 2 years; Low maintenance: No commits in 17 months; Security advisories: 1 open | SOUP analysed and accepted by developer |
| parse-github-url | JavaScript            | https://github.com/jonschlinkert/parse-github-url            | 1.0.2   | Low        | Passed all automated checks                                                                             | SOUP analysed and accepted by developer |
