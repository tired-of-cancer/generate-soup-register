# SOUP Register

This document contains a list of all SOUP (Software of Unknown Provenance) dependencies used in this repository. SOUP is third-party software that is included in the project and is not developed by the project team.

Risk levels are automatically calculated based on:

- **Critical**: Package is deprecated, has known vulnerabilities, or repository is archived
- **High**: Package is abandoned (>2 years without updates) or has open security advisories
- **Medium**: Low maintenance activity (>1 year without commits)
- **Low**: Passed all automated checks

The repository uses a total of 4 unique SOUP dependencies.

## generate-soup-register

| Package Name     | Programming Languages | Website                                                      | Version | Risk Level | Risk Details                     | Verification                            |
| ---------------- | --------------------- | ------------------------------------------------------------ | ------- | ---------- | -------------------------------- | --------------------------------------- |
| @actions/core    | unknown               | https://github.com/actions/toolkit/tree/main/packages/core   | 1.10.1  | Low        | Passed all automated checks      | SOUP analysed and accepted by developer |
| @actions/github  | unknown               | https://github.com/actions/toolkit/tree/main/packages/github | 6.0.0   | Low        | Passed all automated checks      | SOUP analysed and accepted by developer |
| node-fetch       | unknown               | https://github.com/node-fetch/node-fetch                     | 3.3.2   | High       | Abandoned: No updates in 2 years | ⚠️ Risk to be analysed                  |
| parse-github-url | unknown               | https://github.com/jonschlinkert/parse-github-url            | 1.0.2   | Low        | Passed all automated checks      | SOUP analysed and accepted by developer |
