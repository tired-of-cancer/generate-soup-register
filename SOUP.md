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
- **Strong Copyleft**: GPL-\*, AGPL-\* (High risk)

### Handling "⚠️ Risk to be analysed"

When a package is flagged with `⚠️ Risk to be analysed`, the project team must:

1. **Review the risk details** listed in the Risk Details column to understand why the package was flagged
2. **Assess the impact** on patient safety and the intended use of the medical device software
3. **Decide on an action**: either accept the risk with justification, mitigate it (e.g. upgrade the package, replace it, or add compensating controls), or reject the dependency
4. **Update the Verification column** by replacing the ⚠️ status with a note summarizing the decision (e.g. `SOUP analysed and accepted by developer` or `Accepted: vulnerability is in unused code path, not reachable in our usage`)

Re-running the SOUP register generator will preserve your verification notes as long as the risk profile of the package has not changed. If a package's risk level or details change, the status will be updated to `⚠️ Re-assess needed` with a reference to your previous note.

The repository uses a total of 5 unique SOUP dependencies.

## generate-soup-register

| Package Name     | Programming Languages | Website                                                      | License | Version | Risk Level | Risk Details                                          | Verification                            |
| ---------------- | --------------------- | ------------------------------------------------------------ | ------- | ------- | ---------- | ----------------------------------------------------- | --------------------------------------- |
| @actions/core    | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/core   | MIT     | 1.10.1  | High       | Version lag: 2 major versions behind (1.10.1 → 3.0.0) | ⚠️ Risk to be analysed                  |
| @actions/github  | TypeScript            | https://github.com/actions/toolkit/tree/main/packages/github | MIT     | 6.0.0   | High       | Version lag: 3 major versions behind (6.0.0 → 9.1.0)  | ⚠️ Risk to be analysed                  |
| node-fetch       | JavaScript            | https://github.com/node-fetch/node-fetch                     | MIT     | 3.3.2   | High       | Abandoned: No updates in 2 years                      | ⚠️ Risk to be analysed                  |
| parse-github-url | JavaScript            | https://github.com/jonschlinkert/parse-github-url            | MIT     | 1.0.2   | Low        | Passed all automated checks                           | SOUP analysed and accepted by developer |
| semver           | JavaScript            | https://github.com/npm/node-semver#readme                    | ISC     | 7.7.3   | Low        | Passed all automated checks                           | SOUP analysed and accepted by developer |

## Indirect and Development Dependencies

The following vulnerabilities were found in transitive or development dependencies. These are not direct dependencies but may still pose a risk.

| Package                       | Version       | Dependency Path                              | Severity | Advisory                                          | Recommendation    | Type       | Verification           |
| ----------------------------- | ------------- | -------------------------------------------- | -------- | ------------------------------------------------- | ----------------- | ---------- | ---------------------- |
| @babel/helpers                | <7.26.10      | (transitive) > @babel/helpers                | moderate | https://github.com/advisories/GHSA-968p-4wvh-cqc8 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| @babel/runtime                | <7.26.10      | (transitive) > @babel/runtime                | moderate | https://github.com/advisories/GHSA-968p-4wvh-cqc8 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| @babel/runtime-corejs3        | <7.26.10      | (transitive) > @babel/runtime-corejs3        | moderate | https://github.com/advisories/GHSA-968p-4wvh-cqc8 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| @octokit/plugin-paginate-rest | <=9.2.1       | (transitive) > @octokit/plugin-paginate-rest | moderate | https://github.com/advisories/GHSA-h5c3-5r3r-rr8q | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| @octokit/request              | <=8.4.0       | (transitive) > @octokit/request              | moderate | https://github.com/advisories/GHSA-rmvr-2pp2-xj38 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| @octokit/request-error        | <=5.1.0       | (transitive) > @octokit/request-error        | moderate | https://github.com/advisories/GHSA-xx4v-prfh-6cgc | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| ajv                           | <6.14.0       | (transitive) > ajv                           | moderate | https://github.com/advisories/GHSA-2g4f-4pwh-qvx6 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| brace-expansion               | <=1.1.12      | (transitive) > brace-expansion               | moderate | https://github.com/advisories/GHSA-v6h2-p8h4-qcjw | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| braces                        | <3.0.3        | (transitive) > braces                        | high     | https://github.com/advisories/GHSA-grv7-fg5c-xmjg | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| cross-spawn                   | 7.0.0 - 7.0.4 | (transitive) > cross-spawn                   | high     | https://github.com/advisories/GHSA-3xgq-45jj-v275 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| flatted                       | <=3.4.1       | (transitive) > flatted                       | high     | https://github.com/advisories/GHSA-25h7-pfq9-p65f | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| form-data                     | 4.0.0 - 4.0.3 | (transitive) > form-data                     | critical | https://github.com/advisories/GHSA-fjxv-7rqg-78g4 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| js-yaml                       | 4.0.0 - 4.1.0 | (transitive) > js-yaml                       | moderate | https://github.com/advisories/GHSA-mh29-5h37-fv8m | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| lodash                        | <=4.17.23     | (transitive) > lodash                        | high     | https://github.com/advisories/GHSA-xxjr-mmjv-4gpg | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| micromatch                    | <4.0.8        | (transitive) > micromatch                    | moderate | https://github.com/advisories/GHSA-952p-6rrq-rcjv | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| minimatch                     | <=3.1.3       | (transitive) > minimatch                     | high     | https://github.com/advisories/GHSA-3ppc-4f35-3m26 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| picomatch                     | <=2.3.1       | (transitive) > picomatch                     | high     | https://github.com/advisories/GHSA-3v7f-55p6-f55p | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
| undici                        | <=6.23.0      | (transitive) > undici                        | high     | https://github.com/advisories/GHSA-c76h-2ccp-4975 | Run npm audit fix | Transitive | ⚠️ Risk to be analysed |
