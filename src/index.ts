/* eslint-disable import/no-extraneous-dependencies */
import { execSync } from 'node:child_process'
import fs from 'node:fs'
import path = require('path')
import { join } from 'node:path'
import readline from 'node:readline'

import * as core from '@actions/core'
import * as github from '@actions/github'
import { Octokit } from '@octokit/core'
import fetch from 'node-fetch'
import parseGithubUrl from 'parse-github-url'
import { coerce, compare, major, minor, prerelease, satisfies } from 'semver'

const DEFAULT_VERIFICATION_LOW = 'SOUP analysed and accepted by developer'
const DEFAULT_VERIFICATION_RISK = '⚠️ Risk to be analysed'
const DEFAULT_SOUP_FILENAME = 'SOUP.md'

// License risk categories
const PERMISSIVE_LICENSES = [
  'MIT',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  '0BSD',
  'Unlicense',
  'CC0-1.0',
  'WTFPL',
]
const WEAK_COPYLEFT_LICENSES = ['MPL-2.0', 'LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0']
const STRONG_COPYLEFT_LICENSES = [
  'GPL-2.0',
  'GPL-3.0',
  'AGPL-3.0',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',
]

// Store for existing verification values parsed from SOUP.md
// Includes version, risk level, and risk details to detect when re-assessment is needed
type TExistingVerification = {
  version: string
  riskLevel: string
  riskDetails: string
  verification: string
}
let existingVerifications: Map<string, TExistingVerification> = new Map()

// Store for existing indirect vulnerability verifications
// Key is "packageName|version|dependencyPath" to uniquely identify each entry
type TExistingIndirectVerification = {
  verification: string
}
let existingIndirectVerifications: Map<string, TExistingIndirectVerification> =
  new Map()

// Track API failures to halt execution if any occur
const apiFailures: string[] = []

const trackApiFailure = (
  source: string,
  packageName: string,
  error: unknown
) => {
  const message = `${source} failed for ${packageName}: ${
    error instanceof Error ? error.message : 'Unknown error'
  }`
  apiFailures.push(message)
  core.warning(message)
}

type TPackageJson = {
  name: string
  dependencies?: { [key: string]: string }
}

type TNpmData =
  | {
      versions: {
        [key: string]: {
          homepage: string
          repository: {
            url: string
          }
          deprecated?: string
        }
      }
      time?: {
        modified: string
        created: string
        [version: string]: string
      }
      license?: string
    }
  | undefined

type TRiskAnalysis = {
  level: 'Critical' | 'High' | 'Medium' | 'Low'
  reasons: string[]
}

type TOsvVulnerability = {
  id: string
  summary?: string
  affected?: Array<{
    package?: {
      ecosystem?: string
      name?: string
    }
    ranges?: Array<{
      type: 'SEMVER' | 'ECOSYSTEM' | 'GIT'
      events: Array<{
        introduced?: string
        fixed?: string
        last_affected?: string
      }>
    }>
    versions?: string[]
  }>
}

type TOsvResponse = {
  vulns?: TOsvVulnerability[]
}

type TGitHubRepoData = {
  archived: boolean
  pushed_at: string
}

type TSoupData = {
  soupName: string
  soupLanguages: string
  soupSite: string
  soupLicense: string
  soupVersion: string
  soupRiskLevel: string
  soupRiskDetails: string
  soupVerification: string
}

type TLicenseRisk = {
  category: 'Permissive' | 'Weak Copyleft' | 'Strong Copyleft' | 'Unknown'
  risk: 'Low' | 'Medium' | 'High'
  reason: string | undefined
}

type TNpmAuditVulnerability = {
  name: string
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical'
  isDirect: boolean
  via: Array<string | { source: number; name: string; url?: string }>
  effects: string[]
  range: string
  fixAvailable:
    | boolean
    | {
        name: string
        version: string
        isSemVerMajor: boolean
      }
}

type TNpmAuditResult = {
  vulnerabilities: Record<string, TNpmAuditVulnerability>
}

type TIndirectVulnerability = {
  name: string
  version: string
  severity: string
  advisory: string
  recommendation: string
  type: 'Transitive' | 'Dev'
  dependencyPath: string
  verification: string
}

type TIntegrityResult = {
  invalidSignatures: Set<string>
  missingSignatures: Set<string>
  lockfileHashes: Set<string>
}

readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

const auth = core.getInput('token')
const octokit = new Octokit({ auth, request: { fetch } })

/**
 * Method to request programming language data from GitHub so we can list the language of the SOUP
 * @param soupRepoUrl string: github repo url retrieved from NPM info
 * @returns string: comma separated languages that make up at least 10% of the project
 */
const getSoupLanguageData = async (soupRepoUrl: string) => {
  try {
    const { owner, name } = parseGithubUrl(soupRepoUrl) ?? {}
    if (!owner || !name) return 'unknown'

    const soupLanguagesGitHubResponse = await octokit.request(
      'GET /repos/{owner}/{name}/languages',
      { owner, name }
    )

    if (soupLanguagesGitHubResponse.status !== 200) return 'unknown'
    const soupLanguagesData = soupLanguagesGitHubResponse.data as Record<
      string,
      number
    >

    const totalSoupBytes =
      Object.values(soupLanguagesData)?.reduce((a, b) => a + b, 0) ?? 0

    return Object.keys(soupLanguagesData)
      .filter(
        // By filtering out languages that make up less than 10% we prevent listing unrelevant tool languages etc.
        (language) => soupLanguagesData[language] > totalSoupBytes * 0.1
      )
      .join(', ')
  } catch {
    return 'unknown'
  }
}

/**
 * Check license risk based on license type
 * @param license string: the license from NPM registry
 * @param flagGplAsHighRisk boolean: whether to treat GPL/AGPL as High risk
 */
const checkLicenseRisk = (
  license: string | undefined,
  flagGplAsHighRisk: boolean
): TLicenseRisk => {
  if (!license) {
    return {
      category: 'Unknown',
      risk: 'Medium',
      reason: 'License: Unknown or missing',
    }
  }

  // Normalize license string for comparison
  const normalizedLicense = license.toUpperCase()

  // Check permissive licenses
  if (
    PERMISSIVE_LICENSES.some((l) => normalizedLicense.includes(l.toUpperCase()))
  ) {
    return {
      category: 'Permissive',
      risk: 'Low',
      reason: undefined,
    }
  }

  // Check strong copyleft licenses
  if (
    STRONG_COPYLEFT_LICENSES.some((l) =>
      normalizedLicense.includes(l.toUpperCase())
    )
  ) {
    return {
      category: 'Strong Copyleft',
      risk: flagGplAsHighRisk ? 'High' : 'Medium',
      reason: flagGplAsHighRisk
        ? `License: ${license} (copyleft - may require source disclosure)`
        : `License: ${license} (copyleft)`,
    }
  }

  // Check weak copyleft licenses
  if (
    WEAK_COPYLEFT_LICENSES.some((l) =>
      normalizedLicense.includes(l.toUpperCase())
    )
  ) {
    return {
      category: 'Weak Copyleft',
      risk: 'Medium',
      reason: `License: ${license} (weak copyleft)`,
    }
  }

  // Unknown license
  return {
    category: 'Unknown',
    risk: 'Medium',
    reason: `License: ${license} (unrecognized)`,
  }
}

/**
 * Parse signature audit JSON output
 */
const parseSignatureAuditOutput = (
  jsonString: string
): { invalid: Set<string>; missing: Set<string> } => {
  try {
    const data = JSON.parse(jsonString) as {
      invalid?: Array<{ name: string }>
      missing?: Array<{ name: string }>
    }
    return {
      invalid: new Set((data.invalid ?? []).map((p) => p.name)),
      missing: new Set((data.missing ?? []).map((p) => p.name)),
    }
  } catch {
    return { invalid: new Set(), missing: new Set() }
  }
}

/**
 * Run npm audit signatures to verify package registry signatures
 * Returns packages with invalid or missing signatures
 */
const runSignatureAudit = (
  rootPath: string
): { invalid: Set<string>; missing: Set<string> } => {
  try {
    const result = execSync('npm audit signatures --json 2>/dev/null', {
      cwd: rootPath,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024,
    })

    return parseSignatureAuditOutput(result)
  } catch (error) {
    // npm audit signatures may fail or not be available
    const execError = error as { stdout?: string; status?: number }
    if (execError.stdout) {
      const parsed = parseSignatureAuditOutput(execError.stdout)
      if (parsed.invalid.size > 0 || parsed.missing.size > 0) {
        return parsed
      }
    }
    core.warning(
      'npm audit signatures not available - skipping signature verification'
    )
    return { invalid: new Set(), missing: new Set() }
  }
}

/**
 * Parse yarn.lock to extract packages with integrity hashes
 * Returns set of package names that have integrity hashes in lockfile
 */
const parseLockfileIntegrities = (rootPath: string): Set<string> => {
  const hashes = new Set<string>()

  // Try yarn.lock first
  const yarnLockPath = join(rootPath, 'yarn.lock')
  if (fs.existsSync(yarnLockPath)) {
    try {
      const content = fs.readFileSync(yarnLockPath, 'utf8')
      // yarn.lock v1 format: package name followed by integrity on subsequent line
      // Format: "package@version":
      //   integrity sha512-...
      const packageRegex = /^"?(@?[^\n"@]+)@[^\n":]+/gm
      const integrityRegex = /^\s+integrity\s+sha\d+-/gm

      // Collect all package positions
      const packagePositions: Array<{ name: string; index: number }> = []
      const packageMatches = content.matchAll(packageRegex)
      ;[...packageMatches].forEach((m) => {
        packagePositions.push({ name: m[1], index: m.index ?? 0 })
      })

      // Find packages with integrity hashes
      const integrityMatches = content.matchAll(integrityRegex)
      ;[...integrityMatches].forEach((integrityMatch) => {
        // Find the package this integrity belongs to (last package before this integrity line)
        const matchingPackage = packagePositions
          .filter((p) => p.index < (integrityMatch.index ?? 0))
          .at(-1)
        if (matchingPackage) {
          hashes.add(matchingPackage.name)
        }
      })

      return hashes
    } catch {
      core.warning('Failed to parse yarn.lock for integrity hashes')
    }
  }

  // Try package-lock.json as fallback
  const npmLockPath = join(rootPath, 'package-lock.json')
  if (fs.existsSync(npmLockPath)) {
    try {
      const content = fs.readFileSync(npmLockPath, 'utf8')
      const lockData = JSON.parse(content) as {
        packages?: Record<string, { integrity?: string }>
        dependencies?: Record<string, { integrity?: string }>
      }

      // npm lockfile v2/v3 format
      if (lockData.packages) {
        Object.entries(lockData.packages).forEach(
          ([packagePath, packageData]) => {
            if (packageData.integrity) {
              // Extract package name from path (e.g., "node_modules/@scope/name")
              const pathMatch = packagePath.match(/node_modules\/(.+)$/)
              if (pathMatch) {
                hashes.add(pathMatch[1])
              }
            }
          }
        )
      }

      // npm lockfile v1 format
      if (lockData.dependencies) {
        Object.entries(lockData.dependencies).forEach(([name, data]) => {
          if (data.integrity) {
            hashes.add(name)
          }
        })
      }

      return hashes
    } catch {
      core.warning('Failed to parse package-lock.json for integrity hashes')
    }
  }

  return hashes
}

/**
 * Parse lockfile to extract resolved versions for each package.
 * Returns a map where keys are "name@specifier" and/or just "name",
 * and values are the exact resolved version strings.
 */
const parseLockfileVersions = (rootPath: string): Map<string, string> => {
  const versions = new Map<string, string>()

  // Try yarn.lock first
  const yarnLockPath = join(rootPath, 'yarn.lock')
  if (fs.existsSync(yarnLockPath)) {
    try {
      const content = fs.readFileSync(yarnLockPath, 'utf8')
      // Match entry headers and their resolved versions
      // Handles: "package@range":  OR  package@range:  OR  "pkg@range1, pkg@range2":
      const entryRegex = /^"?(.+?)"?:\n\s+version "(.+?)"/gm
      ;[...content.matchAll(entryRegex)].forEach((match) => {
        const resolvedVersion = match[2]
        // Entry header can contain multiple specifiers: "semver@^7.3.7, semver@^7.3.8"
        match[1]
          .split(', ')
          .map((s) => s.replaceAll(/^"|"$/g, ''))
          .forEach((specifier) => {
            versions.set(specifier, resolvedVersion)
            // Also store by name alone (last wins, which is fine for direct deps)
            const nameMatch = specifier.match(/^(@?[^@]+)@/)
            if (nameMatch) {
              versions.set(`${nameMatch[1]}@latest`, resolvedVersion)
            }
          })
      })
      return versions
    } catch {
      core.warning('Failed to parse yarn.lock for resolved versions')
    }
  }

  // Try package-lock.json as fallback
  const npmLockPath = join(rootPath, 'package-lock.json')
  if (fs.existsSync(npmLockPath)) {
    try {
      const content = fs.readFileSync(npmLockPath, 'utf8')
      const lockData = JSON.parse(content) as {
        packages?: Record<string, { version?: string }>
        dependencies?: Record<string, { version?: string }>
      }

      // npm lockfile v2/v3 format
      if (lockData.packages) {
        Object.entries(lockData.packages).forEach(([packagePath, data]) => {
          if (data.version) {
            const pathMatch = packagePath.match(/node_modules\/(.+)$/)
            if (pathMatch) {
              versions.set(pathMatch[1], data.version)
            }
          }
        })
      }

      // npm lockfile v1 format
      if (lockData.dependencies) {
        Object.entries(lockData.dependencies).forEach(([name, data]) => {
          if (data.version) {
            versions.set(name, data.version)
          }
        })
      }

      return versions
    } catch {
      core.warning('Failed to parse package-lock.json for resolved versions')
    }
  }

  return versions
}

/**
 * Resolve a package version from the lockfile map.
 * Tries "name@specifier" first (yarn.lock), then just "name" (package-lock.json).
 * Falls back to stripping the range prefix if not found in lockfile.
 */
const resolveVersion = (
  name: string,
  specifier: string,
  lockfileVersions: Map<string, string>
): string =>
  lockfileVersions.get(`${name}@${specifier}`) ??
  lockfileVersions.get(name) ??
  specifier.replaceAll(/[^\d.-]/g, '')

/**
 * Run integrity checks (signature audit + lockfile hashes)
 * Returns combined integrity results, or empty results if checks unavailable
 */
const runIntegrityChecks = (rootPath: string): TIntegrityResult => {
  const signatureResult = runSignatureAudit(rootPath)
  const lockfileHashes = parseLockfileIntegrities(rootPath)

  return {
    invalidSignatures: signatureResult.invalid,
    missingSignatures: signatureResult.missing,
    lockfileHashes,
  }
}

/**
 * Check integrity status for a specific package
 */
const checkIntegrityStatus = (
  packageName: string,
  integrityResult: TIntegrityResult
): string | undefined => {
  if (integrityResult.invalidSignatures.has(packageName)) {
    return 'Integrity: Invalid registry signature'
  }

  if (integrityResult.missingSignatures.has(packageName)) {
    // Check if lockfile has hash as fallback
    if (!integrityResult.lockfileHashes.has(packageName)) {
      return 'Integrity: No signature or lockfile hash'
    }
    // Has lockfile hash but no signature - informational only, not a risk
    return undefined
  }

  return undefined
}

/**
 * Execute audit command and return stdout
 * Uses yarn audit if yarn.lock exists, otherwise npm audit
 */
const executeAudit = (
  rootPath: string
): { result: string | undefined; isYarn: boolean } => {
  const hasYarnLock = fs.existsSync(join(rootPath, 'yarn.lock'))
  const hasPackageLock = fs.existsSync(join(rootPath, 'package-lock.json'))

  // Prefer yarn audit if yarn.lock exists
  if (hasYarnLock) {
    try {
      const result = execSync('yarn audit --json 2>/dev/null', {
        cwd: rootPath,
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024,
      })
      return { result, isYarn: true }
    } catch (error) {
      // yarn audit exits with non-zero when vulnerabilities found
      const execError = error as { stdout?: string }
      if (execError.stdout) {
        return { result: execError.stdout, isYarn: true }
      }
      // If yarn audit fails completely, fall through to npm if package-lock exists
      if (!hasPackageLock) {
        return { result: undefined, isYarn: true }
      }
    }
  }

  // Fall back to npm audit
  if (hasPackageLock) {
    try {
      const result = execSync('npm audit --json 2>/dev/null', {
        cwd: rootPath,
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024,
      })
      return { result, isYarn: false }
    } catch (error) {
      const execError = error as { stdout?: string }
      if (execError.stdout) {
        return { result: execError.stdout, isYarn: false }
      }
    }
  }

  return { result: undefined, isYarn: hasYarnLock }
}

/**
 * Parse yarn audit JSON output (newline-delimited JSON)
 */
type TYarnAuditAdvisory = {
  type: 'auditAdvisory'
  data: {
    resolution: {
      id: number
      path: string
      dev: boolean
      optional: boolean
      bundled: boolean
    }
    advisory: {
      module_name: string
      severity: string
      url: string
      recommendation: string
      title: string
      findings: Array<{
        version: string
        paths: string[]
      }>
    }
  }
}

const parseYarnAuditOutput = (
  result: string,
  directDeps: Set<string>
): {
  directVulns: Map<string, TNpmAuditVulnerability>
  indirectVulns: TIndirectVulnerability[]
} => {
  const directVulns = new Map<string, TNpmAuditVulnerability>()
  const indirectVulns: TIndirectVulnerability[] = []

  // Yarn outputs newline-delimited JSON
  const lines = result.split('\n').filter((line) => line.trim())

  lines.forEach((line) => {
    try {
      const parsed = JSON.parse(line) as TYarnAuditAdvisory | { type: string }
      if (parsed.type === 'auditAdvisory') {
        const advisory = parsed as TYarnAuditAdvisory
        const {
          module_name: name,
          severity,
          url,
          recommendation,
          findings,
        } = advisory.data.advisory
        const {
          path: depPath,
          dev,
          id: resolutionId,
        } = advisory.data.resolution

        // Extract version from findings
        const version = findings?.[0]?.version || 'unknown'

        // Check if this is a direct dependency
        const isDirect = directDeps.has(name)

        if (isDirect) {
          // Create a compatible structure for direct vulnerabilities
          if (!directVulns.has(name)) {
            directVulns.set(name, {
              name,
              severity: severity as TNpmAuditVulnerability['severity'],
              isDirect: true,
              via: [{ source: resolutionId, name, url }],
              effects: [],
              range: '*',
              fixAvailable: !!recommendation,
            })
          }
        } else {
          // Indirect/transitive vulnerability
          const vulnPath = depPath || `(transitive) > ${name}`
          const key = `${name}|${version}|${vulnPath}`
          const existing = existingIndirectVerifications.get(key)

          indirectVulns.push({
            name,
            version,
            severity,
            advisory: url || 'See yarn audit',
            recommendation: recommendation || 'Check for updates',
            type: dev ? 'Dev' : 'Transitive',
            dependencyPath: vulnPath,
            verification: existing?.verification ?? DEFAULT_VERIFICATION_RISK,
          })
        }
      }
    } catch {
      // Skip unparseable lines
    }
  })

  return { directVulns, indirectVulns }
}

/**
 * Parse npm audit JSON output
 */
const parseNpmAuditOutput = (
  result: string
): {
  directVulns: Map<string, TNpmAuditVulnerability>
  indirectVulns: TIndirectVulnerability[]
} => {
  const directVulns = new Map<string, TNpmAuditVulnerability>()
  const indirectVulns: TIndirectVulnerability[] = []

  const auditData = JSON.parse(result) as TNpmAuditResult

  if (auditData.vulnerabilities) {
    Object.entries(auditData.vulnerabilities).forEach(([name, vuln]) => {
      if (vuln.isDirect) {
        directVulns.set(name, vuln)
      } else {
        // Indirect/transitive vulnerability
        const advisory =
          vuln.via && typeof vuln.via[0] === 'object' && vuln.via[0].url
            ? vuln.via[0].url
            : 'See npm audit'

        let recommendation = 'Check for updates'
        if (vuln.fixAvailable) {
          if (typeof vuln.fixAvailable === 'object') {
            recommendation = `Upgrade ${vuln.fixAvailable.name} to ${vuln.fixAvailable.version}`
            if (vuln.fixAvailable.isSemVerMajor) {
              recommendation += ' (major version change)'
            }
          } else {
            recommendation = 'Run npm audit fix'
          }
        }

        // Build dependency path from effects
        const dependencyPath =
          vuln.effects.length > 0
            ? `${vuln.effects[0]} > ${name}`
            : `(transitive) > ${name}`

        const version = vuln.range || 'unknown'
        const key = `${name}|${version}|${dependencyPath}`
        const existingVerification = existingIndirectVerifications.get(key)

        indirectVulns.push({
          name,
          version,
          severity: vuln.severity,
          advisory,
          recommendation,
          type: 'Transitive',
          dependencyPath,
          verification:
            existingVerification?.verification ?? DEFAULT_VERIFICATION_RISK,
        })
      }
    })
  }

  return { directVulns, indirectVulns }
}

/**
 * Run audit and parse results
 * Uses yarn audit if yarn.lock exists, otherwise npm audit
 * Returns vulnerability data for direct and indirect dependencies
 */
const runAudit = (
  rootPath: string,
  directDeps: Set<string>
): {
  directVulns: Map<string, TNpmAuditVulnerability>
  indirectVulns: TIndirectVulnerability[]
} => {
  const { result, isYarn } = executeAudit(rootPath)

  if (!result) {
    core.warning(
      `${isYarn ? 'yarn' : 'npm'} audit failed - continuing without audit data`
    )
    return {
      directVulns: new Map<string, TNpmAuditVulnerability>(),
      indirectVulns: [],
    }
  }

  try {
    if (isYarn) {
      return parseYarnAuditOutput(result, directDeps)
    }
    return parseNpmAuditOutput(result)
  } catch (error) {
    core.warning(
      `${isYarn ? 'yarn' : 'npm'} audit parse failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      } - continuing without audit data`
    )
    return {
      directVulns: new Map<string, TNpmAuditVulnerability>(),
      indirectVulns: [],
    }
  }
}

/**
 * Format npm audit findings for a direct dependency
 */
const formatAuditFinding = (vuln: TNpmAuditVulnerability): string => {
  const severityMap: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    moderate: 'Moderate',
    low: 'Low',
    info: 'Info',
  }
  return `npm audit: ${severityMap[vuln.severity] ?? vuln.severity} severity`
}

/**
 * Generate markdown section for indirect/dev vulnerabilities
 */
const generateIndirectVulnerabilitiesSection = (
  vulns: TIndirectVulnerability[]
): string => {
  if (vulns.length === 0) return ''

  const header = `## Indirect and Development Dependencies

The following vulnerabilities were found in transitive or development dependencies. These are not direct dependencies but may still pose a risk.

| Package | Version | Dependency Path | Severity | Advisory | Recommendation | Type | Verification |
|---------|---------|-----------------|----------|----------|----------------|------|--------------|
`

  const rows = vulns
    .map(
      (v) =>
        `| ${v.name} | ${v.version} | ${v.dependencyPath} | ${v.severity} | ${v.advisory} | ${v.recommendation} | ${v.type} | ${v.verification} |`
    )
    .join('\n')

  return `\n\n${header}${rows}`
}

/**
 * Check if package is deprecated via NPM registry data
 */
const checkDeprecation = (
  npmData: TNpmData,
  version: string
): string | undefined => {
  if (!npmData?.versions) return undefined
  const cleanVersion = version.replaceAll(/[^\d.-]/g, '')
  const versionData = npmData.versions[cleanVersion]
  if (versionData?.deprecated) {
    return `Deprecated: ${versionData.deprecated}`
  }
  return undefined
}

/**
 * Check if package is abandoned (no updates in >2 years)
 */
const checkAbandonment = (npmData: TNpmData): string | undefined => {
  if (!npmData?.time?.modified) return undefined
  const lastModified = new Date(npmData.time.modified)
  const twoYearsAgo = new Date()
  twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2)

  if (lastModified < twoYearsAgo) {
    const years = Math.floor(
      (Date.now() - lastModified.getTime()) / (365 * 24 * 60 * 60 * 1000)
    )
    return `Abandoned: No updates in ${years} years`
  }
  return undefined
}

/**
 * Check version lag against latest available version
 * Returns risk reason if significantly behind:
 * - >1 minor version behind (same major) → Medium risk
 * - 1 major version behind → Medium risk
 * - 2+ major versions behind → High risk
 */
const checkVersionLag = (
  npmData: TNpmData,
  installedVersion: string
): { reason: string | undefined; severity: 'high' | 'medium' | undefined } => {
  if (!npmData?.versions) return { reason: undefined, severity: undefined }

  // Get all stable versions (exclude prereleases and deprecated versions)
  const allVersions = Object.keys(npmData.versions)
    .filter((v) => {
      const coerced = coerce(v)
      const isDeprecated = npmData.versions[v]?.deprecated
      return coerced && !prerelease(v) && !isDeprecated
    })
    .sort((a, b) => {
      const coercedA = coerce(a)
      const coercedB = coerce(b)
      if (!coercedA || !coercedB) return 0
      return compare(coercedA, coercedB)
    })

  if (allVersions.length === 0)
    return { reason: undefined, severity: undefined }

  const latestVersion = allVersions.at(-1)
  if (!latestVersion) return { reason: undefined, severity: undefined }

  const installedCoerced = coerce(installedVersion)
  const latestCoerced = coerce(latestVersion)

  if (!installedCoerced || !latestCoerced)
    return { reason: undefined, severity: undefined }

  const installedMajor = major(installedCoerced)
  const latestMajor = major(latestCoerced)
  const installedMinor = minor(installedCoerced)
  const latestMinor = minor(latestCoerced)

  const majorsBehind = latestMajor - installedMajor

  if (majorsBehind >= 2) {
    return {
      reason: `Version lag: ${majorsBehind} major versions behind (${installedCoerced.version} → ${latestCoerced.version})`,
      severity: 'high',
    }
  }

  if (majorsBehind === 1) {
    return {
      reason: `Version lag: 1 major version behind (${installedCoerced.version} → ${latestCoerced.version})`,
      severity: 'medium',
    }
  }

  // Same major version - check minor version lag
  const minorsBehind = latestMinor - installedMinor

  if (minorsBehind > 1) {
    return {
      reason: `Version lag: ${minorsBehind} minor versions behind (${installedCoerced.version} → ${latestCoerced.version})`,
      severity: 'medium',
    }
  }

  return { reason: undefined, severity: undefined }
}

/**
 * Check if a version matches a single OSV range
 */
const checkOsvRange = (
  normalizedVersion: string,
  range: NonNullable<TOsvVulnerability['affected']>[0]['ranges'] extends
    | (infer R)[]
    | undefined
    ? R
    : never
): boolean => {
  if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') {
    // Can't check GIT ranges, assume affected
    return true
  }

  // Extract introduced and fixed from events
  const introduced = range.events.find((event) => event.introduced)?.introduced
  const fixed = range.events.find((event) => event.fixed)?.fixed

  // Normalize "0" to "0.0.0"
  const normalizedIntroduced = introduced === '0' ? '0.0.0' : introduced

  // Build range string and check
  if (normalizedIntroduced && fixed) {
    const rangeString = `>=${normalizedIntroduced} <${fixed}`
    try {
      return satisfies(normalizedVersion, rangeString)
    } catch {
      return true // Invalid range, assume affected
    }
  }
  if (normalizedIntroduced && !fixed) {
    // No fix available, all versions >= introduced are affected
    const rangeString = `>=${normalizedIntroduced}`
    try {
      return satisfies(normalizedVersion, rangeString)
    } catch {
      return true
    }
  }
  return false
}

const isVersionAffected = (
  vuln: TOsvVulnerability,
  version: string
): boolean => {
  // Normalize version for semver comparison
  const normalizedVersion = coerce(version)?.version
  if (!normalizedVersion) return true // If we can't parse, assume affected (safe default)

  // If no affected info, assume affected
  if (!vuln.affected || vuln.affected.length === 0) return true

  // Check each affected entry using .some()
  return vuln.affected.some((affected) => {
    // Check explicit version list first
    if (affected.versions?.includes(version)) {
      return true
    }

    // Check version ranges
    if (affected.ranges) {
      return affected.ranges.some((range) =>
        checkOsvRange(normalizedVersion, range)
      )
    }

    return false
  })
}

/**
 * Query OSV API for known vulnerabilities affecting the specific version
 */
const checkVulnerabilities = async (
  packageName: string,
  version: string
): Promise<string | undefined> => {
  try {
    const cleanVersion = version.replaceAll(/[^\d.-]/g, '')
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: packageName, ecosystem: 'npm' },
        version: cleanVersion,
      }),
    })

    if (!response.ok) {
      trackApiFailure(
        'OSV API',
        packageName,
        new Error(`HTTP ${response.status}`)
      )
      return undefined
    }

    const data = (await response.json()) as TOsvResponse
    if (data.vulns && data.vulns.length > 0) {
      // Filter to only vulnerabilities that actually affect this version
      const affectingVulns = data.vulns.filter((vuln) =>
        isVersionAffected(vuln, cleanVersion)
      )

      if (affectingVulns.length > 0) {
        const vulnLinks = affectingVulns
          .slice(0, 3)
          .map((v) => `[${v.id}](https://osv.dev/vulnerability/${v.id})`)
          .join(', ')
        const suffix =
          affectingVulns.length > 3
            ? ` (+${affectingVulns.length - 3} more)`
            : ''
        return `Vulnerabilities: ${vulnLinks}${suffix}`
      }
    }
    return undefined
  } catch (error) {
    trackApiFailure('OSV API', packageName, error)
    return undefined
  }
}

/**
 * Check GitHub repo status (archived, last push date)
 */
const checkGitHubRepoStatus = async (
  repoUrl: string,
  packageName: string
): Promise<{
  archived: string | undefined
  lowMaintenance: string | undefined
  unverifiable: string | undefined
}> => {
  try {
    const { owner, name } = parseGithubUrl(repoUrl) ?? {}
    if (!owner || !name)
      return {
        archived: undefined,
        lowMaintenance: undefined,
        unverifiable: undefined,
      }

    const response = await octokit.request('GET /repos/{owner}/{name}', {
      owner,
      name,
    })

    if (response.status !== 200) {
      trackApiFailure(
        'GitHub Repo API',
        packageName,
        new Error(`HTTP ${response.status}`)
      )
      return {
        archived: undefined,
        lowMaintenance: undefined,
        unverifiable: undefined,
      }
    }

    const data = response.data as TGitHubRepoData
    const result: {
      archived: string | undefined
      lowMaintenance: string | undefined
      unverifiable: string | undefined
    } = {
      archived: undefined,
      lowMaintenance: undefined,
      unverifiable: undefined,
    }

    if (data.archived) {
      result.archived = 'Repository archived'
    }

    if (data.pushed_at) {
      const lastPush = new Date(data.pushed_at)
      const oneYearAgo = new Date()
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1)

      if (lastPush < oneYearAgo) {
        const months = Math.floor(
          (Date.now() - lastPush.getTime()) / (30 * 24 * 60 * 60 * 1000)
        )
        result.lowMaintenance = `Low maintenance: No commits in ${months} months`
      }
    }

    return result
  } catch (error) {
    // 404 means repo not found (private, deleted, or wrong URL) - flag as unverifiable, not a failure
    const { status } = error as { status?: number }
    if (status === 404) {
      core.warning(
        `Repository not found for ${packageName} - flagging as unverifiable`
      )
      return {
        archived: undefined,
        lowMaintenance: undefined,
        unverifiable: 'Repository not found (private or deleted)',
      }
    }
    trackApiFailure('GitHub Repo API', packageName, error)
    return {
      archived: undefined,
      lowMaintenance: undefined,
      unverifiable: undefined,
    }
  }
}

/**
 * Check if a version is affected by a GitHub advisory's vulnerable_version_range
 * GitHub format: ">= 5.16.0, <= 5.19.0" or "< 1.2.3" etc.
 */
const isVersionAffectedByAdvisory = (
  version: string,
  vulnerableRange: string | undefined
): boolean => {
  if (!vulnerableRange) return true // No range specified, assume affected

  const normalizedVersion = coerce(version)?.version
  if (!normalizedVersion) return true // Can't parse, assume affected

  try {
    // Convert GitHub format to semver format
    // GitHub uses ", " to separate conditions, semver uses " "
    const semverRange = vulnerableRange.replaceAll(/,\s*/g, ' ')
    return satisfies(normalizedVersion, semverRange)
  } catch {
    // Invalid range, assume affected
    return true
  }
}

type TGitHubAdvisory = {
  ghsa_id: string
  vulnerabilities?: Array<{
    package?: {
      ecosystem?: string
      name?: string
    }
    vulnerable_version_range?: string
  }>
}

/**
 * Check for open security advisories on GitHub that affect the specific version
 * Returns advisory info, or undefined if none found, or special "unverifiable" string for 404s
 */
const checkSecurityAdvisories = async (
  repoUrl: string,
  packageName: string,
  version: string
): Promise<{
  advisories: string | undefined
  unverifiable: string | undefined
}> => {
  try {
    const { owner, name } = parseGithubUrl(repoUrl) ?? {}
    if (!owner || !name)
      return { advisories: undefined, unverifiable: undefined }

    const cleanVersion = version.replaceAll(/[^\d.-]/g, '')

    const response = await octokit.request(
      'GET /repos/{owner}/{name}/security-advisories',
      {
        owner,
        name,
        state: 'published',
      }
    )

    if (response.status !== 200) {
      trackApiFailure(
        'GitHub Advisories API',
        packageName,
        new Error(`HTTP ${response.status}`)
      )
      return { advisories: undefined, unverifiable: undefined }
    }

    const advisories = response.data as TGitHubAdvisory[]
    if (advisories && advisories.length > 0) {
      // Filter to only advisories that affect our version
      const affectingAdvisories = advisories.filter((advisory) => {
        // If no vulnerabilities info, assume affected
        if (
          !advisory.vulnerabilities ||
          advisory.vulnerabilities.length === 0
        ) {
          return true
        }

        // Check if any vulnerability in this advisory affects our package and version
        return advisory.vulnerabilities.some((vuln) => {
          // Check if this vulnerability is for npm ecosystem
          if (vuln.package?.ecosystem && vuln.package.ecosystem !== 'npm') {
            return false
          }

          // Check version range
          return isVersionAffectedByAdvisory(
            cleanVersion,
            vuln.vulnerable_version_range
          )
        })
      })

      if (affectingAdvisories.length > 0) {
        const advisoryLinks = affectingAdvisories
          .slice(0, 3)
          .map(
            (a) => `[${a.ghsa_id}](https://github.com/advisories/${a.ghsa_id})`
          )
          .join(', ')
        const suffix =
          affectingAdvisories.length > 3
            ? ` (+${affectingAdvisories.length - 3} more)`
            : ''
        return {
          advisories: `Advisories: ${advisoryLinks}${suffix}`,
          unverifiable: undefined,
        }
      }
    }
    return { advisories: undefined, unverifiable: undefined }
  } catch (error) {
    // 404 means repo not found - flag as unverifiable, not a failure
    const { status } = error as { status?: number }
    if (status === 404) {
      // Don't log warning here - checkGitHubRepoStatus will already log it
      return {
        advisories: undefined,
        unverifiable: 'Advisories not verifiable (repo not found)',
      }
    }
    trackApiFailure('GitHub Advisories API', packageName, error)
    return { advisories: undefined, unverifiable: undefined }
  }
}

/**
 * Perform all risk checks and calculate overall risk level
 */
const analyzeRisk = async (
  npmData: TNpmData,
  packageName: string,
  version: string,
  repoUrl: string | undefined,
  licenseRisk: TLicenseRisk,
  integrityResult: TIntegrityResult,
  npmAuditVuln: TNpmAuditVulnerability | undefined
): Promise<TRiskAnalysis> => {
  const reasons: string[] = []

  const deprecation = checkDeprecation(npmData, version)
  const abandonment = checkAbandonment(npmData)
  const versionLag = checkVersionLag(npmData, version)
  const integrityStatus = checkIntegrityStatus(packageName, integrityResult)

  const [vulnResult, repoStatus, advisoriesResult] = await Promise.all([
    checkVulnerabilities(packageName, version),
    repoUrl
      ? checkGitHubRepoStatus(repoUrl, packageName)
      : Promise.resolve({
          archived: undefined,
          lowMaintenance: undefined,
          unverifiable: undefined,
        }),
    repoUrl
      ? checkSecurityAdvisories(repoUrl, packageName, version)
      : Promise.resolve({ advisories: undefined, unverifiable: undefined }),
  ])

  if (deprecation) reasons.push(deprecation)
  if (abandonment) reasons.push(abandonment)
  if (versionLag.reason) reasons.push(versionLag.reason)
  if (vulnResult) reasons.push(vulnResult)
  if (repoStatus.archived) reasons.push(repoStatus.archived)
  if (repoStatus.lowMaintenance) reasons.push(repoStatus.lowMaintenance)
  if (repoStatus.unverifiable) reasons.push(repoStatus.unverifiable)
  if (advisoriesResult.advisories) reasons.push(advisoriesResult.advisories)
  // Only add advisories unverifiable if repo wasn't already flagged as unverifiable
  if (advisoriesResult.unverifiable && !repoStatus.unverifiable) {
    reasons.push(advisoriesResult.unverifiable)
  }
  // Add license risk reason if any
  if (licenseRisk.reason) reasons.push(licenseRisk.reason)
  // Add integrity status if any issues
  if (integrityStatus) reasons.push(integrityStatus)
  // Add npm audit finding if any
  if (npmAuditVuln) reasons.push(formatAuditFinding(npmAuditVuln))

  // Check if any verification was impossible
  const hasUnverifiable =
    repoStatus.unverifiable || advisoriesResult.unverifiable

  // Check for integrity issues (only if we got valid results)
  const hasIntegrityIssue =
    integrityResult.invalidSignatures.size > 0 ||
    integrityResult.missingSignatures.size > 0
      ? !!integrityStatus
      : false

  // Check for high severity npm audit findings
  const hasHighAuditFinding =
    npmAuditVuln &&
    (npmAuditVuln.severity === 'critical' || npmAuditVuln.severity === 'high')

  let level: TRiskAnalysis['level'] = 'Low'

  if (deprecation || vulnResult || repoStatus.archived || hasHighAuditFinding) {
    level = 'Critical'
  } else if (
    abandonment ||
    advisoriesResult.advisories ||
    versionLag.severity === 'high' ||
    licenseRisk.risk === 'High'
  ) {
    level = 'High'
  } else if (
    repoStatus.lowMaintenance ||
    hasUnverifiable ||
    versionLag.severity === 'medium' ||
    licenseRisk.risk === 'Medium' ||
    hasIntegrityIssue
  ) {
    // Unverifiable packages, license issues, or integrity issues get Medium risk
    level = 'Medium'
  }

  return {
    level,
    reasons: reasons.length > 0 ? reasons : ['Passed all automated checks'],
  }
}

/**
 * Determine the verification text for a package based on risk level and existing values
 * @param packageName string: name of the package
 * @param currentVersion string: current version being analyzed
 * @param riskLevel string: calculated risk level
 */
const getVerification = (
  packageName: string,
  currentVersion: string,
  currentRiskLevel: string,
  currentRiskDetails: string
): string => {
  const existing = existingVerifications.get(packageName)

  if (existing) {
    const changes: string[] = []

    // Check if version changed
    const normalizedCurrent = coerce(currentVersion)?.version
    const normalizedExisting = coerce(existing.version)?.version
    if (
      normalizedCurrent &&
      normalizedExisting &&
      normalizedCurrent !== normalizedExisting
    ) {
      changes.push(`version ${normalizedExisting} → ${normalizedCurrent}`)
    }

    // Check if risk level changed
    if (currentRiskLevel !== existing.riskLevel) {
      changes.push(`risk ${existing.riskLevel} → ${currentRiskLevel}`)
    }

    // Check if risk details changed (new issues found)
    if (currentRiskDetails !== existing.riskDetails) {
      changes.push('risk details changed')
    }

    if (changes.length > 0) {
      // Something changed - flag for re-assessment
      const changesSummary = changes.join(', ')
      return `⚠️ Re-assess needed (${changesSummary}). Previous note: ${existing.verification}`
    }

    // Nothing changed, preserve custom verification
    return existing.verification
  }

  // No existing verification, set based on risk level
  return currentRiskLevel === 'Low'
    ? DEFAULT_VERIFICATION_LOW
    : DEFAULT_VERIFICATION_RISK
}

/**
 * Method to request SOUP package information from NPM
 * @param soupName string: name of the SOUP as listed in our package file
 * @param soupVersion string: version of the SOUP as listed in our lockfile
 * @param flagGplAsHighRisk boolean: whether to treat GPL/AGPL as High risk
 * @param integrityResult TIntegrityResult: results from integrity checks
 * @param auditVulns Map: npm audit vulnerabilities for direct dependencies
 */
const getSoupDataForPackage = async (
  soupName: string,
  soupVersion: string,
  flagGplAsHighRisk: boolean,
  integrityResult: TIntegrityResult,
  auditVulns: Map<string, TNpmAuditVulnerability>
): Promise<TSoupData> => {
  const soupDataResponse = await fetch(`https://registry.npmjs.org/${soupName}`)
  const soupData = (await soupDataResponse.json()) as TNpmData

  let soupLanguages = 'unknown'
  let soupSite = 'private repo'
  let repoUrl: string | undefined

  // Extract license from NPM data
  const soupLicense = soupData?.license ?? 'Unknown'
  const licenseRisk = checkLicenseRisk(soupData?.license, flagGplAsHighRisk)

  if (soupData?.versions) {
    const versionSpecificSoupData =
      soupData?.versions[soupVersion.replaceAll(/[^\d.-]/g, '')]

    if (versionSpecificSoupData?.repository?.url) {
      repoUrl = versionSpecificSoupData.repository.url

      if (repoUrl.includes('github')) {
        soupLanguages = await getSoupLanguageData(repoUrl)
      }
    }

    soupSite =
      versionSpecificSoupData?.homepage ||
      versionSpecificSoupData?.repository?.url ||
      'unknown'
  }

  // Get npm audit vulnerability for this package if any
  const npmAuditVuln = auditVulns.get(soupName)

  const riskAnalysis = await analyzeRisk(
    soupData,
    soupName,
    soupVersion,
    repoUrl,
    licenseRisk,
    integrityResult,
    npmAuditVuln
  )

  return {
    soupName,
    soupLanguages,
    soupSite,
    soupLicense,
    soupVersion,
    soupRiskLevel: riskAnalysis.level,
    soupRiskDetails: riskAnalysis.reasons.join('; '),
    soupVerification: getVerification(
      soupName,
      soupVersion,
      riskAnalysis.level,
      riskAnalysis.reasons.join('; ')
    ),
  }
}

/**
 * Method to format SOUP data for one package as a table
 * @param soupData TSoupData: the data generated by the other methods
 */
const generateSoupTable = (soupData: TSoupData[]) => {
  const tableHeader =
    '| Package Name | Programming Languages | Website | License | Version | Risk Level | Risk Details | Verification |\n|---|---|---|---|---|---|---|---|\n'
  const tableContents: string[] = []
  soupData.forEach((data) => {
    tableContents.push(
      `| ${data.soupName} | ${data.soupLanguages} | ${data.soupSite} | ${data.soupLicense} | ${data.soupVersion} | ${data.soupRiskLevel} | ${data.soupRiskDetails} | ${data.soupVerification} |`
    )
  })
  return tableHeader + tableContents.sort().join('\n')
}

/**
 * Method to recursively go though all of the repo to find all "package.json" files
 * that might be part of the (mono)repo project
 * @param directory string: the directory to start/continue the recursive search in
 * @param resultArray string[]: the array we pass through recursively and fill with all results
 */
const findFilesRecursive = (directory: string, resultArray: string[]) => {
  fs.readdirSync(directory).forEach((file: string) => {
    const subpath = path.join(directory, file)
    if (fs.lstatSync(subpath).isDirectory()) {
      // Skip node_modules folder
      if (subpath.includes('node_modules')) return
      // don't try to find package.json files in folders like .git or .github
      if (subpath.includes('/.')) return
      findFilesRecursive(subpath, resultArray)
    } else if (file === 'package.json') {
      resultArray.push(`${directory}/${file}`)
    }
  })
}

/**
 * Method to generate a SOUP table for a single package.json. Most repositories will only call this method once
 * But in mono-repos this will be called once for each package.json file in the subfolders of the repo
 * (excluding node_modules)
 * @param packageJSON TPackageJson: the contents of a single package JSON to generate a SOUP table for
 * @param flagGplAsHighRisk boolean: whether to treat GPL/AGPL as High risk
 * @param integrityResult TIntegrityResult: results from integrity checks
 * @param auditVulns Map: npm audit vulnerabilities for direct dependencies
 */
const getSoupDataForPackageCollection = async (
  packageJSON: TPackageJson,
  flagGplAsHighRisk: boolean,
  integrityResult: TIntegrityResult,
  auditVulns: Map<string, TNpmAuditVulnerability>,
  lockfileVersions: Map<string, string>
) => {
  const soupDataRequests = <Promise<TSoupData>[]>[]

  if (packageJSON.dependencies) {
    Object.entries(packageJSON.dependencies).forEach(
      ([soupName, soupSpecifier]) => {
        const soupVersion = resolveVersion(
          soupName,
          soupSpecifier,
          lockfileVersions
        )
        soupDataRequests.push(
          getSoupDataForPackage(
            soupName,
            soupVersion,
            flagGplAsHighRisk,
            integrityResult,
            auditVulns
          )
        )
      }
    )
  }

  const soupData = await Promise.all(soupDataRequests)

  const header = `## ${packageJSON.name}\n\n`
  const table = generateSoupTable(soupData)

  return header + table
}

/**
 * Method to generate a list of unique dependencies from a list of package.json contents.
 * @param packageJSONs TPackageJson[]: the contents of one or more package JSON to generate a unique list of names
 */
const getUniqueDependencies = (packageJSONs: TPackageJson[]) => {
  const dependencies = new Set<string>()

  packageJSONs.forEach((packageJSON) => {
    if (packageJSON.dependencies) {
      Object.keys(packageJSON.dependencies).forEach((dependency) =>
        dependencies.add(dependency)
      )
    }
  })

  return [...dependencies]
}

/**
 * Parse existing SOUP.md to extract verification values for each package.
 * This allows preserving custom verification text across regenerations.
 * @param soupPath string: path to the existing SOUP.md file
 */
const parseExistingVerifications = (soupPath: string) => {
  existingVerifications = new Map()

  if (!fs.existsSync(soupPath)) return

  try {
    const content = fs.readFileSync(soupPath, 'utf8')
    const lines = content.split('\n')

    // Filter to table data rows and extract verifications
    // Skip separator rows (---) and header row (Package Name)
    lines
      .filter(
        (line) =>
          line.startsWith('|') &&
          !line.includes('---') &&
          !line.includes('Package Name')
      )
      .forEach((line) => {
        const cells = line
          .split('|')
          .map((cell) => cell.trim())
          .filter((cell) => cell.length > 0)

        // Table has 8 columns: Name, Languages, Website, License, Version, Risk Level, Risk Details, Verification
        // Also support old 7-column format for backwards compatibility
        if (cells.length >= 8) {
          // New format with License column
          const packageName = cells[0]
          const version = cells[4]
          const riskLevel = cells[5]
          const riskDetails = cells[6]
          const verification = cells[7]

          // Only store non-default verifications (custom entries)
          // Also exclude entries that are already flagged for re-assessment
          if (
            verification &&
            verification !== DEFAULT_VERIFICATION_LOW &&
            verification !== DEFAULT_VERIFICATION_RISK &&
            !verification.startsWith('⚠️ Re-assess')
          ) {
            existingVerifications.set(packageName, {
              version,
              riskLevel,
              riskDetails,
              verification,
            })
          }
        } else if (cells.length >= 7) {
          // Old format without License column (backwards compatibility)
          const packageName = cells[0]
          const version = cells[3]
          const riskLevel = cells[4]
          const riskDetails = cells[5]
          const verification = cells[6]

          if (
            verification &&
            verification !== DEFAULT_VERIFICATION_LOW &&
            verification !== DEFAULT_VERIFICATION_RISK &&
            !verification.startsWith('⚠️ Re-assess')
          ) {
            existingVerifications.set(packageName, {
              version,
              riskLevel,
              riskDetails,
              verification,
            })
          }
        }
      })

    if (existingVerifications.size > 0) {
      core.info(
        `📝 Preserved ${existingVerifications.size} custom verification entries`
      )
    }
  } catch {
    // If parsing fails, continue with empty map
  }
}

/**
 * Parse existing SOUP.md to extract verification values for indirect dependencies.
 * This allows preserving custom verification text across regenerations.
 * @param soupPath string: path to the existing SOUP.md file
 */
const parseExistingIndirectVerifications = (soupPath: string) => {
  existingIndirectVerifications = new Map()

  if (!fs.existsSync(soupPath)) return

  try {
    const content = fs.readFileSync(soupPath, 'utf8')

    // Find the indirect dependencies section
    const indirectSectionStart = content.indexOf(
      '## Indirect and Development Dependencies'
    )
    if (indirectSectionStart === -1) return

    const indirectContent = content.slice(indirectSectionStart)
    const lines = indirectContent.split('\n')

    // Filter to table data rows
    // Skip separator rows (---) and header row (Package)
    lines
      .filter(
        (line) =>
          line.startsWith('|') &&
          !line.includes('---') &&
          !line.includes('Package')
      )
      .forEach((line) => {
        const cells = line
          .split('|')
          .map((cell) => cell.trim())
          .filter((cell) => cell.length > 0)

        // Table has 8 columns: Package, Version, Dependency Path, Severity,
        // Advisory, Recommendation, Type, Verification
        if (cells.length >= 8) {
          const packageName = cells[0]
          const version = cells[1]
          const dependencyPath = cells[2]
          const verification = cells[7]

          // Create unique key from package, version, and path
          const key = `${packageName}|${version}|${dependencyPath}`

          // Only store non-default verifications (custom entries)
          if (
            verification &&
            verification !== DEFAULT_VERIFICATION_RISK &&
            !verification.startsWith('⚠️ Re-assess')
          ) {
            existingIndirectVerifications.set(key, { verification })
          }
        } else if (cells.length >= 7) {
          // Old format without Verification column - nothing to preserve
        }
      })

    if (existingIndirectVerifications.size > 0) {
      core.info(
        `📝 Preserved ${existingIndirectVerifications.size} custom indirect verification entries`
      )
    }
  } catch {
    // If parsing fails, continue with empty map
  }
}

/**
 * Method to generate a header and intro for the SOUP register
 * @param packageJSONs TPackageJson[]: the contents of one or more package JSON to generate a unique list of names
 * @param flagGplAsHighRisk boolean: whether GPL is flagged as high risk
 */
const generateSoupHeader = (
  packageJSONs: TPackageJson[],
  flagGplAsHighRisk: boolean
) => {
  const header = `# SOUP Register`

  const dependenciesCount = getUniqueDependencies(packageJSONs).length

  const gplRiskNote = flagGplAsHighRisk
    ? 'GPL/AGPL licenses (copyleft - may require source disclosure)'
    : 'GPL/AGPL licenses are flagged as Medium risk'

  const intro = `This document contains a list of all SOUP (Software of Unknown Provenance) dependencies used in this repository. SOUP is third-party software that is included in the project and is not developed by the project team.

Risk levels are automatically calculated based on:
- **Critical**: Package is deprecated, has known vulnerabilities, repository is archived, or has critical/high npm audit findings
- **High**: Package is abandoned (>2 years without updates), has open security advisories, is 2+ major versions behind latest, or ${gplRiskNote}
- **Medium**: Low maintenance activity (>1 year without commits), 1 major version behind, >1 minor versions behind, weak copyleft license (LGPL/MPL), unknown license, or integrity verification issues
- **Low**: Passed all automated checks

License categories:
- **Permissive**: MIT, Apache-2.0, BSD-\\*, ISC (Low risk)
- **Weak Copyleft**: MPL-2.0, LGPL-\\* (Medium risk)
- **Strong Copyleft**: GPL-\\*, AGPL-\\* (${
    flagGplAsHighRisk ? 'High' : 'Medium'
  } risk)

The repository uses a total of ${dependenciesCount} unique SOUP dependencies.`

  return `${header}\n\n${intro}\n\n`
}

/**
 * Check if the SOUP.md file has any git changes (staged, unstaged, or untracked)
 * @param soupPath string: absolute path to SOUP.md
 */
const hasSoupChanges = (soupPath: string): boolean => {
  try {
    const diff = execSync(`git diff --name-only -- "${soupPath}"`, {
      encoding: 'utf8',
    }).trim()

    const untracked = execSync(
      `git ls-files --others --exclude-standard -- "${soupPath}"`,
      { encoding: 'utf8' }
    ).trim()

    return diff.length > 0 || untracked.length > 0
  } catch {
    return true
  }
}

/**
 * Create a branch, commit SOUP.md changes, and force-push to remote
 * @param soupPath string: absolute path to SOUP.md
 * @param branchName string: name of the branch to create/update
 */
const commitAndPushSoup = (soupPath: string, branchName: string): void => {
  const execOptions = {
    encoding: 'utf8' as const,
    cwd: path.dirname(soupPath),
  }

  execSync('git config user.name "github-actions[bot]"', execOptions)
  execSync(
    'git config user.email "41898282+github-actions[bot]@users.noreply.github.com"',
    execOptions
  )

  execSync(`git checkout -B ${branchName}`, execOptions)
  execSync(`git add -- "${soupPath}"`, execOptions)
  execSync('git commit -m "chore: update SOUP register"', execOptions)
  execSync(`git push --force origin ${branchName}`, execOptions)
}

/**
 * Find an existing open PR from the given branch
 * @param owner string: repository owner
 * @param repo string: repository name
 * @param branchName string: the head branch name to search for
 */
const findExistingPr = async (
  owner: string,
  repo: string,
  branchName: string
): Promise<number | undefined> => {
  try {
    const response = await octokit.request('GET /repos/{owner}/{repo}/pulls', {
      owner,
      repo,
      state: 'open',
      head: `${owner}:${branchName}`,
    })

    const pulls = response.data as Array<{ number: number }>
    if (pulls.length > 0) {
      return pulls[0].number
    }
    return undefined
  } catch (error) {
    core.warning(
      `Failed to search for existing PRs: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`
    )
    return undefined
  }
}

/**
 * Create or update a pull request with SOUP.md changes
 * @param soupPath string: absolute path to SOUP.md
 * @param branchName string: PR branch name
 * @param prTitle string: title for the pull request
 * @param prLabels string: comma-separated labels
 */
const createOrUpdatePr = async (
  soupPath: string,
  branchName: string,
  prTitle: string,
  prLabels: string
): Promise<string | undefined> => {
  const { owner, repo } = github.context.repo

  let baseBranch: string
  if (github.context.eventName === 'pull_request') {
    const pr = github.context.payload.pull_request as
      | { base?: { ref?: string } }
      | undefined
    baseBranch = pr?.base?.ref ?? 'main'
  } else {
    baseBranch = github.context.ref.replace('refs/heads/', '')
  }

  core.info(`🔀 Creating branch '${branchName}' and committing SOUP.md...`)
  try {
    commitAndPushSoup(soupPath, branchName)
  } catch (error) {
    core.error(
      `Failed to commit and push: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`
    )
    return undefined
  }

  const existingPrNumber = await findExistingPr(owner, repo, branchName)

  if (existingPrNumber) {
    core.info(`📝 Existing PR #${existingPrNumber} updated via force-push`)

    try {
      await octokit.request('PATCH /repos/{owner}/{repo}/pulls/{pull_number}', {
        owner,
        repo,
        pull_number: existingPrNumber,
        title: prTitle,
      })
    } catch (error) {
      core.warning(
        `Failed to update PR title: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`
      )
    }

    return `https://github.com/${owner}/${repo}/pull/${existingPrNumber}`
  }

  core.info(`🆕 Creating new pull request...`)
  try {
    const prBody = [
      '## SOUP Register Update',
      '',
      'This pull request was automatically generated by the SOUP register action.',
      'Please review the changes to `SOUP.md` and verify any new or updated entries.',
      '',
      '> Entries marked with :warning: require human review.',
    ].join('\n')

    const response = await octokit.request('POST /repos/{owner}/{repo}/pulls', {
      owner,
      repo,
      title: prTitle,
      body: prBody,
      head: branchName,
      base: baseBranch,
    })

    const prData = response.data as { number: number; html_url: string }
    core.info(`✅ Pull request created: ${prData.html_url}`)

    const labels = prLabels
      .split(',')
      .map((l) => l.trim())
      .filter((l) => l.length > 0)

    if (labels.length > 0) {
      try {
        await octokit.request(
          'POST /repos/{owner}/{repo}/issues/{issue_number}/labels',
          { owner, repo, issue_number: prData.number, labels }
        )
        core.info(`🏷️ Applied labels: ${labels.join(', ')}`)
      } catch (error) {
        core.warning(
          `Failed to apply labels: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        )
      }
    }

    return prData.html_url
  } catch (error) {
    core.error(
      `Failed to create pull request: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`
    )
    return undefined
  }
}

/**
 * Main generator method: calls the other methods and combines their output in MD format and stores it in SOUP.md
 */
const generateSoupRegister = async () => {
  core.info(`📋 Starting SOUP generation`)

  const basePath = core.getInput('path')
  const flagGplAsHighRisk = core.getInput('flag-gpl-as-high-risk') !== 'false'
  const rootPath = join(process.cwd(), basePath)
  const soupPath = join(rootPath, DEFAULT_SOUP_FILENAME)

  // Parse existing SOUP.md to preserve custom verifications
  parseExistingVerifications(soupPath)
  parseExistingIndirectVerifications(soupPath)

  // Parse lockfile to resolve exact installed versions
  core.info(`📦 Resolving package versions from lockfile...`)
  const lockfileVersions = parseLockfileVersions(rootPath)

  // Run integrity checks (signature audit + lockfile hashes)
  core.info(`🔐 Running integrity checks...`)
  const integrityResult = runIntegrityChecks(rootPath)
  if (integrityResult.invalidSignatures.size > 0) {
    core.warning(
      `Found ${integrityResult.invalidSignatures.size} packages with invalid signatures`
    )
  }
  if (integrityResult.missingSignatures.size > 0) {
    core.info(
      `Found ${integrityResult.missingSignatures.size} packages without signatures (lockfile hashes will be checked)`
    )
  }

  // get array of package.json paths
  const packageJSONPaths: string[] = []
  findFilesRecursive(rootPath, packageJSONPaths)

  // Read SOUP dependencies from package json
  const packageJSONs = packageJSONPaths
    .map((packageJSONPath) => {
      const packageString = fs.readFileSync(packageJSONPath).toString()
      const packageJSON = JSON.parse(packageString) as TPackageJson
      return packageJSON
    })
    // filter out package.json files without dependencies
    .filter((packageJSON) => !!packageJSON.dependencies)

  // Collect all direct dependencies for audit classification
  const directDeps = new Set<string>()
  packageJSONs.forEach((package_) => {
    if (package_.dependencies) {
      Object.keys(package_.dependencies).forEach((dep) => directDeps.add(dep))
    }
  })

  // Run audit (yarn or npm depending on lockfile)
  core.info(`🔍 Running security audit...`)
  const { directVulns: auditVulns, indirectVulns } = runAudit(
    rootPath,
    directDeps
  )
  if (auditVulns.size > 0) {
    core.warning(
      `Found ${auditVulns.size} direct dependencies with audit findings`
    )
  }
  if (indirectVulns.length > 0) {
    core.info(
      `Found ${indirectVulns.length} indirect/transitive vulnerabilities`
    )
  }

  const repositorySoupRequests = <Promise<string>[]>[]

  packageJSONs.forEach((packageJson) =>
    repositorySoupRequests.push(
      getSoupDataForPackageCollection(
        packageJson,
        flagGplAsHighRisk,
        integrityResult,
        auditVulns,
        lockfileVersions
      )
    )
  )

  const soupData = await Promise.all(repositorySoupRequests)

  // Check for API failures before writing - don't override historic data with incomplete data
  if (apiFailures.length > 0) {
    core.error(
      `❌ ${apiFailures.length} API call(s) failed during risk analysis:`
    )
    apiFailures.forEach((failure) => core.error(`  - ${failure}`))
    core.setFailed(
      'SOUP generation aborted due to API failures. Existing SOUP.md preserved to prevent data loss.'
    )
    return
  }

  const soupHeader = generateSoupHeader(packageJSONs, flagGplAsHighRisk)

  // Generate indirect vulnerabilities section
  const indirectSection = generateIndirectVulnerabilitiesSection(indirectVulns)

  const soupRegister = soupHeader + soupData.join('\n\n') + indirectSection

  core.info(`✅ SOUP data retrieved`)

  // Write SOUP file
  try {
    fs.writeFileSync(soupPath, soupRegister, { encoding: 'utf8', flag: 'w' })
    core.info(`✅ SOUP register written to ${DEFAULT_SOUP_FILENAME}`)
  } catch (error) {
    core.error(error instanceof Error ? error : String(error))
    core.setFailed(error instanceof Error ? error : String(error))
    return
  }

  // Handle PR creation if enabled
  const createPr = core.getInput('create-pr') === 'true'

  if (createPr) {
    if (hasSoupChanges(soupPath)) {
      const branchName = core.getInput('pr-branch') || 'soup-register-update'
      const prTitle = core.getInput('pr-title') || 'chore: update SOUP register'
      const prLabels = core.getInput('pr-labels') || ''

      const prUrl = await createOrUpdatePr(
        soupPath,
        branchName,
        prTitle,
        prLabels
      )
      core.setOutput('pr-url', prUrl ?? '')

      if (!prUrl) {
        core.setFailed('Failed to create or update pull request')
        return
      }
    } else {
      core.info('📋 No changes to SOUP.md detected — skipping PR creation')
      core.setOutput('pr-url', '')
    }
  }

  core.info(`🏁 SOUP generation finished`)
}

generateSoupRegister()
