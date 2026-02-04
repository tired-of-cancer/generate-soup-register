/* eslint-disable import/no-extraneous-dependencies */
import fs from 'node:fs'
import path = require('path')
import { join } from 'node:path'
import readline from 'node:readline'

import * as core from '@actions/core'
import { Octokit } from '@octokit/core'
import fetch from 'node-fetch'
import parseGithubUrl from 'parse-github-url'
import { coerce, compare, major, minor, prerelease, satisfies } from 'semver'

const DEFAULT_VERIFICATION_LOW = 'SOUP analysed and accepted by developer'
const DEFAULT_VERIFICATION_RISK = '⚠️ Risk to be analysed'
const DEFAULT_SOUP_FILENAME = 'SOUP.md'

// Store for existing verification values parsed from SOUP.md
// Includes version, risk level, and risk details to detect when re-assessment is needed
type TExistingVerification = {
  version: string
  riskLevel: string
  riskDetails: string
  verification: string
}
let existingVerifications: Map<string, TExistingVerification> = new Map()

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
  soupVersion: string
  soupRiskLevel: string
  soupRiskDetails: string
  soupVerification: string
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
  repoUrl: string | undefined
): Promise<TRiskAnalysis> => {
  const reasons: string[] = []

  const deprecation = checkDeprecation(npmData, version)
  const abandonment = checkAbandonment(npmData)
  const versionLag = checkVersionLag(npmData, version)

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

  // Check if any verification was impossible
  const hasUnverifiable =
    repoStatus.unverifiable || advisoriesResult.unverifiable

  let level: TRiskAnalysis['level'] = 'Low'

  if (deprecation || vulnResult || repoStatus.archived) {
    level = 'Critical'
  } else if (
    abandonment ||
    advisoriesResult.advisories ||
    versionLag.severity === 'high'
  ) {
    level = 'High'
  } else if (
    repoStatus.lowMaintenance ||
    hasUnverifiable ||
    versionLag.severity === 'medium'
  ) {
    // Unverifiable packages get Medium risk - need developer review
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
 */
const getSoupDataForPackage = async (
  soupName: string,
  soupVersion: string
): Promise<TSoupData> => {
  const soupDataResponse = await fetch(`https://registry.npmjs.org/${soupName}`)
  const soupData = (await soupDataResponse.json()) as TNpmData

  let soupLanguages = 'unknown'
  let soupSite = 'private repo'
  let repoUrl: string | undefined

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

  const riskAnalysis = await analyzeRisk(
    soupData,
    soupName,
    soupVersion,
    repoUrl
  )

  return {
    soupName,
    soupLanguages,
    soupSite,
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
    '| Package Name | Programming Languages | Website | Version | Risk Level | Risk Details | Verification |\n|---|---|---|---|---|---|---|\n'
  const tableContents: string[] = []
  soupData.forEach((data) => {
    tableContents.push(
      `| ${data.soupName} | ${data.soupLanguages} | ${data.soupSite} | ${data.soupVersion} | ${data.soupRiskLevel} | ${data.soupRiskDetails} | ${data.soupVerification} |`
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
 */
const getSoupDataForPackageCollection = async (packageJSON: TPackageJson) => {
  const soupDataRequests = <Promise<TSoupData>[]>[]

  if (packageJSON.dependencies) {
    Object.entries(packageJSON.dependencies).forEach(
      ([soupName, soupVersion]) =>
        soupDataRequests.push(getSoupDataForPackage(soupName, soupVersion))
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

        // Table has 7 columns: Name, Languages, Website, Version, Risk Level, Risk Details, Verification
        if (cells.length >= 7) {
          const packageName = cells[0]
          const version = cells[3]
          const riskLevel = cells[4]
          const riskDetails = cells[5]
          const verification = cells[6]

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
 * Method to generate a header and intro for the SOUP register
 * @param packageJSONs TPackageJson[]: the contents of one or more package JSON to generate a unique list of names
 */
const generateSoupHeader = (packageJSONs: TPackageJson[]) => {
  const header = `# SOUP Register`

  const dependenciesCount = getUniqueDependencies(packageJSONs).length

  const intro = `This document contains a list of all SOUP (Software of Unknown Provenance) dependencies used in this repository. SOUP is third-party software that is included in the project and is not developed by the project team.

Risk levels are automatically calculated based on:
- **Critical**: Package is deprecated, has known vulnerabilities, or repository is archived
- **High**: Package is abandoned (>2 years without updates), has open security advisories, or is 2+ major versions behind latest
- **Medium**: Low maintenance activity (>1 year without commits), 1 major version behind, or >1 minor versions behind
- **Low**: Passed all automated checks

The repository uses a total of ${dependenciesCount} unique SOUP dependencies.`

  return `${header}\n\n${intro}\n\n`
}

/**
 * Main generator method: calls the other methods and combines their output in MD format and stores it in SOUP.md
 */
const generateSoupRegister = async () => {
  core.info(`📋 Starting SOUP generation`)

  const basePath = core.getInput('path')
  const rootPath = join(process.cwd(), basePath)
  const soupPath = join(rootPath, DEFAULT_SOUP_FILENAME)

  // Parse existing SOUP.md to preserve custom verifications
  parseExistingVerifications(soupPath)

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

  const repositorySoupRequests = <Promise<string>[]>[]

  packageJSONs.forEach((packageJson) =>
    repositorySoupRequests.push(getSoupDataForPackageCollection(packageJson))
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

  const soupHeader = generateSoupHeader(packageJSONs)

  const soupRegister = soupHeader + soupData.join('\n\n')

  core.info(`✅ SOUP data retrieved`)

  // Write SOUP file
  await fs.writeFile(
    soupPath,
    soupRegister,
    { encoding: 'utf8', flag: 'w' },
    (error) => {
      if (error) {
        core.error(error)
        core.setFailed(error)
      } else {
        core.info(`✅ SOUP register written to ${DEFAULT_SOUP_FILENAME}`)
      }
    }
  )

  core.info(`🏁 SOUP generation finished`)
}

generateSoupRegister()
