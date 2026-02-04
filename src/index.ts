/* eslint-disable import/no-extraneous-dependencies */
import fs from 'node:fs'
import path = require('path')
import { join } from 'node:path'
import readline from 'node:readline'

import * as core from '@actions/core'
import { Octokit } from '@octokit/core'
import fetch from 'node-fetch'
import parseGithubUrl from 'parse-github-url'

const DEFAULT_VERIFICATION_LOW = 'SOUP analysed and accepted by developer'
const DEFAULT_VERIFICATION_RISK = '⚠️ Risk to be analysed'
const DEFAULT_SOUP_FILENAME = 'SOUP.md'

// Store for existing verification values parsed from SOUP.md
let existingVerifications: Map<string, string> = new Map()

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

type TOsvResponse = {
  vulns?: Array<{ id: string; summary?: string }>
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
 * Query OSV API for known vulnerabilities
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

    if (!response.ok) return undefined

    const data = (await response.json()) as TOsvResponse
    if (data.vulns && data.vulns.length > 0) {
      const vulnLinks = data.vulns
        .slice(0, 3)
        .map((v) => `[${v.id}](https://osv.dev/vulnerability/${v.id})`)
        .join(', ')
      const suffix =
        data.vulns.length > 3 ? ` (+${data.vulns.length - 3} more)` : ''
      return `Vulnerabilities: ${vulnLinks}${suffix}`
    }
    return undefined
  } catch {
    return undefined
  }
}

/**
 * Check GitHub repo status (archived, last push date)
 */
const checkGitHubRepoStatus = async (
  repoUrl: string
): Promise<{
  archived: string | undefined
  lowMaintenance: string | undefined
}> => {
  try {
    const { owner, name } = parseGithubUrl(repoUrl) ?? {}
    if (!owner || !name)
      return { archived: undefined, lowMaintenance: undefined }

    const response = await octokit.request('GET /repos/{owner}/{name}', {
      owner,
      name,
    })

    if (response.status !== 200)
      return { archived: undefined, lowMaintenance: undefined }

    const data = response.data as TGitHubRepoData
    const result: {
      archived: string | undefined
      lowMaintenance: string | undefined
    } = {
      archived: undefined,
      lowMaintenance: undefined,
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
  } catch {
    return { archived: undefined, lowMaintenance: undefined }
  }
}

/**
 * Check for open security advisories on GitHub
 */
const checkSecurityAdvisories = async (
  repoUrl: string
): Promise<string | undefined> => {
  try {
    const { owner, name } = parseGithubUrl(repoUrl) ?? {}
    if (!owner || !name) return undefined

    const response = await octokit.request(
      'GET /repos/{owner}/{name}/security-advisories',
      {
        owner,
        name,
        state: 'published',
      }
    )

    if (response.status !== 200) return undefined

    const advisories = response.data as Array<{ ghsa_id: string }>
    if (advisories && advisories.length > 0) {
      const advisoryLinks = advisories
        .slice(0, 3)
        .map(
          (a) => `[${a.ghsa_id}](https://github.com/advisories/${a.ghsa_id})`
        )
        .join(', ')
      const suffix =
        advisories.length > 3 ? ` (+${advisories.length - 3} more)` : ''
      return `Advisories: ${advisoryLinks}${suffix}`
    }
    return undefined
  } catch {
    return undefined
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

  const [vulnResult, repoStatus, advisoriesResult] = await Promise.all([
    checkVulnerabilities(packageName, version),
    repoUrl
      ? checkGitHubRepoStatus(repoUrl)
      : Promise.resolve({ archived: undefined, lowMaintenance: undefined }),
    repoUrl ? checkSecurityAdvisories(repoUrl) : Promise.resolve(),
  ])

  if (deprecation) reasons.push(deprecation)
  if (abandonment) reasons.push(abandonment)
  if (vulnResult) reasons.push(vulnResult)
  if (repoStatus.archived) reasons.push(repoStatus.archived)
  if (repoStatus.lowMaintenance) reasons.push(repoStatus.lowMaintenance)
  if (advisoriesResult) reasons.push(advisoriesResult)

  let level: TRiskAnalysis['level'] = 'Low'

  if (deprecation || vulnResult || repoStatus.archived) {
    level = 'Critical'
  } else if (abandonment || advisoriesResult) {
    level = 'High'
  } else if (repoStatus.lowMaintenance) {
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
 * @param riskLevel string: calculated risk level
 */
const getVerification = (packageName: string, riskLevel: string): string => {
  // If there's a custom verification, preserve it
  const existing = existingVerifications.get(packageName)
  if (existing) return existing

  // Otherwise, set based on risk level
  return riskLevel === 'Low'
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
    soupVerification: getVerification(soupName, riskAnalysis.level),
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
    lines
      .filter((line) => line.startsWith('|') && !line.includes('---'))
      .forEach((line) => {
        const cells = line
          .split('|')
          .map((cell) => cell.trim())
          .filter((cell) => cell.length > 0)

        // Table has 7 columns: Name, Languages, Website, Version, Risk Level, Risk Details, Verification
        if (cells.length >= 7) {
          const packageName = cells[0]
          const verification = cells[6]

          // Only store non-default verifications (custom entries)
          if (
            verification &&
            verification !== DEFAULT_VERIFICATION_LOW &&
            verification !== DEFAULT_VERIFICATION_RISK
          ) {
            existingVerifications.set(packageName, verification)
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
- **High**: Package is abandoned (>2 years without updates) or has open security advisories
- **Medium**: Low maintenance activity (>1 year without commits)
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
