/* eslint-disable import/no-extraneous-dependencies */
import fs from 'node:fs'
import { join } from 'node:path'
import readline from 'node:readline'

import * as core from '@actions/core'
import { Octokit } from '@octokit/core'
import fetch from 'node-fetch'

const DEFAULT_RISK_LEVEL = 'Low'
const DEFAULT_VERIFICATION = 'SOUP analysed and accepted by developer'
const DEFAULT_SOUP_FILENAME = 'SOUP.md'

type TPackageJson = { dependencies: { [key: string]: string } }
type TNpmData =
  | {
    versions: {
      [key: string]: {
        homepage: string
        repository: {
          url: string
        }
      }
    }
  }
  | undefined

readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

const auth = core.getInput('token')
const octokit = new Octokit({ auth })

const tableHeader =
  '| Package Name | Programming Languages | Website | Version | Risk Level | Verification of Reasoning |\n|---|---|---|---|---|---|\n'
const tableContents: string[] = []

/**
 * Method to request programming language data from GitHub so we can list the language of the SOUP
 * @param soupRepoUrl string: github repo url retrieved from NPM info
 * @returns string: comma separated languages that make up at least 10% of the project
 */
const getSoupLanguageData = async (soupRepoUrl: string) => {
  const soupRepoUriParts = soupRepoUrl.replace('.git', '').split('/').reverse()
  const soupLanguagesGitHubResponse = await octokit.request(
    'GET /repos/{owner}/{repo}/languages',
    { owner: soupRepoUriParts[1], repo: soupRepoUriParts[0] }
  )

  if (soupLanguagesGitHubResponse.status !== 200) return 'unknown'
  const soupLanguagesData = soupLanguagesGitHubResponse.data

  const totalSoupBytes = Object.values(soupLanguagesData).reduce(
    (a: number, b: number) => a + b
  )

  return Object.keys(soupLanguagesData)
    .filter(
      // By filtering out languages that make up less than 10% we prevent listing unrelevant tool languages etc.
      (language) => soupLanguagesData[language] > totalSoupBytes * 0.1
    )
    .join(', ')
}

/**
 * Method to request SOUP package information from NPM
 * @param soupName string: name of the SOUP as listed in our package file
 * @param soupVersion string: version of the SOUP as listed in our lockfile
 */
const getSoupDataForPackage = async (soupName: string, soupVersion: string) => {
  const soupDataResponse = await fetch(`https://registry.npmjs.org/${soupName}`)
  const soupData = (await soupDataResponse.json()) as TNpmData

  let soupLanguages = 'unknown'
  let soupSite = 'private repo'

  if (soupData?.versions) {
    const versionSpecificSoupData =
      soupData?.versions[soupVersion.replace(/[^\d.-]/g, '')]

    if (versionSpecificSoupData?.repository?.url?.includes('github')) {
      soupLanguages = await getSoupLanguageData(
        versionSpecificSoupData.repository.url
      )
    }

    soupSite =
      versionSpecificSoupData?.homepage ||
      versionSpecificSoupData.repository.url
  }

  tableContents.push(
    `| ${soupName} | ${soupLanguages} | ${soupSite} | ${soupVersion} | ${DEFAULT_RISK_LEVEL} | ${DEFAULT_VERIFICATION} |`
  )
}

/**
 * Main generator method: calls the other methods and combines their output in MD format and stores it in SOUP.md
 */
const generateSoupRegister = async () => {
  core.info(`📋 Starting SOUP generation`)

  const path = core.getInput('path')
  const soupPath = join(process.cwd(), path, DEFAULT_SOUP_FILENAME)

  // Read SOUP dependencies from package json
  const packageString = fs.readFileSync(join(path, 'package.json')).toString()
  const packageJSON = JSON.parse(packageString) as TPackageJson

  // Enrich SOUP data
  const soupDataRequests = <Promise<void>[]>[]
  Object.entries(packageJSON.dependencies).forEach(([soupName, soupVersion]) =>
    soupDataRequests.push(getSoupDataForPackage(soupName, soupVersion))
  )
  await Promise.all(soupDataRequests)

  core.info(`✅ SOUP data retrieved`)

  // Write SOUP file
  await fs.writeFile(
    soupPath,
    tableHeader + tableContents.sort().join('\n'),
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
