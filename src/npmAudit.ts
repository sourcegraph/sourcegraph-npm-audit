import { combineLatest, EMPTY, from } from 'rxjs'
import { distinctUntilChanged, filter, map, switchMap } from 'rxjs/operators'
import * as sourcegraph from 'sourcegraph'

/**
 * TODO:
 * - Support package-lock.json and yarn.lock to audit transitive deps
 * - Error handling
 * - Unit tests
 */

const auditDecorationType = sourcegraph.app.createDecorationType()

interface Configuration {
    'npmModuleAudit.corsAnywhereUrl'?: string
}

const getConfig = (): Configuration => sourcegraph.configuration.get<Configuration>().value

export function activate(context: sourcegraph.ExtensionContext): void {
    const panelView = sourcegraph.app.createPanelView('npmAudit.panel')
    panelView.title = 'npm audit'
    panelView.content = 'Open a TypeScript or Javascript file that imports node modules to see audit results'

    context.subscriptions.add(
        combineLatest([
            from(sourcegraph.app.activeWindowChanges).pipe(
                switchMap(activeWindow => activeWindow?.activeViewComponentChanges || EMPTY),
                filter((viewer): viewer is sourcegraph.CodeEditor => !!viewer && viewer.type === 'CodeEditor'),
                filter(
                    editor => editor.document.languageId === 'typescript' || editor.document.languageId === 'javascript'
                ),
                distinctUntilChanged((a, b) => a.document === b.document)
            ),
            from(sourcegraph.configuration).pipe(map(() => getConfig())),
        ])
            .pipe(
                switchMap(async ([editor, config]) => {
                    const corsAnywhereUrl =
                        (config['npmModuleAudit.corsAnywhereUrl']?.replace(/\/$/, '') ||
                            'https://cors-anywhere.herokuapp.com') + '/'

                    const uri = new URL(editor.document.uri)
                    const repoName = decodeURIComponent(uri.hostname + uri.pathname)
                    const commitID = decodeURIComponent(uri.search.slice(1))
                    const filePath = decodeURIComponent(uri.hash.slice(1))

                    const text = editor.document.text ?? ''
                    let match: RegExpExecArray | null = null
                    const moduleNames: string[] = []
                    const moduleIndex: Record<string, number | undefined> = {}

                    // make default matchIndex 1
                    const patterns: { pattern: RegExp; matchIndex: number }[] = [
                        // standard ES2015 import
                        { pattern: /import\s.+\sfrom\s["']([^.~][\w.-]*)["']*/g, matchIndex: 1 },
                        // dynamic import syntax
                        { pattern: /import\(["']([^.~][\w.-]*)["']\)/g, matchIndex: 1 },
                        // TODO: require (minimize false positives?)
                        { pattern: /require\(["']([^.~][\w.-]*)["']\)/g, matchIndex: 1 },
                    ]

                    for (const { pattern, matchIndex } of patterns) {
                        while ((match = pattern.exec(text))) {
                            const name = match[matchIndex]
                            moduleNames.push(name)
                            moduleIndex[name] = match.index
                        }
                    }

                    const auditResponse = await getVulnerabilities(
                        repoName,
                        commitID,
                        filePath,
                        moduleNames,
                        corsAnywhereUrl
                    )

                    return { editor, moduleNames, moduleIndex, auditResponse }
                })
            )
            .subscribe(({ editor, moduleNames, moduleIndex, auditResponse }) => {
                // Panel content will include info for all vulns from deps
                // Decorations are added for vulnerable modules in this file

                // Panel content
                const markdownString = auditResponseToMarkdown(auditResponse, moduleNames)
                panelView.content = markdownString

                const moduleLines = auditResponse.actions
                    .filter(action => moduleIndex[action.module] !== undefined)
                    .map(action => ({
                        name: action.module,
                        line: editor.document.positionAt(moduleIndex[action.module] ?? 0).line,
                    }))

                editor.setDecorations(
                    auditDecorationType,
                    moduleLines.map(({ name, line }) => ({
                        range: new sourcegraph.Range(
                            new sourcegraph.Position(line, 0),
                            new sourcegraph.Position(line, 0)
                        ),
                        after: {
                            contentText: `Module "${name}" is insecure!`,
                            backgroundColor: 'pink',
                            color: 'black',
                            linkURL: '#tab=npmAudit.panel',
                        },
                        // backgroundColor: '#f0a49e',
                    }))
                )
            })
    )
}

export function getClosestPackageJSON(filePath: string, paths: string[]): number {
    interface Tree {
        /** filename -> index of full path */
        blobs: Record<string, number | undefined>
        trees: Record<string, Tree | undefined>
    }

    const fileTree: { root: Tree } = { root: { blobs: {}, trees: {} } }

    for (const [pathIndex, path] of paths.entries()) {
        const splitPath = path.split('/')
        // No leading slashes AFAIK
        let cwd = fileTree.root
        for (const [componentIndex, component] of splitPath.entries()) {
            // last component, so this is a file
            if (componentIndex === splitPath.length - 1) {
                cwd.blobs[component] = pathIndex
                break
            }
            // If the tree doesn't already exist, create it
            const nextTree = cwd.trees[component] ?? { blobs: {}, trees: {} }
            // Reassign in case it didn't exist before
            cwd.trees[component] = nextTree
            cwd = nextTree
        }
    }

    const depfileByPriority = ['package.json']
    // const depfileByPriority = ['package-lock.json', 'yarn.lock', 'package.json']
    // TODO: Prioritize package-lock at same level over package at same level,
    // but package at lower level > package-lock at higher level. Uncomment full list once all types are supported
    let deepestAncestorPackage = 0
    let cwd: Tree | undefined = fileTree.root
    for (const component of filePath.split('/')) {
        if (!cwd) {
            break
        }
        for (const depfile of depfileByPriority) {
            const maybePath = cwd.blobs[depfile]
            if (maybePath !== undefined) {
                deepestAncestorPackage = maybePath
            }
        }
        cwd = cwd.trees[component]
    }

    return deepestAncestorPackage
}

export interface NPMAuditResponse {
    actions: {
        isMajor: boolean
        action: string
        module: string
        resolves: { id: number; path: string; dev: boolean; optional: boolean; bundled: boolean }[]
        target: string
    }[]
    advisories: Record<number, Advisory>
    metadata: {
        dependencies: number
        devDependencies: number
        optionalDependencies: number
        totalDependencies: number
        vulnerabilities: {
            critical: number
            high: number
            info: number
            low: number
            moderate: number
        }
    }
    muted: []
}

export interface Advisory {
    access: string
    created: string
    cwe: string
    findings: { paths: string[]; version: string }[]
    found_by: { link: string; name: string }
    id: string
    metadata: { module_type: string; exploitability: string; affected_components: string }
    module_name: string
    overview: string
    patched_versions: string
    recommendation: string
    references: string
    reported_by: { link: string; name: string }
    severity: string
    title: string
    updated: string
    url: string
    vulnerable_versions: string
}

// file path -> vuln report of closest package.json
const auditResponseCache: Record<string, NPMAuditResponse | undefined> = {}

async function getVulnerabilities(
    repo: string,
    rev: string,
    filePath: string,
    packageNames: string[],
    proxyURL: string
): Promise<NPMAuditResponse> {
    // Check cache (todo: make sure gets and sets use parent directory path, not file path)
    const cachedAuditResponse = auditResponseCache[filePath]

    // If cached, return cached data
    if (cachedAuditResponse) {
        return cachedAuditResponse
    }

    // Request package.json
    const packageJSONString = await getPackageJSONs(repo, rev, filePath, packageNames)

    // Convert package.json to audit body (type required by npm audit endpoint)
    const auditBody = packageToAuditBody(packageJSONString)

    // Store in cache, then return audit response
    const auditResponse = await auditPackageJSON(auditBody, proxyURL)
    auditResponseCache[filePath] = auditResponse
    return auditResponse
}

export function packageToAuditBody(packageJSONString: string): string {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const packageJSON: {
        devDependencies: Record<string, string>
        dependencies: Record<string, string>
    } = JSON.parse(packageJSONString)
    // TODO: Validate w/ zod or io-ts?

    const dependencyNames = Object.keys(packageJSON.dependencies)

    const requires: Record<string, string> = {}
    const dependencies: Record<string, { version: string }> = {}

    for (const name of dependencyNames) {
        const version = packageJSON.dependencies[name].replace(/[^\d.]/g, '')
        if (!version) {
            continue
        }

        requires[name] = version
        dependencies[name] = { version }
    }

    const auditBody: {
        requires: Record<string, string>
        dependencies: Record<string, { version: string; dev?: boolean }>
    } = {
        requires,
        dependencies,
    }

    return JSON.stringify(auditBody)
}

/**
 * To be rendered in panel view
 *
 * TODO: Use <details />? Make it look better
 */
export function auditResponseToMarkdown({ actions, advisories }: NPMAuditResponse, modulesImported: string[]): string {
    if (actions.length === 0) {
        return 'This file has no found vulnerabilities. To get more accurate results, run `npm audit` locally, or use the [Snyk extension](/extensions/sourcegraph/snyk)'
    }

    const advisoriesByModule: { imported: Record<string, Advisory[]>; notImported: Record<string, Advisory[]> } = {
        imported: {},
        notImported: {},
    }

    for (const { module, resolves } of actions) {
        // No need to render sections for modules with no vulnerabilities.
        // Typically, this endpoint will only return modules with issues
        const imported = modulesImported.includes(module)
        if (resolves?.length > 0) {
            advisoriesByModule[imported ? 'imported' : 'notImported'][module] = []
            for (const { id } of resolves) {
                advisoriesByModule[imported ? 'imported' : 'notImported'][module].push(advisories[id])
            }
        }
    }

    let markdownString = '## Issues\n'

    for (const module of Object.keys(advisoriesByModule.imported)) {
        markdownString += `\n#### Issues found for module: ${module}\n`
        for (const advisory of advisoriesByModule.imported[module]) {
            markdownString += `\n\n- Overview: ${advisory.overview}\n- Severity: ${advisory.severity}\n- Found by: ${advisory.found_by.name}\n`
        }
    }

    const notImportedModules = Object.keys(advisoriesByModule.notImported)
    if (notImportedModules.length > 0) {
        markdownString += '\n### Issues found in modules not imported in this file\n'
        for (const module of notImportedModules) {
            for (const advisory of advisoriesByModule.notImported[module]) {
                markdownString += `- Overview: ${advisory.overview}\n- Severity: ${advisory.severity}\n- Found by: ${advisory.found_by.name}\n`
            }
        }
    }

    return markdownString
}

// Fetch functions

async function getPackageJSONs(repo: string, rev: string, filePath: string, packageNames: string[]): Promise<string> {
    // Make a regex of all package names
    let packagesRegex = '('
    for (const [index, packageName] of packageNames.entries()) {
        packagesRegex += `"${packageName}"`
        if (index !== packageNames.length - 1) {
            packagesRegex += '|'
        }
    }
    packagesRegex += ')'

    const query = `repo:${repo} rev:${rev} file:package.json ${packagesRegex}`

    const { data } = await sourcegraph.commands.executeCommand<GQLResponse>(
        'queryGraphQL',
        `query PackagePaths($query: String!) {
            search(query: $query) {
                results {
                    results {
                        ... on FileMatch {
                            file {
                                path
                                content
                            }
                        }
                    }
                }
            }
        }`,
        { query }
    )

    return data.search.results.results[
        getClosestPackageJSON(
            filePath,
            data.search.results.results.map(({ file }) => file.path)
        )
    ].file.content
}

interface GQLResponse {
    data: {
        search: {
            results: {
                results: {
                    file: { path: string; content: string }
                }[]
            }
        }
    }
    errors: unknown
}

async function auditPackageJSON(body: string, proxyURL: string): Promise<NPMAuditResponse> {
    const response = await fetch(
        // 'https://cors-anywhere.herokuapp.com/' by default
        proxyURL + 'https://registry.npmjs.org/-/npm/v1/security/audits',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body,
        }
    )
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return response.json()
    // TODO: validation w/ zod or io-ts?
}

// Sourcegraph extension documentation: https://docs.sourcegraph.com/extensions/authoring
