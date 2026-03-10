import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

/**
 * OS3 Extension: Real-time supply chain security for PyPI, NPM, and Maven.
 */

interface OS3Alternative {
    package: string;
    score: number;
    delta: string;
    why: string;
}

interface OS3Report {
    score: number;
    risk_level: string;
    explanations: string[];
    alternatives: OS3Alternative[];
    ecosystem: string;
    vulns: string[];
}

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('os3-security');
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = "$(shield) OS³: Ready";
    statusBarItem.show();

    // 1. Hover Provider
    const hoverProvider = vscode.languages.registerHoverProvider(
        [{ language: 'python' }, { language: 'javascript' }, { language: 'typescript' }, { language: 'json' }],
        {
            async provideHover(document, position, token) {
                const line = document.lineAt(position.line).text;
                const pkgName = extractPackageName(line, document.languageId);

                if (pkgName) {
                    const report = await getOS3Score(pkgName, document.languageId);
                    if (report) {
                        return createHoverMessage(pkgName, report);
                    }
                }
                return null;
            }
        }
    );

    // 2. Continuous Scanning (Debounced)
    let timeout: NodeJS.Timeout | undefined = undefined;
    const triggerScan = (document: vscode.TextDocument) => {
        if (timeout) {
            clearTimeout(timeout);
        }
        timeout = setTimeout(() => scanDocument(document, diagnosticCollection), 500);
    };

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => triggerScan(e.document)),
        vscode.workspace.onDidOpenTextDocument(doc => triggerScan(doc)),
        vscode.workspace.onDidSaveTextDocument(doc => {
            if (path.basename(doc.fileName) === 'package.json' || path.basename(doc.fileName) === 'requirements.txt' || path.basename(doc.fileName) === 'pom.xml') {
                runFullScan(doc.fileName);
            }
        })
    );

    // Initial scan for all open editors
    vscode.window.visibleTextEditors.forEach(editor => triggerScan(editor.document));

    // 3. Code Actions (Quick Fixes)
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        [{ language: 'python' }, { language: 'javascript' }, { language: 'typescript' }, { language: 'json' }],
        {
            provideCodeActions(document, range, context, token) {
                const actions: vscode.CodeAction[] = [];
                for (const diagnostic of context.diagnostics) {
                    if (diagnostic.source === 'OS³') {
                        const pkgName = diagnostic.code as string;

                        // Action: Suppress
                        const suppressAction = new vscode.CodeAction(`OS³: Suppress ${pkgName}`, vscode.CodeActionKind.QuickFix);
                        suppressAction.command = {
                            command: 'os3.suppress',
                            title: 'Suppress Package',
                            arguments: [pkgName, getEcosystem(document.languageId)]
                        };
                        actions.push(suppressAction);
                    }
                }
                return actions;
            }
        }
    );

    // 4. Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('os3.sync', async () => {
            statusBarItem.text = "$(sync~spin) OS³: Syncing...";
            try {
                await executeOS3Command('sync');
                vscode.window.showInformationMessage('OS³: Vulnerability cache synced.');
                statusBarItem.text = "$(shield) OS³: Synced";
            } catch (err) {
                vscode.window.showErrorMessage('OS³ Sync failed. Ensure CLI is installed.');
                statusBarItem.text = "$(warning) OS³: Error";
            }
        }),

        vscode.commands.registerCommand('os3.suppress', async (pkg: string, eco: string) => {
            const reason = await vscode.window.showInputBox({ prompt: `Reason for suppressing ${pkg}?`, value: 'Developer reviewed, safe' });
            if (reason) {
                await executeOS3Command(`suppress add ${pkg} --ecosystem ${eco} --reason "${reason}" --all`);
                vscode.window.showInformationMessage(`OS³: ${pkg} suppressed.`);
            }
        })
    );

    context.subscriptions.push(hoverProvider, codeActionProvider, diagnosticCollection, statusBarItem);
}

// --- Logic Helpers ---

async function scanDocument(document: vscode.TextDocument, collection: vscode.DiagnosticCollection) {
    if (!['python', 'javascript', 'typescript', 'json'].includes(document.languageId)) return;

    const diagnostics: vscode.Diagnostic[] = [];
    const text = document.getText();
    const lines = text.split('\n');

    const config = vscode.workspace.getConfiguration('os3');
    const warnThreshold = config.get<number>('warnIfScoreBelow', 70);
    const errorThreshold = config.get<number>('errorIfScoreBelow', 40);

    for (let i = 0; i < lines.length; i++) {
        const pkgName = extractPackageName(lines[i], document.languageId);
        if (pkgName) {
            const report = await getOS3Score(pkgName, document.languageId);
            if (report && report.score < warnThreshold) {
                const range = new vscode.Range(i, 0, i, lines[i].length);
                const severity = report.score < errorThreshold ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;

                const diag = new vscode.Diagnostic(
                    range,
                    `OS³ Security: ${pkgName} is High Risk (${report.score}/100). ${report.explanations[0]}`,
                    severity
                );
                diag.source = 'OS³';
                diag.code = pkgName;
                diagnostics.push(diag);
            }
        }
    }
    collection.set(document.uri, diagnostics);
}

function extractPackageName(line: string, langId: string): string | null {
    if (langId === 'python') {
        const reg = /(?:from|import)\s+([a-zA-Z0-9_-]+)/;
        const match = line.match(reg);
        return match ? match[1] : null;
    } else if (langId === 'javascript' || langId === 'typescript') {
        const regImport = /import\s+.*\s+from\s+['"]([a-zA-Z0-9_-@/]+)['"]/;
        const regRequire = /require\(['"]([a-zA-Z0-9_-@/]+)['"]\)/;
        const match = line.match(regImport) || line.match(regRequire);
        return match ? match[1] : null;
    } else if (langId === 'json') {
        // package.json dependencies
        const reg = /"([^"]+)"\s*:\s*"[^"]+"/;
        const match = line.match(reg);
        return match ? match[1] : null;
    }
    return null;
}

function getEcosystem(langId: string): string {
    if (langId === 'python') return 'pypi';
    return 'npm'; // Default for JS/TS/JSON
}

async function getOS3Score(pkg: string, langId: string): Promise<OS3Report | null> {
    const ecosystem = getEcosystem(langId);
    try {
        const output = await executeOS3Command(`score ${pkg} --ecosystem ${ecosystem} --json`);
        return JSON.parse(output);
    } catch (e) {
        return null;
    }
}

function createHoverMessage(pkg: string, report: OS3Report): vscode.Hover {
    const color = report.score >= 80 ? 'green' : report.score >= 55 ? 'orange' : 'red';
    const badge = `**Score: [${report.score}/100]** (${report.risk_level})`;

    const markdown = new vscode.MarkdownString();
    markdown.appendMarkdown(`### OS³ Security: ${pkg}\n\n`);
    markdown.appendMarkdown(`${badge}\n\n`);

    markdown.appendMarkdown(`**Audit Results:**\n`);
    report.explanations.slice(0, 3).forEach(exp => {
        markdown.appendMarkdown(`- ${exp}\n`);
    });

    if (report.alternatives && report.alternatives.length > 0) {
        markdown.appendMarkdown(`\n**Safer Alternatives:**\n\n`);
        markdown.appendMarkdown(`| Package | Score | Improvement |\n`);
        markdown.appendMarkdown(`| :--- | :--- | :--- |\n`);
        report.alternatives.slice(0, 3).forEach(alt => {
            markdown.appendMarkdown(`| ${alt.package} | ${alt.score} | ${alt.delta} |\n`);
        });
    }

    markdown.isTrusted = true;
    return new vscode.Hover(markdown);
}

function runFullScan(filePath: string) {
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "OS³: Scanning project artifacts...",
        cancellable: false
    }, async (progress) => {
        try {
            const output = await executeOS3Command(`scan ${filePath} --json`);
            const data = JSON.parse(output);
            if (data.summary && data.summary.high_risk_found) {
                vscode.window.showWarningMessage(`OS³: Found ${data.summary.risk_counts.HIGH} high-risk dependencies in ${path.basename(filePath)}!`);
            }
        } catch (e) {
            // Error handling
        }
    });
}

function executeOS3Command(args: string): Promise<string> {
    const config = vscode.workspace.getConfiguration('os3');
    const cliPath = config.get<string>('cliPath', 'os3');

    return new Promise((resolve, reject) => {
        exec(`${cliPath} ${args}`, (error, stdout, stderr) => {
            if (error) {
                // If the error contains legitimate JSON, we might still want to parse it (some errors return partial results)
                if (stdout && stdout.startsWith('{')) {
                    resolve(stdout);
                    return;
                }
                reject(error);
                return;
            }
            resolve(stdout);
        });
    });
}

export function deactivate() { }
