import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

// ---------------- TYPES ----------------

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

// ---------------- ACTIVATE ----------------

export function activate(context: vscode.ExtensionContext) {
    console.log("OS3 Extension Activated");

    const diagnostics = vscode.languages.createDiagnosticCollection('os3');
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);

    statusBar.text = "🛡 OS3 Ready";
    statusBar.show();

    // Hover Provider
    const hover = vscode.languages.registerHoverProvider(
        ['javascript', 'typescript', 'python', 'json'],
        {
            async provideHover(document, position) {
                const line = document.lineAt(position.line).text;
                const pkg = extractPackageName(line, document.languageId);

                if (!pkg) return null;

                const report = await getOS3Score(pkg, document.languageId);
                if (!report) return null;

                return createHover(pkg, report);
            }
        }
    );

    // Debounced scan
    let timer: NodeJS.Timeout | undefined;

    const triggerScan = (doc: vscode.TextDocument) => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => scanDocument(doc, diagnostics), 400);
    };

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(triggerScan),
        vscode.workspace.onDidChangeTextDocument(e => triggerScan(e.document)),
        vscode.workspace.onDidSaveTextDocument(doc => {
            const name = path.basename(doc.fileName);
            if (['package.json', 'requirements.txt', 'pom.xml'].includes(name)) {
                runFullScan(doc.fileName);
            }
        })
    );

    vscode.window.visibleTextEditors.forEach(e => triggerScan(e.document));

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('os3.sync', async () => {
            statusBar.text = "🔄 OS3 Syncing...";
            try {
                await execCLI('sync');
                vscode.window.showInformationMessage("OS3 Synced");
                statusBar.text = "🛡 OS3 Synced";
            } catch (e: any) {
                vscode.window.showErrorMessage("Sync failed: " + e.message);
                statusBar.text = "⚠ OS3 Error";
            }
        })
    );

    context.subscriptions.push(hover, diagnostics, statusBar);
}

// ---------------- SCAN ----------------

async function scanDocument(doc: vscode.TextDocument, collection: vscode.DiagnosticCollection) {
    if (!['javascript', 'typescript', 'python', 'json'].includes(doc.languageId)) return;

    const lines = doc.getText().split('\n');
    const results: vscode.Diagnostic[] = [];

    const config = vscode.workspace.getConfiguration('os3');
    const warn = config.get<number>('warnIfScoreBelow', 70);
    const error = config.get<number>('errorIfScoreBelow', 40);

    for (let i = 0; i < lines.length; i++) {
        const pkg = extractPackageName(lines[i], doc.languageId);
        if (!pkg) continue;

        try {
            const report = await getOS3Score(pkg, doc.languageId);
            if (!report) continue;

            if (report.score < warn) {
                const severity =
                    report.score < error
                        ? vscode.DiagnosticSeverity.Error
                        : vscode.DiagnosticSeverity.Warning;

                results.push(
                    new vscode.Diagnostic(
                        new vscode.Range(i, 0, i, lines[i].length),
                        `OS3: ${pkg} risk ${report.score}/100 → ${report.explanations[0] || ''}`,
                        severity
                    )
                );
            }
        } catch (e) {
            console.error("Scan error:", e);
        }
    }

    collection.set(doc.uri, results);
}

// ---------------- PARSING ----------------

function extractPackageName(line: string, lang: string): string | null {
    if (lang === 'python') {
        const m = line.match(/(?:from|import)\s+([a-zA-Z0-9_-]+)/);
        return m?.[1] || null;
    }

    if (lang === 'javascript' || lang === 'typescript') {
        const m =
            line.match(/from\s+['"]([^'"]+)['"]/) ||
            line.match(/require\(['"]([^'"]+)['"]\)/);
        return m?.[1] || null;
    }

    if (lang === 'json') {
        const m = line.match(/"dependencies"\s*:/);
        if (m) return null; // skip root

        const dep = line.match(/"([^"]+)"\s*:\s*"[^"]+"/);
        return dep?.[1] || null;
    }

    return null;
}

function ecosystem(lang: string) {
    return lang === 'python' ? 'pypi' : 'npm';
}

// ---------------- OS3 LOGIC ----------------

async function getOS3Score(pkg: string, lang: string): Promise<OS3Report | null> {
    try {
        const out = await execCLI(`score ${pkg} --ecosystem ${ecosystem(lang)} --json`);
        return JSON.parse(out);
    } catch (e: any) {
        console.error("OS3 Error:", e.message);
        return null;
    }
}

// ---------------- CLI EXEC ----------------

function execCLI(args: string): Promise<string> {
    const config = vscode.workspace.getConfiguration('os3');
    const cli = config.get<string>('cliPath', 'os3');

    const cmd = `${cli} ${args}`;
    console.log("Executing:", cmd);

    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout, stderr) => {
            console.log("STDOUT:", stdout);
            console.log("STDERR:", stderr);

            if (err) {
                reject(err);
                return;
            }

            const jsonStart = stdout.indexOf('{');
            if (jsonStart === -1) {
                reject(new Error("Invalid JSON output"));
                return;
            }

            resolve(stdout.substring(jsonStart));
        });
    });
}

// ---------------- HOVER ----------------

function createHover(pkg: string, report: OS3Report): vscode.Hover {
    const md = new vscode.MarkdownString();

    md.appendMarkdown(`### 🛡 OS3: ${pkg}\n\n`);
    md.appendMarkdown(`**Score:** ${report.score}/100 (${report.risk_level})\n\n`);

    md.appendMarkdown(`**Findings:**\n`);
    report.explanations.slice(0, 3).forEach(e => {
        md.appendMarkdown(`- ${e}\n`);
    });

    if (report.alternatives?.length) {
        md.appendMarkdown(`\n**Alternatives:**\n`);
        report.alternatives.slice(0, 3).forEach(a => {
            md.appendMarkdown(`- ${a.package} (${a.score})\n`);
        });
    }

    md.isTrusted = true;
    return new vscode.Hover(md);
}

// ---------------- FULL SCAN ----------------

function runFullScan(file: string) {
    vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: "OS3 Scanning...",
        },
        async () => {
            try {
                const out = await execCLI(`scan ${file} --json`);
                const data = JSON.parse(out);

                if (data?.summary?.high_risk_found) {
                    vscode.window.showWarningMessage(
                        `OS3: ${data.summary.risk_counts.HIGH} high-risk deps found`
                    );
                }
            } catch (e) {
                vscode.window.showErrorMessage("Scan failed");
            }
        }
    );
}

export function deactivate() {}