import * as vscode from 'vscode';
import { SecurityScanner } from './scanner/securityScanner';
import { DiagnosticProvider } from './providers/diagnosticProvider';
import { CodeActionProvider } from './providers/codeActionProvider';
import { SecurityDecorationProvider } from './providers/decorationProvider';
import { SecurityCodeLensProvider } from './providers/codeLensProvider';
import { VulnerabilityExplainer } from './utils/vulnerabilityExplainer';
import { IgnoreManager } from './utils/ignoreManager';
import { NotificationService } from './utils/notificationService';
import { StatusBarProvider } from './providers/statusBarProvider';
import { HoverProvider } from './providers/hoverProvider';
import { SecureCompletionProvider } from './providers/completionProvider';

export function activate(context: vscode.ExtensionContext) {
    IgnoreManager.initialize(context);

    const securityScanner = new SecurityScanner();
    const diagnosticProvider = new DiagnosticProvider(securityScanner);
    const codeActionProvider = new CodeActionProvider(securityScanner);
    const decorationProvider = new SecurityDecorationProvider();
    const codeLensProvider = new SecurityCodeLensProvider(securityScanner);
    const statusBarProvider = new StatusBarProvider();
    const hoverProvider = new HoverProvider(securityScanner);
    const completionProvider = new SecureCompletionProvider();

    /**
     * Central helper — always call this after a scan so active issues,
     * ignored hints, decorations, and the status bar stay in sync.
     */
    function applyResults(
        document: vscode.TextDocument,
        editor?: vscode.TextEditor
    ) {
        const all = securityScanner.scanDocumentAll(document);
        const active = all.filter(v => !IgnoreManager.isIgnored(document, v.line, v.type));
        const ignored = all.filter(v => IgnoreManager.isIgnored(document, v.line, v.type));

        diagnosticProvider.updateDiagnostics(document, active);
        diagnosticProvider.updateIgnoredDiagnostics(document, ignored);
        statusBarProvider.update(active);

        if (editor) {
            if (active.length === 0) {
                decorationProvider.clearDecorations(editor);
            } else {
                decorationProvider.updateDecorations(editor, active);
            }
            codeLensProvider.refresh();
        }

        return { active, ignored };
    }

    // ─── Commands ────────────────────────────────────────────────────────────

    const scanCurrentFileCommand = vscode.commands.registerCommand('codeshield.scanCurrentFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }

        statusBarProvider.setScanning();
        const { active } = applyResults(editor.document, editor);

        if (active.length === 0) {
            vscode.window.showInformationMessage('No security vulnerabilities found in current file');
        } else {
            vscode.window.showWarningMessage(`Found ${active.length} security issue(s) in current file`);
            await NotificationService.notifyMultipleVulnerabilities(active, editor.document);
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('codeshield.scanWorkspace', async () => {
        statusBarProvider.setScanning();
        vscode.window.showInformationMessage('Scanning workspace for security vulnerabilities...');

        const files = await vscode.workspace.findFiles(
            '**/*.{js,ts,py,java,cs,cpp,c,h,php,sql,dart,go,rb,kt,swift}',
            '{**/node_modules/**,**/.git/**,**/dist/**,**/out/**,**/build/**}'
        );

        let totalActive = 0;

        for (const file of files) {
            const document = await vscode.workspace.openTextDocument(file);
            const { active } = applyResults(document);
            totalActive += active.length;
        }

        if (totalActive === 0) {
            vscode.window.showInformationMessage('No security vulnerabilities found in workspace');
        } else {
            vscode.window.showWarningMessage(`Found ${totalActive} security issue(s) across ${files.length} file(s)`);
        }
    });

    const explainVulnerabilityCommand = vscode.commands.registerCommand(
        'codeshield.explainVulnerability',
        async (vulnerability: any) => {
            const editor = vscode.window.activeTextEditor;
            if (editor && vulnerability.line) {
                const position = new vscode.Position(vulnerability.line - 1, vulnerability.column || 0);
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
            }
            VulnerabilityExplainer.explainVulnerability(vulnerability);
        }
    );

    const ignoreVulnerabilityCommand = vscode.commands.registerCommand(
        'codeshield.ignoreVulnerability',
        async (document: vscode.TextDocument, vulnerability: any) => {
            await IgnoreManager.addToIgnoreList(document, vulnerability.line, vulnerability.type);

            const editor = vscode.window.activeTextEditor;
            applyResults(document, editor?.document === document ? editor : undefined);

            const label = vulnerability.type.replace(/-/g, ' ');
            vscode.window.showInformationMessage(
                `Ignored ${label} at line ${vulnerability.line}. It will appear as a hint in the Problems panel.`
            );
        }
    );

    const ignoreAllInFileCommand = vscode.commands.registerCommand(
        'codeshield.ignoreAllInFile',
        async (document?: vscode.TextDocument) => {
            const doc = document ?? vscode.window.activeTextEditor?.document;
            if (!doc) {
                vscode.window.showWarningMessage('No active file to ignore issues in');
                return;
            }

            const all = securityScanner.scanDocumentAll(doc);
            const active = all.filter(v => !IgnoreManager.isIgnored(doc, v.line, v.type));

            if (active.length === 0) {
                vscode.window.showInformationMessage('No active security issues to ignore in this file');
                return;
            }

            await IgnoreManager.addAllToIgnoreList(doc, active);

            const editor = vscode.window.activeTextEditor;
            applyResults(doc, editor?.document === doc ? editor : undefined);

            vscode.window.showInformationMessage(
                `Ignored ${active.length} issue(s) in this file. They remain visible as hints in the Problems panel.`
            );
        }
    );

    const applyQuickFixCommand = vscode.commands.registerCommand(
        'codeshield.applyQuickFix',
        async (documentUri: vscode.Uri, vulnerability: any) => {
            if (vulnerability.fixAction) {
                await vscode.env.clipboard.writeText(vulnerability.fixAction.replacement);
                vscode.window.showInformationMessage(
                    `Safe example copied to clipboard — paste it to replace the vulnerable code.`
                );
            }
        }
    );

    const copySafeExampleCommand = vscode.commands.registerCommand(
        'codeshield.copySafeExample',
        async (vulnerability: any) => {
            if (vulnerability?.fixAction?.replacement) {
                await vscode.env.clipboard.writeText(vulnerability.fixAction.replacement);
                vscode.window.showInformationMessage(
                    `Safe example copied to clipboard — paste it to replace the vulnerable code.`
                );
            }
        }
    );

    const analyzeSelectionCommand = vscode.commands.registerCommand('codeshield.analyzeSelection', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }

        const selection = editor.selection;
        if (selection.isEmpty) {
            vscode.window.showInformationMessage('Please select code to analyze');
            return;
        }

        const startLine = selection.start.line;
        const lines = editor.document.getText(selection).split('\n');
        const vulnerabilities = securityScanner.scanDocument(editor.document)
            .filter(v => v.line > startLine && v.line <= startLine + lines.length);

        if (vulnerabilities.length === 0) {
            vscode.window.showInformationMessage('No security vulnerabilities found in selected code');
        } else {
            vscode.window.showWarningMessage(
                `Found ${vulnerabilities.length} issue(s) in selection`,
                'Go to First'
            ).then(action => {
                if (action === 'Go to First') {
                    const first = vulnerabilities[0];
                    const position = new vscode.Position(first.line - 1, first.column || 0);
                    editor.selection = new vscode.Selection(position, position);
                    editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
                }
            });
        }
    });

    // ─── Providers & listeners ────────────────────────────────────────────────

    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 'php', 'sql', 'go', 'ruby', 'kotlin'];

    context.subscriptions.push(
        scanCurrentFileCommand,
        scanWorkspaceCommand,
        explainVulnerabilityCommand,
        ignoreVulnerabilityCommand,
        ignoreAllInFileCommand,
        applyQuickFixCommand,
        copySafeExampleCommand,
        analyzeSelectionCommand,
        statusBarProvider,
        codeLensProvider,
        vscode.languages.registerCodeActionsProvider(supportedLanguages, codeActionProvider),
        vscode.languages.registerCodeLensProvider(supportedLanguages, codeLensProvider),
        vscode.languages.registerHoverProvider(supportedLanguages, hoverProvider),
        vscode.languages.registerCompletionItemProvider(
            supportedLanguages,
            completionProvider,
            '(', '.', '"', "'"
        ),
        vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
            if (!supportedLanguages.includes(document.languageId)) { return; }
            const { active } = applyResults(document);
            await NotificationService.notifyMultipleVulnerabilities(active, document);
        }),
        vscode.workspace.onDidChangeTextDocument((event) => {
            const document = event.document;
            if (!supportedLanguages.includes(document.languageId)) { return; }
            setTimeout(() => {
                // Re-resolve the editor at callback time — user may have switched tabs
                const currentEditor = vscode.window.visibleTextEditors.find(e => e.document === document);
                applyResults(document, currentEditor);
            }, 500);
        }),
        vscode.window.onDidChangeActiveTextEditor((editor) => {
            if (editor && supportedLanguages.includes(editor.document.languageId)) {
                applyResults(editor.document, editor);
            } else {
                statusBarProvider.setIdle();
            }
        })
    );
}

export function deactivate() {}
