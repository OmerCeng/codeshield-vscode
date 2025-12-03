import * as vscode from 'vscode';
import { SecurityScanner } from './scanner/securityScanner';
import { DiagnosticProvider } from './providers/diagnosticProvider';
import { CodeActionProvider } from './providers/codeActionProvider';
import { SecurityDecorationProvider } from './providers/decorationProvider';
import { SecurityCodeLensProvider } from './providers/codeLensProvider';
import { VulnerabilityExplainer } from './utils/vulnerabilityExplainer';
import { IgnoreManager } from './utils/ignoreManager';
import { NotificationService } from './utils/notificationService';

export function activate(context: vscode.ExtensionContext) {
    // Extension activated silently

    // Initialize IgnoreManager
    IgnoreManager.initialize(context);

    const securityScanner = new SecurityScanner();
    const diagnosticProvider = new DiagnosticProvider(securityScanner);
    const codeActionProvider = new CodeActionProvider();
    const decorationProvider = new SecurityDecorationProvider();
    const codeLensProvider = new SecurityCodeLensProvider();

    // Register commands
    const scanCurrentFileCommand = vscode.commands.registerCommand('codeshield.scanCurrentFile', async () => {
        vscode.window.showInformationMessage('CodeShield scan command triggered!');
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }

        const document = editor.document;
        const vulnerabilities = securityScanner.scanDocument(document);
        
        if (vulnerabilities.length === 0) {
            vscode.window.showInformationMessage('✅ No security vulnerabilities found in current file');
            decorationProvider.clearDecorations(editor);
        } else {
            vscode.window.showWarningMessage(`⚠️ Found ${vulnerabilities.length} security issue(s) in current file`);
            // Update both diagnostics and decorations
            diagnosticProvider.updateDiagnostics(document, vulnerabilities);
            decorationProvider.updateDecorations(editor, vulnerabilities);
            codeLensProvider.refresh();
            
            // Send notifications for critical vulnerabilities
            await NotificationService.notifyMultipleVulnerabilities(vulnerabilities, document);
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('codeshield.scanWorkspace', async () => {
        vscode.window.showInformationMessage('🔍 Scanning workspace for security vulnerabilities...');
        
        const files = await vscode.workspace.findFiles('**/*.{js,ts,py,java,cs,cpp,c,h,php,sql,dart}', '**/node_modules/**');
        let totalVulnerabilities = 0;

        for (const file of files) {
            const document = await vscode.workspace.openTextDocument(file);
            const vulnerabilities = securityScanner.scanDocument(document);
            
            if (vulnerabilities.length > 0) {
                totalVulnerabilities += vulnerabilities.length;
                diagnosticProvider.updateDiagnostics(document, vulnerabilities);
            }
        }

        if (totalVulnerabilities === 0) {
            vscode.window.showInformationMessage('✅ No security vulnerabilities found in workspace');
        } else {
            vscode.window.showWarningMessage(`⚠️ Found ${totalVulnerabilities} security issue(s) in workspace`);
        }
    });

    const explainVulnerabilityCommand = vscode.commands.registerCommand('codeshield.explainVulnerability', 
        async (vulnerability: any) => {
            // If we have a document URI, navigate to the vulnerability location
            const editor = vscode.window.activeTextEditor;
            if (editor && vulnerability.line) {
                const position = new vscode.Position(vulnerability.line - 1, vulnerability.column || 0);
                const range = new vscode.Range(position, position);
                
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
            }
            
            VulnerabilityExplainer.explainVulnerability(vulnerability);
        }
    );

    const ignoreVulnerabilityCommand = vscode.commands.registerCommand('codeshield.ignoreVulnerability',
        async (document: vscode.TextDocument, vulnerability: any) => {
            await IgnoreManager.addToIgnoreList(document, vulnerability.line, vulnerability.type);
            
            // Refresh diagnostics and decorations to hide the ignored vulnerability
            const editor = vscode.window.activeTextEditor;
            if (editor && editor.document === document) {
                const updatedVulnerabilities = securityScanner.scanDocument(document);
                diagnosticProvider.updateDiagnostics(document, updatedVulnerabilities);
                decorationProvider.updateDecorations(editor, updatedVulnerabilities);
                codeLensProvider.refresh();
            }
            
            vscode.window.showInformationMessage(
                `�️ Ignored ${vulnerability.type.replace('-', ' ')} warning at line ${vulnerability.line}`
            );
        }
    );

    const applyQuickFixCommand = vscode.commands.registerCommand('codeshield.applyQuickFix',
        async (documentUri: vscode.Uri, vulnerability: any) => {
            const document = await vscode.workspace.openTextDocument(documentUri);
            const editor = await vscode.window.showTextDocument(document);
            
            if (vulnerability.fixAction) {
                const range = new vscode.Range(
                    vulnerability.line - 1,
                    vulnerability.column,
                    vulnerability.line - 1,
                    vulnerability.column + vulnerability.code.length
                );
                
                await editor.edit(editBuilder => {
                    editBuilder.replace(range, vulnerability.fixAction.replacement);
                });
                
                vscode.window.showInformationMessage(`🔧 Applied fix: ${vulnerability.fixAction.title}`);
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

        const selectedText = editor.document.getText(selection);
        const startLine = selection.start.line;
        
        // Scan the selected text directly without creating a new document
        const lines = selectedText.split('\n');
        const vulnerabilities = securityScanner.scanDocument(editor.document)
            .filter(v => v.line > startLine && v.line <= startLine + lines.length);
        
        if (vulnerabilities.length === 0) {
            vscode.window.showInformationMessage('✅ No security vulnerabilities found in selected code');
        } else {
            // Show detailed results
            const results = vulnerabilities.map(v => 
                `• Line ${v.line}: ${v.type.replace('-', ' ').toUpperCase()}\n  ${v.message}`
            ).join('\n\n');
            
            vscode.window.showWarningMessage(
                `⚠️ Found ${vulnerabilities.length} security issue(s) in selection:\n\n${results}`,
                'View Details'
            ).then(action => {
                if (action === 'View Details' && vulnerabilities.length > 0) {
                    // Navigate to first vulnerability
                    const firstVuln = vulnerabilities[0];
                    const position = new vscode.Position(firstVuln.line - 1, firstVuln.column || 0);
                    editor.selection = new vscode.Selection(position, position);
                    editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
                }
            });
        }
    });

    // Register providers
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'csharp', 'cpp', 'c', 'php', 'sql', 'go'];
    
    context.subscriptions.push(
        scanCurrentFileCommand,
        scanWorkspaceCommand,
        explainVulnerabilityCommand,
        ignoreVulnerabilityCommand,
        applyQuickFixCommand,
        analyzeSelectionCommand,
        vscode.languages.registerCodeActionsProvider(supportedLanguages, codeActionProvider),
        vscode.languages.registerCodeLensProvider(supportedLanguages, codeLensProvider),
        // Auto-scan on file save
        vscode.workspace.onDidSaveTextDocument(async (document: vscode.TextDocument) => {
            if (supportedLanguages.includes(document.languageId)) {
                const vulnerabilities = securityScanner.scanDocument(document);
                diagnosticProvider.updateDiagnostics(document, vulnerabilities);
                
                // Send notification for critical vulnerabilities
                await NotificationService.notifyMultipleVulnerabilities(vulnerabilities, document);
            }
        }),
        // Auto-update on text change
        vscode.workspace.onDidChangeTextDocument((event) => {
            const document = event.document;
            const editor = vscode.window.activeTextEditor;
            if (editor && supportedLanguages.includes(document.languageId)) {
                // Debounce ile performance için 500ms bekle
                setTimeout(() => {
                    const vulnerabilities = securityScanner.scanDocument(document);
                    diagnosticProvider.updateDiagnostics(document, vulnerabilities);
                    decorationProvider.updateDecorations(editor, vulnerabilities);
                    codeLensProvider.refresh();
                }, 500);
            }
        }),
        // Update decorations when switching editors
        vscode.window.onDidChangeActiveTextEditor((editor) => {
            if (editor && supportedLanguages.includes(editor.document.languageId)) {
                const vulnerabilities = securityScanner.scanDocument(editor.document);
                decorationProvider.updateDecorations(editor, vulnerabilities);
            }
        })
    );
}

export function deactivate() {
    // Extension deactivated
}