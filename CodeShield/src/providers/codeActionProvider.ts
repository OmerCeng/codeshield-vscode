import * as vscode from 'vscode';
import { SecurityScanner } from '../scanner/securityScanner';
import { SecurityVulnerability } from '../types/vulnerability';
import { IgnoreManager } from '../utils/ignoreManager';

export class CodeActionProvider implements vscode.CodeActionProvider {
    constructor(private securityScanner: SecurityScanner) {}

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {
        
        const actions: vscode.CodeAction[] = [];

        // Get vulnerabilities for current document
        const vulnerabilities = this.securityScanner.scanDocument(document);
        
        // Find vulnerabilities that intersect with current range
        const relevantVulnerabilities = vulnerabilities.filter(vuln => {
            const vulnRange = new vscode.Range(
                vuln.line - 1, vuln.column,
                vuln.line - 1, vuln.column + vuln.code.length
            );
            return range.intersection(vulnRange) !== undefined;
        });

        // Process each relevant vulnerability
        for (const vulnerability of relevantVulnerabilities) {
            // Create quick fix actions based on vulnerability type
            actions.push(...this.createQuickFixes(document, vulnerability));
            
            // Add explanation action
            const explainAction = new vscode.CodeAction(
                `🛡️ Explain ${vulnerability.type.replace('-', ' ').toUpperCase()}`,
                vscode.CodeActionKind.Empty
            );
            
            explainAction.command = {
                command: 'codeshield.explainVulnerability',
                title: 'Explain Security Vulnerability',
                arguments: [vulnerability]
            };

            actions.push(explainAction);
        }

        // Add general scan action
        if (actions.length === 0) {
            const scanAction = new vscode.CodeAction(
                'Scan for security issues',
                vscode.CodeActionKind.Source
            );
            
            scanAction.command = {
                command: 'codeshield.scanCurrentFile',
                title: 'Scan Current File'
            };

            actions.push(scanAction);
        }

        return actions;
    }

    private createQuickFixes(document: vscode.TextDocument, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const vulnRange = new vscode.Range(
            vulnerability.line - 1, vulnerability.column,
            vulnerability.line - 1, vulnerability.column + vulnerability.code.length
        );

        switch (vulnerability.type) {
            case 'sql-injection':
                fixes.push(...this.createSqlInjectionFixes(document, vulnRange, vulnerability));
                break;
            case 'api-key':
                fixes.push(...this.createApiKeyFixes(document, vulnRange, vulnerability));
                break;
            case 'hardcoded-secret':
                fixes.push(...this.createSecretFixes(document, vulnRange, vulnerability));
                break;
            case 'unsafe-eval':
                fixes.push(...this.createUnsafeEvalFixes(document, vulnRange, vulnerability));
                break;
            case 'path-traversal':
                fixes.push(...this.createPathTraversalFixes(document, vulnRange, vulnerability));
                break;
            case 'xss':
                fixes.push(...this.createXSSFixes(document, vulnRange, vulnerability));
                break;
            case 'ssrf':
                fixes.push(...this.createSSRFFixes(document, vulnRange, vulnerability));
                break;
        }

        return fixes;
    }

    private makeCopyFix(label: string, vulnerability: SecurityVulnerability): vscode.CodeAction {
        const fix = new vscode.CodeAction(label, vscode.CodeActionKind.QuickFix);
        fix.command = {
            command: 'codeshield.copySafeExample',
            title: label,
            arguments: [vulnerability]
        };
        fix.isPreferred = true;
        return fix;
    }

    private makeIgnoreFix(label: string, document: vscode.TextDocument, vulnerability: SecurityVulnerability): vscode.CodeAction {
        const fix = new vscode.CodeAction(label, vscode.CodeActionKind.Empty);
        fix.command = {
            command: 'codeshield.ignoreVulnerability',
            title: 'Ignore Vulnerability',
            arguments: [document, vulnerability]
        };
        return fix;
    }

    private createSqlInjectionFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy safe parameterized query example', vulnerability),
            this.makeIgnoreFix('Ignore this SQL injection warning', document, vulnerability),
        ];
    }

    private createApiKeyFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy environment variable example', vulnerability),
            this.makeIgnoreFix('Ignore this API key warning', document, vulnerability),
        ];
    }

    private createSecretFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy safe secret handling example', vulnerability),
            this.makeIgnoreFix('Ignore this hardcoded secret warning', document, vulnerability),
        ];
    }

    private createUnsafeEvalFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy safe alternative to eval', vulnerability),
            this.makeIgnoreFix('Ignore this unsafe eval warning', document, vulnerability),
        ];
    }

    private createPathTraversalFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy safe path handling example', vulnerability),
            this.makeIgnoreFix('Ignore this path traversal warning', document, vulnerability),
        ];
    }

    private createXSSFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy XSS-safe DOM update example', vulnerability),
            this.makeIgnoreFix('Ignore this XSS warning', document, vulnerability),
        ];
    }

    private createSSRFFixes(document: vscode.TextDocument, _range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        return [
            this.makeCopyFix('$(clippy) Copy safe URL validation example', vulnerability),
            this.makeIgnoreFix('Ignore this SSRF warning', document, vulnerability),
        ];
    }
}