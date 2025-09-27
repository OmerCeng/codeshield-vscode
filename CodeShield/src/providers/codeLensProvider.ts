import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { SecurityScanner } from '../scanner/securityScanner';

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
    private securityScanner = new SecurityScanner();
    private vulnerabilities: SecurityVulnerability[] = [];

    provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] {
        const codeLenses: vscode.CodeLens[] = [];
        
        // Scan document for vulnerabilities
        this.vulnerabilities = this.securityScanner.scanDocument(document);

        for (const vulnerability of this.vulnerabilities) {
            const range = new vscode.Range(
                vulnerability.line - 1,
                0,
                vulnerability.line - 1,
                0
            );

            // Main security alert lens
            const securityLens = new vscode.CodeLens(range, {
                title: `🛡️ ${this.getSecurityIcon(vulnerability.type)} ${vulnerability.type.replace('-', ' ').toUpperCase()} - ${vulnerability.severity.toUpperCase()}`,
                command: 'codeshield.explainVulnerability',
                arguments: [vulnerability]
            });
            codeLenses.push(securityLens);

            // Quick fix lens (if available)
            if (vulnerability.fixAction) {
                const fixLens = new vscode.CodeLens(range, {
                    title: `🔧 ${vulnerability.fixAction.title}`,
                    command: 'codeshield.applyQuickFix',
                    arguments: [document.uri, vulnerability]
                });
                codeLenses.push(fixLens);
            }

            // Ignore lens (compact)
            const ignoreLens = new vscode.CodeLens(range, {
                title: `❌  Ignore`,
                command: 'codeshield.ignoreVulnerability',
                arguments: [document, vulnerability]
            });
            codeLenses.push(ignoreLens);
        }

        // Add summary lens at top of file if vulnerabilities exist
        if (this.vulnerabilities.length > 0) {
            const summaryRange = new vscode.Range(0, 0, 0, 0);
            const summaryLens = new vscode.CodeLens(summaryRange, {
                title: `🚨 ${this.vulnerabilities.length} Security Issue${this.vulnerabilities.length > 1 ? 's' : ''} Found - Click to scan workspace`,
                command: 'codeshield.scanWorkspace'
            });
            codeLenses.unshift(summaryLens);
        }

        return codeLenses;
    }

    private getSecurityIcon(type: string): string {
        const icons: { [key: string]: string } = {
            'sql-injection': '🚨',
            'api-key': '🔑',
            'hardcoded-secret': '🔒',
            'unsafe-eval': '⚠️',
            'path-traversal': '📁',
            'xss': '🌐',
            'ssrf': '🌍',
            'nosql-injection': '🗃️',
            'prototype-pollution': '🧬',
            'redos': '🔄'
        };
        return icons[type] || '🛡️';
    }

    refresh() {
        this.onDidChangeCodeLensesEmitter.fire();
    }

    private onDidChangeCodeLensesEmitter = new vscode.EventEmitter<void>();
    onDidChangeCodeLenses = this.onDidChangeCodeLensesEmitter.event;
}