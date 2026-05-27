import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { SecurityScanner } from '../scanner/securityScanner';

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
    private vulnerabilities: SecurityVulnerability[] = [];

    constructor(private securityScanner: SecurityScanner) {}

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

            // Copy safe example to clipboard (never modifies the file)
            if (vulnerability.fixAction) {
                const copyLens = new vscode.CodeLens(range, {
                    title: `$(clippy) Copy Safe Example`,
                    command: 'codeshield.copySafeExample',
                    arguments: [vulnerability]
                });
                codeLenses.push(copyLens);
            }

            // Ignore lens (compact)
            const ignoreLens = new vscode.CodeLens(range, {
                title: `❌  Ignore`,
                command: 'codeshield.ignoreVulnerability',
                arguments: [document, vulnerability]
            });
            codeLenses.push(ignoreLens);
        }

        if (this.vulnerabilities.length > 0) {
            const summaryRange = new vscode.Range(0, 0, 0, 0);

            const summaryLens = new vscode.CodeLens(summaryRange, {
                title: `🚨 ${this.vulnerabilities.length} security issue${this.vulnerabilities.length > 1 ? 's' : ''} found`,
                command: 'codeshield.scanCurrentFile',
            });

            const ignoreAllLens = new vscode.CodeLens(summaryRange, {
                title: `$(eye-closed) Ignore All in This File`,
                command: 'codeshield.ignoreAllInFile',
                arguments: [document],
            });

            codeLenses.unshift(ignoreAllLens);
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

    dispose() {
        this.onDidChangeCodeLensesEmitter.dispose();
    }

    private onDidChangeCodeLensesEmitter = new vscode.EventEmitter<void>();
    onDidChangeCodeLenses = this.onDidChangeCodeLensesEmitter.event;
}