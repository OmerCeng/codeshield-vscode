import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { SecurityScanner } from '../scanner/securityScanner';

export class DiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(private securityScanner: SecurityScanner) {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeshield');
    }

    updateDiagnostics(document: vscode.TextDocument, vulnerabilities: SecurityVulnerability[]) {
        // Clear existing diagnostics first
        this.diagnosticCollection.delete(document.uri);
        
        const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vulnerability => {
            const range = new vscode.Range(
                vulnerability.line - 1,
                vulnerability.column,
                vulnerability.line - 1,
                vulnerability.column + vulnerability.code.length
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                vulnerability.message,
                this.getSeverity(vulnerability.severity)
            );

            diagnostic.source = 'CodeShield';
            diagnostic.code = vulnerability.type;
            
            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    clearDiagnostics(document: vscode.TextDocument) {
        this.diagnosticCollection.delete(document.uri);
    }

    private getSeverity(severity: 'error' | 'warning' | 'info'): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'info':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    dispose() {
        this.diagnosticCollection.dispose();
    }
}