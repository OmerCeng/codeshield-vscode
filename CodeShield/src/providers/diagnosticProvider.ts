import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { SecurityScanner } from '../scanner/securityScanner';

export class DiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private ignoredCollection: vscode.DiagnosticCollection;

    constructor(private securityScanner: SecurityScanner) {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeshield');
        this.ignoredCollection = vscode.languages.createDiagnosticCollection('codeshield-ignored');
    }

    updateDiagnostics(document: vscode.TextDocument, vulnerabilities: SecurityVulnerability[]) {
        this.diagnosticCollection.delete(document.uri);

        const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(v => {
            const range = new vscode.Range(
                v.line - 1, v.column,
                v.line - 1, v.column + v.code.length
            );
            const diagnostic = new vscode.Diagnostic(range, v.message, this.getSeverity(v.severity));
            diagnostic.source = 'CodeShield';
            diagnostic.code = v.type;
            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    updateIgnoredDiagnostics(document: vscode.TextDocument, ignoredVulnerabilities: SecurityVulnerability[]) {
        this.ignoredCollection.delete(document.uri);

        const diagnostics: vscode.Diagnostic[] = ignoredVulnerabilities.map(v => {
            const range = new vscode.Range(
                v.line - 1, v.column,
                v.line - 1, v.column + v.code.length
            );
            const label = v.type.replace(/-/g, ' ').toUpperCase();
            const diagnostic = new vscode.Diagnostic(
                range,
                `[Ignored] ${label} — ${v.message}`,
                vscode.DiagnosticSeverity.Information
            );
            diagnostic.source = 'CodeShield (ignored)';
            diagnostic.code = v.type;
            return diagnostic;
        });

        this.ignoredCollection.set(document.uri, diagnostics);
    }

    clearDiagnostics(document: vscode.TextDocument) {
        this.diagnosticCollection.delete(document.uri);
        this.ignoredCollection.delete(document.uri);
    }

    private getSeverity(severity: 'error' | 'warning' | 'info'): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'error':   return vscode.DiagnosticSeverity.Error;
            case 'warning': return vscode.DiagnosticSeverity.Warning;
            case 'info':    return vscode.DiagnosticSeverity.Information;
            default:        return vscode.DiagnosticSeverity.Warning;
        }
    }

    dispose() {
        this.diagnosticCollection.dispose();
        this.ignoredCollection.dispose();
    }
}