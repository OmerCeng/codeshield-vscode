import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';

export class SecurityDecorationProvider {
    private decorationTypes: Map<string, vscode.TextEditorDecorationType> = new Map();

    constructor() {
        this.initializeDecorations();
    }

    private initializeDecorations() {
        // SQL Injection - Minimalist red underline
        this.decorationTypes.set('sql-injection', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #FF3B30',
            overviewRulerColor: '#FF3B30',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#FF3B30'),
            gutterIconSize: '60%'
        }));

        // API Key - Minimalist orange underline
        this.decorationTypes.set('api-key', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #FF9500',
            overviewRulerColor: '#FF9500',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#FF9500'),
            gutterIconSize: '60%'
        }));

        // Hardcoded Secret - Minimalist purple underline
        this.decorationTypes.set('hardcoded-secret', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #AF52DE',
            overviewRulerColor: '#AF52DE',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#AF52DE'),
            gutterIconSize: '60%'
        }));

        // Unsafe Eval - Minimalist yellow underline
        this.decorationTypes.set('unsafe-eval', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #FFCC00',
            overviewRulerColor: '#FFCC00',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#FFCC00'),
            gutterIconSize: '60%'
        }));

        // Path Traversal - Minimalist blue underline
        this.decorationTypes.set('path-traversal', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #007AFF',
            overviewRulerColor: '#007AFF',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#007AFF'),
            gutterIconSize: '60%'
        }));

        // XSS - Minimalist pink underline
        this.decorationTypes.set('xss', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #FF2D55',
            overviewRulerColor: '#FF2D55',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#FF2D55'),
            gutterIconSize: '60%'
        }));

        // SSRF - Minimalist green underline
        this.decorationTypes.set('ssrf', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #34C759',
            overviewRulerColor: '#34C759',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#34C759'),
            gutterIconSize: '60%'
        }));

        // NoSQL Injection - Minimalist cyan underline
        this.decorationTypes.set('nosql-injection', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #5AC8FA',
            overviewRulerColor: '#5AC8FA',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#5AC8FA'),
            gutterIconSize: '60%'
        }));

        // Prototype Pollution - Minimalist teal underline
        this.decorationTypes.set('prototype-pollution', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #64D2FF',
            overviewRulerColor: '#64D2FF',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#64D2FF'),
            gutterIconSize: '60%'
        }));

        // ReDoS - Minimalist gray underline
        this.decorationTypes.set('redos', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #8E8E93',
            overviewRulerColor: '#8E8E93',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            gutterIconPath: this.createMinimalIcon('●', '#8E8E93'),
            gutterIconSize: '60%'
        }));
    }

    private createSvgIcon(emoji: string, color: string): vscode.Uri {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
            <circle cx="8" cy="8" r="7" fill="${color}" opacity="0.8"/>
            <text x="8" y="12" text-anchor="middle" font-size="10" fill="white">${emoji}</text>
        </svg>`;
        
        const encodedSvg = Buffer.from(svg).toString('base64');
        return vscode.Uri.parse(`data:image/svg+xml;base64,${encodedSvg}`);
    }

    private createMinimalIcon(symbol: string, color: string): vscode.Uri {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 12 12">
            <circle cx="6" cy="6" r="3" fill="${color}" opacity="0.9"/>
        </svg>`;
        
        const encodedSvg = Buffer.from(svg).toString('base64');
        return vscode.Uri.parse(`data:image/svg+xml;base64,${encodedSvg}`);
    }

    updateDecorations(editor: vscode.TextEditor, vulnerabilities: SecurityVulnerability[]) {
        // Clear all existing decorations
        for (const [type, decoration] of this.decorationTypes) {
            editor.setDecorations(decoration, []);
        }

        // Group vulnerabilities by type
        const groupedVulnerabilities: Map<string, vscode.DecorationOptions[]> = new Map();

        for (const vulnerability of vulnerabilities) {
            if (!groupedVulnerabilities.has(vulnerability.type)) {
                groupedVulnerabilities.set(vulnerability.type, []);
            }

            const range = new vscode.Range(
                vulnerability.line - 1,
                vulnerability.column,
                vulnerability.line - 1,
                vulnerability.column + vulnerability.code.length
            );

            const decorationOption: vscode.DecorationOptions = {
                range,
                hoverMessage: new vscode.MarkdownString(
                    `### 🛡️ CodeShield Security Alert\n\n` +
                    `**Type:** ${vulnerability.type.replace('-', ' ').toUpperCase()}\n\n` +
                    `**Message:** ${vulnerability.message}\n\n` +
                    `**Severity:** ${vulnerability.severity}\n\n` +
                    `**Code:** \`${vulnerability.code}\`\n\n` +
                    `**Suggestion:** ${vulnerability.suggestion}\n\n` +
                    `---\n\n` +
                    `💡 *Right-click for quick fixes*`
                )
            };

            groupedVulnerabilities.get(vulnerability.type)!.push(decorationOption);
        }

        // Apply decorations by type
        for (const [type, decorations] of groupedVulnerabilities) {
            const decorationType = this.decorationTypes.get(type);
            if (decorationType) {
                editor.setDecorations(decorationType, decorations);
            }
        }
    }

    clearDecorations(editor: vscode.TextEditor) {
        for (const [type, decoration] of this.decorationTypes) {
            editor.setDecorations(decoration, []);
        }
    }

    dispose() {
        for (const [type, decoration] of this.decorationTypes) {
            decoration.dispose();
        }
        this.decorationTypes.clear();
    }
}