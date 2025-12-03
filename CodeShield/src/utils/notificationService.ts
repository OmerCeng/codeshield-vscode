import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';

export interface NotificationRule {
    vulnerabilityTypes?: string[];
    minSeverity?: 'error' | 'warning' | 'info';
    showPopup?: boolean;
    playSound?: boolean;
    customMessage?: string;
}

export class NotificationService {
    private static readonly CONFIG_KEY = 'codeshield.notifications';
    
    static async notifyVulnerability(vulnerability: SecurityVulnerability, document: vscode.TextDocument): Promise<void> {
        const config = vscode.workspace.getConfiguration();
        const rules = config.get<NotificationRule>(this.CONFIG_KEY);
        
        // Default rule if not configured
        const defaultRule: NotificationRule = {
            minSeverity: 'error',
            showPopup: true,
            playSound: false
        };
        
        const activeRule = rules || defaultRule;
        
        // Check if we should notify based on rules
        if (!this.shouldNotify(vulnerability, activeRule)) {
            return;
        }
        
        // Build notification message
        const message = activeRule.customMessage 
            ? activeRule.customMessage.replace('{type}', vulnerability.type).replace('{message}', vulnerability.message)
            : `🛡️ Security Issue: ${vulnerability.message}`;
        
        const fileName = document.fileName.split('/').pop();
        const fullMessage = `${message}\n📄 File: ${fileName}:${vulnerability.line}`;
        
        // Show popup if enabled
        if (activeRule.showPopup) {
            const action = await this.showNotificationPopup(vulnerability, fullMessage);
            if (action === 'Fix Now') {
                vscode.commands.executeCommand('codeshield.applyQuickFix', document.uri, vulnerability);
            } else if (action === 'Ignore') {
                vscode.commands.executeCommand('codeshield.ignoreVulnerability', document, vulnerability);
            }
        }
        
        // Play sound if enabled (VS Code doesn't have built-in sound, but we can show status bar)
        if (activeRule.playSound) {
            this.flashStatusBar(vulnerability);
        }
    }
    
    private static shouldNotify(vulnerability: SecurityVulnerability, rule: NotificationRule): boolean {
        // Check vulnerability type filter
        if (rule.vulnerabilityTypes && rule.vulnerabilityTypes.length > 0) {
            if (!rule.vulnerabilityTypes.includes(vulnerability.type)) {
                return false;
            }
        }
        
        // Check severity filter
        if (rule.minSeverity) {
            const severityLevels = { 'info': 0, 'warning': 1, 'error': 2 };
            const vulnLevel = severityLevels[vulnerability.severity];
            const minLevel = severityLevels[rule.minSeverity];
            
            if (vulnLevel < minLevel) {
                return false;
            }
        }
        
        return true;
    }
    
    private static async showNotificationPopup(
        vulnerability: SecurityVulnerability, 
        message: string
    ): Promise<string | undefined> {
        const severityIcon = {
            'error': '🔴',
            'warning': '⚠️',
            'info': 'ℹ️'
        };
        
        const icon = severityIcon[vulnerability.severity];
        const actions: string[] = [];
        
        if (vulnerability.fixAction) {
            actions.push('Fix Now');
        }
        actions.push('Ignore', 'Details');
        
        if (vulnerability.severity === 'error') {
            return await vscode.window.showErrorMessage(`${icon} ${message}`, ...actions);
        } else if (vulnerability.severity === 'warning') {
            return await vscode.window.showWarningMessage(`${icon} ${message}`, ...actions);
        } else {
            return await vscode.window.showInformationMessage(`${icon} ${message}`, ...actions);
        }
    }
    
    private static flashStatusBar(vulnerability: SecurityVulnerability): void {
        const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        statusBarItem.text = `$(alert) ${vulnerability.type}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        statusBarItem.show();
        
        // Flash for 3 seconds
        setTimeout(() => {
            statusBarItem.dispose();
        }, 3000);
    }
    
    static async notifyMultipleVulnerabilities(
        vulnerabilities: SecurityVulnerability[], 
        document: vscode.TextDocument
    ): Promise<void> {
        // Only show notifications for critical (error) vulnerabilities
        const critical = vulnerabilities.filter(v => v.severity === 'error');
        
        if (critical.length > 0) {
            const fileName = document.fileName.split('/').pop();
            const message = `🔴 CodeShield: Found ${critical.length} critical security issue(s) in ${fileName}`;
            
            const action = await vscode.window.showErrorMessage(message, 'View All', 'Dismiss');
            
            if (action === 'View All') {
                // Show all vulnerabilities in a webview panel
                this.showVulnerabilityList(critical, document);
            }
        }
    }
    
    private static showVulnerabilityList(
        vulnerabilities: SecurityVulnerability[],
        document: vscode.TextDocument
    ): void {
        const panel = vscode.window.createWebviewPanel(
            'vulnerabilityList',
            '🛡️ CodeShield - Critical Security Issues',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true
            }
        );
        
        const fileName = document.fileName.split('/').pop();
        const vulnerabilityItems = vulnerabilities.map((v, index) => `
            <div class="vuln-item" onclick="navigateToLine(${v.line}, ${v.column || 0})">
                <div class="vuln-header">
                    <span class="vuln-number">#${index + 1}</span>
                    <span class="vuln-type">${v.type.toUpperCase().replace(/-/g, ' ')}</span>
                    <span class="vuln-location">Line ${v.line}</span>
                </div>
                <div class="vuln-message">${v.message}</div>
                <div class="vuln-code"><code>${this.escapeHtml(v.code)}</code></div>
            </div>
        `).join('');
        
        panel.webview.html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Issues</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            padding: 20px;
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
        }
        h1 {
            color: var(--vscode-errorForeground);
            margin-bottom: 10px;
        }
        .file-info {
            color: var(--vscode-descriptionForeground);
            margin-bottom: 30px;
            font-size: 14px;
        }
        .vuln-item {
            background: var(--vscode-editor-inactiveSelectionBackground);
            border-left: 4px solid var(--vscode-errorForeground);
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .vuln-item:hover {
            background: var(--vscode-list-hoverBackground);
            transform: translateX(5px);
        }
        .vuln-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }
        .vuln-number {
            background: var(--vscode-errorForeground);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .vuln-type {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .vuln-location {
            color: var(--vscode-textLink-foreground);
            font-size: 13px;
            margin-left: auto;
        }
        .vuln-message {
            color: var(--vscode-foreground);
            margin-bottom: 10px;
            font-size: 14px;
        }
        .vuln-code {
            background: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
        code {
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: var(--vscode-textPreformat-foreground);
        }
        .info-box {
            background: var(--vscode-inputValidation-infoBackground);
            border: 1px solid var(--vscode-inputValidation-infoBorder);
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <h1>🔴 Critical Security Issues</h1>
    <div class="file-info">📄 File: ${fileName} | Found ${vulnerabilities.length} issue(s)</div>
    
    <div class="info-box">
        💡 Click on any issue to navigate to the code location
    </div>
    
    ${vulnerabilityItems}
    
    <script>
        const vscode = acquireVsCodeApi();
        
        function navigateToLine(line, column) {
            vscode.postMessage({
                command: 'navigateToLine',
                line: line,
                column: column
            });
        }
    </script>
</body>
</html>`;
        
        // Handle messages from webview
        panel.webview.onDidReceiveMessage(
            async message => {
                if (message.command === 'navigateToLine') {
                    const editor = await vscode.window.showTextDocument(document);
                    const position = new vscode.Position(message.line - 1, message.column);
                    const range = new vscode.Range(position, position);
                    
                    editor.selection = new vscode.Selection(position, position);
                    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
                }
            }
        );
    }
    
    private static escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}
