import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';

export class StatusBarProvider {
    private statusBarItem: vscode.StatusBarItem;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.statusBarItem.command = 'workbench.actions.view.problems';
        this.statusBarItem.tooltip = 'Click to open Problems panel';
        this.statusBarItem.show();
        this.setIdle();
    }

    update(vulnerabilities: SecurityVulnerability[]) {
        const critical = vulnerabilities.filter(v => v.severity === 'error').length;
        const warnings = vulnerabilities.filter(v => v.severity === 'warning').length;

        if (critical === 0 && warnings === 0) {
            this.statusBarItem.text = '$(shield) CodeShield: Secure';
            this.statusBarItem.backgroundColor = undefined;
            this.statusBarItem.tooltip = 'No security issues found. Click to open Problems panel.';
            return;
        }

        const parts: string[] = [];
        if (critical > 0) {
            parts.push(`${critical} critical`);
        }
        if (warnings > 0) {
            parts.push(`${warnings} warning${warnings > 1 ? 's' : ''}`);
        }

        this.statusBarItem.text = `$(shield) CodeShield: ${parts.join(' | ')}`;
        this.statusBarItem.tooltip = [
            `CodeShield found ${vulnerabilities.length} issue(s)`,
            critical > 0 ? `• ${critical} critical (errors)` : '',
            warnings > 0 ? `• ${warnings} warning(s)` : '',
            '',
            'Click to open Problems panel',
        ].filter(Boolean).join('\n');

        if (critical > 0) {
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else {
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        }
    }

    setIdle() {
        this.statusBarItem.text = '$(shield) CodeShield';
        this.statusBarItem.backgroundColor = undefined;
        this.statusBarItem.tooltip = 'CodeShield security scanner. Click to open Problems panel.';
    }

    setScanning() {
        this.statusBarItem.text = '$(sync~spin) CodeShield: Scanning...';
        this.statusBarItem.backgroundColor = undefined;
    }

    dispose() {
        this.statusBarItem.dispose();
    }
}
