import * as vscode from 'vscode';
import { SecurityScanner } from '../scanner/securityScanner';
import { SecurityVulnerability } from '../types/vulnerability';
import { IgnoreManager } from '../utils/ignoreManager';

export class CodeActionProvider implements vscode.CodeActionProvider {
    private securityScanner = new SecurityScanner();

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

    private createSqlInjectionFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        // Fix 1: Use parameterized query
        const parameterizedFix = new vscode.CodeAction(
            '🔧 Use parameterized query',
            vscode.CodeActionKind.QuickFix
        );
        parameterizedFix.edit = new vscode.WorkspaceEdit();
        
        let fixedCode = '';
        if (line.includes('cursor.execute')) {
            fixedCode = line.replace(/["']\s*SELECT\s+.*?\+\s*[^"']*["']/gi, '"SELECT * FROM table WHERE id = %s", (param,)');
        } else if (line.includes('executeQuery')) {
            fixedCode = line.replace(/["']\s*SELECT\s+.*?\+\s*[^"']*["']/gi, '"SELECT * FROM table WHERE id = ?"');
        } else {
            fixedCode = line.replace(/["']\s*.*?\+\s*[^"']*["']/gi, '"SELECT * FROM table WHERE id = ?"');
        }

        parameterizedFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedCode);
        parameterizedFix.isPreferred = true;
        fixes.push(parameterizedFix);

        // Fix 2: Add comment about ORM usage
        const ormFix = new vscode.CodeAction(
            '💡 Suggest ORM usage',
            vscode.CodeActionKind.QuickFix
        );
        ormFix.edit = new vscode.WorkspaceEdit();
        ormFix.edit.insert(document.uri, range.start, '// TODO: Consider using an ORM like Sequelize, TypeORM, or SQLAlchemy\n');
        fixes.push(ormFix);

        // Fix 3: Ignore this SQL injection warning
        const ignoreSqlFix = new vscode.CodeAction(
            '�️ Ignore this SQL injection warning',
            vscode.CodeActionKind.Empty
        );
        ignoreSqlFix.command = {
            command: 'codeshield.ignoreVulnerability',
            title: 'Ignore Vulnerability',
            arguments: [document, vulnerability]
        };
        fixes.push(ignoreSqlFix);

        return fixes;
    }

    private createApiKeyFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        // Fix 1: Replace with environment variable
        const envFix = new vscode.CodeAction(
            '🔑 Use environment variable',
            vscode.CodeActionKind.QuickFix
        );
        envFix.edit = new vscode.WorkspaceEdit();
        
        const keyName = this.extractKeyName(vulnerability.code);
        const envVar = `process.env.${keyName}`;
        const fixedLine = line.replace(/["'][^"']*["']/, envVar);
        
        envFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
        envFix.isPreferred = true;
        fixes.push(envFix);

        // Fix 2: Add .env file reminder
        const envFileFix = new vscode.CodeAction(
            '📄 Add to .env file',
            vscode.CodeActionKind.QuickFix
        );
        envFileFix.edit = new vscode.WorkspaceEdit();
        envFileFix.edit.insert(document.uri, range.start, `// Add to .env file: ${keyName}=your_actual_key_here\n`);
        fixes.push(envFileFix);

        // Fix 3: Ignore this API key warning
        const ignoreApiKeyFix = new vscode.CodeAction(
            '�️ Ignore this API key warning',
            vscode.CodeActionKind.Empty
        );
        ignoreApiKeyFix.command = {
            command: 'codeshield.ignoreVulnerability',
            title: 'Ignore Vulnerability',
            arguments: [document, vulnerability]
        };
        fixes.push(ignoreApiKeyFix);

        return fixes;
    }

    private createSecretFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        // Fix 1: Environment variable
        const envFix = new vscode.CodeAction(
            '🔒 Use environment variable',
            vscode.CodeActionKind.QuickFix
        );
        envFix.edit = new vscode.WorkspaceEdit();
        
        let envVarName = 'SECRET_VALUE';
        if (line.includes('password')) {
            envVarName = 'DATABASE_PASSWORD';
        }
        if (line.includes('secret')) {
            envVarName = 'SECRET_KEY';
        }
        
        const fixedLine = line.replace(/["'][^"']*["']/, `process.env.${envVarName}`);
        envFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
        envFix.isPreferred = true;
        fixes.push(envFix);

        // Fix 2: Ignore this secret warning
        const ignoreSecretFix = new vscode.CodeAction(
            '�️ Ignore this secret warning',
            vscode.CodeActionKind.Empty
        );
        ignoreSecretFix.command = {
            command: 'codeshield.ignoreVulnerability',
            title: 'Ignore Vulnerability',
            arguments: [document, vulnerability]
        };
        fixes.push(ignoreSecretFix);

        return fixes;
    }

    private createUnsafeEvalFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        if (line.includes('eval(')) {
            // Fix 1: JSON.parse for eval
            const jsonFix = new vscode.CodeAction(
                '🔧 Use JSON.parse instead',
                vscode.CodeActionKind.QuickFix
            );
            jsonFix.edit = new vscode.WorkspaceEdit();
            const fixedLine = line.replace(/eval\s*\([^)]+\)/, 'JSON.parse(input)');
            jsonFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
            jsonFix.isPreferred = true;
            fixes.push(jsonFix);
        }

        if (line.includes('setTimeout') && line.includes('"')) {
            // Fix 2: Function reference for setTimeout
            const funcRefFix = new vscode.CodeAction(
                '⚡ Use function reference',
                vscode.CodeActionKind.QuickFix
            );
            funcRefFix.edit = new vscode.WorkspaceEdit();
            const fixedLine = line.replace(/setTimeout\s*\(\s*["'][^"']*["']\s*,/, 'setTimeout(functionName,');
            funcRefFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
            fixes.push(funcRefFix);
        }

        return fixes;
    }

    private createPathTraversalFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        // Fix 1: path.resolve usage
        const pathResolveFix = new vscode.CodeAction(
            '📁 Use path.resolve',
            vscode.CodeActionKind.QuickFix
        );
        pathResolveFix.edit = new vscode.WorkspaceEdit();
        
        let fixedLine = line;
        if (line.includes('fs.readFile')) {
            fixedLine = line.replace(/["'][^"']*["']\s*\+\s*[^,)]+/, 'path.resolve(safeBasePath, sanitizedFileName)');
        } else if (line.includes('res.sendFile')) {
            fixedLine = line.replace(/\+\s*[^)]+/, ', sanitizedPath)');
        }
        
        pathResolveFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
        pathResolveFix.isPreferred = true;
        fixes.push(pathResolveFix);

        // Fix 2: Add path import
        const importFix = new vscode.CodeAction(
            '📦 Add path import',
            vscode.CodeActionKind.QuickFix
        );
        importFix.edit = new vscode.WorkspaceEdit();
        importFix.edit.insert(document.uri, new vscode.Position(0, 0), 'const path = require("path");\n');
        fixes.push(importFix);

        return fixes;
    }

    private createXSSFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        if (line.includes('innerHTML')) {
            // Fix 1: textContent instead of innerHTML
            const textContentFix = new vscode.CodeAction(
                '🌐 Use textContent',
                vscode.CodeActionKind.QuickFix
            );
            textContentFix.edit = new vscode.WorkspaceEdit();
            const fixedLine = line.replace(/\.innerHTML\s*=/, '.textContent =');
            textContentFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
            textContentFix.isPreferred = true;
            fixes.push(textContentFix);
        }

        if (line.includes('$') && line.includes('.html(')) {
            // Fix 2: jQuery .text() instead of .html()
            const jqueryTextFix = new vscode.CodeAction(
                '📝 Use .text() instead',
                vscode.CodeActionKind.QuickFix
            );
            jqueryTextFix.edit = new vscode.WorkspaceEdit();
            const fixedLine = line.replace(/\.html\s*\(/, '.text(');
            jqueryTextFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
            fixes.push(jqueryTextFix);
        }

        return fixes;
    }

    private createSSRFFixes(document: vscode.TextDocument, range: vscode.Range, vulnerability: SecurityVulnerability): vscode.CodeAction[] {
        const fixes: vscode.CodeAction[] = [];
        const line = document.lineAt(range.start.line).text;

        // Fix 1: Add URL validation
        const validateFix = new vscode.CodeAction(
            '🌍 Add URL validation',
            vscode.CodeActionKind.QuickFix
        );
        validateFix.edit = new vscode.WorkspaceEdit();
        
        let fixedLine = line;
        if (line.includes('fetch(')) {
            fixedLine = line.replace(/fetch\s*\(\s*([^)]+)\)/, 'fetch(validateURL($1))');
        } else if (line.includes('axios.')) {
            fixedLine = line.replace(/axios\.[a-z]+\s*\(\s*([^)]+)\)/, 'axios.get(validateURL($1))');
        }
        
        validateFix.edit.replace(document.uri, range.with(range.start, range.start.with(range.start.line, line.length)), fixedLine);
        validateFix.isPreferred = true;
        fixes.push(validateFix);

        // Fix 2: Add validation function
        const addValidationFix = new vscode.CodeAction(
            '🔧 Add validateURL function',
            vscode.CodeActionKind.QuickFix
        );
        addValidationFix.edit = new vscode.WorkspaceEdit();
        const validationFunction = `
function validateURL(url) {
    const allowedDomains = ['api.example.com', 'trusted-service.com'];
    try {
        const urlObj = new URL(url);
        return allowedDomains.includes(urlObj.hostname) ? url : null;
    } catch {
        return null;
    }
}
`;
        addValidationFix.edit.insert(document.uri, new vscode.Position(0, 0), validationFunction);
        fixes.push(addValidationFix);

        return fixes;
    }

    private extractKeyName(code: string): string {
        const keyMatch = code.match(/(\w+)[_-]?(key|token|secret)/i);
        if (keyMatch) {
            return keyMatch[0].toUpperCase().replace('-', '_');
        }
        return 'API_KEY';
    }
}