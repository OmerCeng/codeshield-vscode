import * as vscode from 'vscode';

interface SecureSnippet {
    trigger: string;
    label: string;
    detail: string;
    documentation: string;
    insertText: string;
    languages: string[];
}

const SECURE_SNIPPETS: SecureSnippet[] = [
    // SQL — JavaScript / TypeScript
    {
        trigger: 'db.query(',
        label: 'db.query() — secure parameterized',
        detail: 'CodeShield: Safe SQL query',
        documentation: 'Parameterized query prevents SQL injection. Never concatenate user input into SQL strings.',
        insertText: 'db.query("SELECT * FROM ${1:table} WHERE ${2:column} = ?", [${3:userInput}])',
        languages: ['javascript', 'typescript'],
    },
    {
        trigger: 'connection.query(',
        label: 'connection.query() — secure parameterized',
        detail: 'CodeShield: Safe SQL query',
        documentation: 'Use placeholders (?) instead of string concatenation to prevent SQL injection.',
        insertText: 'connection.query("SELECT * FROM ${1:table} WHERE ${2:column} = ?", [${3:userInput}], (err, results) => {\n\t${4:// handle results}\n})',
        languages: ['javascript', 'typescript'],
    },
    // SQL — Python
    {
        trigger: 'cursor.execute(',
        label: 'cursor.execute() — secure parameterized',
        detail: 'CodeShield: Safe SQL query',
        documentation: 'Use %s placeholders with a tuple argument — never use f-strings or % formatting in SQL.',
        insertText: 'cursor.execute("SELECT * FROM ${1:table} WHERE ${2:column} = %s", (${3:user_input},))',
        languages: ['python'],
    },
    // SQL — Java
    {
        trigger: 'connection.prepareStatement(',
        label: 'prepareStatement() — secure parameterized',
        detail: 'CodeShield: Safe PreparedStatement',
        documentation: 'PreparedStatement prevents SQL injection. Use ? as placeholders.',
        insertText: [
            'PreparedStatement stmt = connection.prepareStatement(',
            '\t"SELECT * FROM ${1:table} WHERE ${2:column} = ?");',
            'stmt.setString(1, ${3:userInput});',
            'ResultSet rs = stmt.executeQuery();',
        ].join('\n'),
        languages: ['java'],
    },
    // Hashing — JavaScript
    {
        trigger: 'bcrypt.hash(',
        label: 'bcrypt.hash() — secure password hashing',
        detail: 'CodeShield: Safe password hashing',
        documentation: 'Use bcrypt with a cost factor of at least 12. Never store plain-text passwords.',
        insertText: 'bcrypt.hash(${1:password}, 12)',
        languages: ['javascript', 'typescript'],
    },
    // Hashing — Python
    {
        trigger: 'hashlib.',
        label: 'hashlib — secure password hashing',
        detail: 'CodeShield: Use bcrypt/argon2, not hashlib for passwords',
        documentation: 'hashlib (MD5, SHA1, SHA256) is not suitable for passwords. Use bcrypt or argon2-cffi instead.',
        insertText: [
            '# Secure password hashing with bcrypt',
            'import bcrypt',
            'hashed = bcrypt.hashpw(${1:password}.encode(), bcrypt.gensalt(rounds=12))',
        ].join('\n'),
        languages: ['python'],
    },
    // File read — Node.js
    {
        trigger: 'fs.readFile(',
        label: 'fs.readFile() — with path validation',
        detail: 'CodeShield: Safe file read',
        documentation: 'Always resolve and validate file paths to prevent path traversal attacks.',
        insertText: [
            'const safePath = path.resolve(${1:BASE_DIR}, path.basename(${2:userInput}));',
            'if (!safePath.startsWith(${1:BASE_DIR})) {',
            '\tthrow new Error("Access denied");',
            '}',
            'fs.readFile(safePath, "utf8", (err, data) => {',
            '\t${3:// handle data}',
            '});',
        ].join('\n'),
        languages: ['javascript', 'typescript'],
    },
    // eval alternative — JavaScript
    {
        trigger: 'JSON.parse(',
        label: 'JSON.parse() — safe alternative to eval',
        detail: 'CodeShield: Safe JSON parsing',
        documentation: 'Use JSON.parse() instead of eval() to parse data. Never use eval() on user input.',
        insertText: [
            'let parsed;',
            'try {',
            '\tparsed = JSON.parse(${1:input});',
            '} catch {',
            '\tthrow new Error("Invalid JSON input");',
            '}',
        ].join('\n'),
        languages: ['javascript', 'typescript'],
    },
    // subprocess — Python
    {
        trigger: 'subprocess.run(',
        label: 'subprocess.run() — without shell=True',
        detail: 'CodeShield: Safe subprocess call',
        documentation: 'Never use shell=True with user-controlled input. Pass arguments as a list.',
        insertText: [
            'subprocess.run(',
            '\t["${1:command}", "${2:arg1}"],',
            '\tcapture_output=True,',
            '\ttext=True,',
            '\tcheck=True',
            ')',
        ].join('\n'),
        languages: ['python'],
    },
    // fetch — JavaScript
    {
        trigger: 'fetch(',
        label: 'fetch() — with URL validation',
        detail: 'CodeShield: Safe HTTP request',
        documentation: 'Validate URLs against an allowlist before fetching to prevent SSRF attacks.',
        insertText: [
            'const ALLOWED_HOSTS = ["${1:api.example.com}"];',
            'const url = new URL(${2:userInput});',
            'if (!ALLOWED_HOSTS.includes(url.hostname)) {',
            '\tthrow new Error("Forbidden URL");',
            '}',
            'const response = await fetch(url.toString());',
        ].join('\n'),
        languages: ['javascript', 'typescript'],
    },
    // innerHTML alternative
    {
        trigger: 'innerHTML',
        label: 'textContent — safe innerHTML alternative',
        detail: 'CodeShield: XSS-safe DOM update',
        documentation: 'Use textContent instead of innerHTML to prevent XSS when inserting user-provided text.',
        insertText: '${1:element}.textContent = ${2:userInput};',
        languages: ['javascript', 'typescript'],
    },
    // yaml.safe_load — Python
    {
        trigger: 'yaml.load(',
        label: 'yaml.safe_load() — safe YAML loading',
        detail: 'CodeShield: Safe YAML parsing',
        documentation: 'yaml.load() with arbitrary input allows code execution. Always use yaml.safe_load().',
        insertText: 'yaml.safe_load(${1:stream})',
        languages: ['python'],
    },
    // ast.literal_eval — Python
    {
        trigger: 'ast.literal_eval(',
        label: 'ast.literal_eval() — safe eval alternative',
        detail: 'CodeShield: Safe expression evaluation',
        documentation: 'ast.literal_eval() safely evaluates strings containing Python literals only. Use instead of eval().',
        insertText: [
            'import ast',
            'ast.literal_eval(${1:user_input})',
        ].join('\n'),
        languages: ['python'],
    },
];

export class SecureCompletionProvider implements vscode.CompletionItemProvider {
    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
    ): vscode.ProviderResult<vscode.CompletionItem[]> {
        const lineText = document.lineAt(position).text.substring(0, position.character);
        const languageId = document.languageId;

        const items: vscode.CompletionItem[] = [];

        for (const snippet of SECURE_SNIPPETS) {
            if (!snippet.languages.includes(languageId)) {
                continue;
            }
            const keyword = snippet.trigger.replace(/[([.,]/g, '').toLowerCase();
            if (!lineText.toLowerCase().includes(keyword)) {
                continue;
            }

            const item = new vscode.CompletionItem(
                snippet.label,
                vscode.CompletionItemKind.Snippet,
            );

            item.detail = snippet.detail;
            item.documentation = new vscode.MarkdownString(
                `🛡 **CodeShield — Secure Snippet**\n\n${snippet.documentation}`,
            );
            item.insertText = new vscode.SnippetString(snippet.insertText);
            item.sortText = '0_codeshield_' + snippet.label;
            item.filterText = snippet.trigger;

            items.push(item);
        }

        return items;
    }
}

export function getSnippetsForTrigger(trigger: string, languageId: string): SecureSnippet[] {
    return SECURE_SNIPPETS.filter(s =>
        s.languages.includes(languageId) &&
        trigger.includes(s.trigger.replace(/[([.]/g, '').toLowerCase())
    );
}
