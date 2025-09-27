import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { IgnoreManager } from '../utils/ignoreManager';

export class SecurityScanner {
    private sqlInjectionPatterns = [
        // SQL Injection patterns
        /['"]\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"]/g, // String concatenation in SQL
        /query\s*=\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
        /execute\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
        /cursor\.execute\s*\(\s*['"]\s*SELECT\s+.*?\s*%\s*/gi, // Python string formatting
        /Statement\.executeQuery\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi, // Java
        /SqlCommand\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi, // C#
    ];

    private apiKeyPatterns = [
        // Common API key patterns
        /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
        /secret[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
        /access[_-]?token\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
        /bearer\s+[a-zA-Z0-9_-]{20,}/gi,
        /sk-[a-zA-Z0-9]{20,}/g, // OpenAI API keys
        /pk-[a-zA-Z0-9]{20,}/g, // Stripe public keys
        /AKIA[0-9A-Z]{16}/g, // AWS Access Key
        /ya29\.[a-zA-Z0-9_-]{68}/g, // Google OAuth token
        /ghp_[a-zA-Z0-9]{36}/g, // GitHub personal access token
    ];

    private hardcodedSecretPatterns = [
        /password\s*[:=]\s*['"][^'"]{8,}['"]/gi,
        /pwd\s*[:=]\s*['"][^'"]{8,}['"]/gi,
        /private[_-]?key\s*[:=]\s*['"]-----BEGIN/gi,
        /connection[_-]?string\s*[:=]\s*['"].*password=/gi,
    ];

    private unsafeEvalPatterns = [
        /eval\s*\(/g,
        /Function\s*\(/g,
        /setTimeout\s*\(\s*['"][^'"]*['"]\s*,/g,
        /setInterval\s*\(\s*['"][^'"]*['"]\s*,/g,
        /execSync\s*\(\s*['"][^'"]*\$\{/g, // Command injection
    ];

    // Path Traversal - File system operations with user input
    private pathTraversalPatterns = [
        /fs\.readFile\s*\(\s*[^,)]*\+\s*/g, // Node.js fs.readFile with concatenation
        /fs\.writeFile\s*\(\s*[^,)]*\+\s*/g, // Node.js fs.writeFile with concatenation
        /require\s*\(\s*[^)]*\+\s*/g, // Dynamic require with user input
        /res\.sendFile\s*\(\s*[^)]*\+\s*/g, // Express sendFile with concatenation
        /open\s*\(\s*[^,)]*\+\s*/g, // Python open() with concatenation
        /readFileSync\s*\(\s*[^,)]*\+\s*/g, // Node.js readFileSync
        /createReadStream\s*\(\s*[^,)]*\+\s*/g, // Node.js createReadStream
    ];

    // XSS - Cross-Site Scripting vulnerabilities
    private xssPatterns = [
        /\.innerHTML\s*=\s*[^'"]*[\+\$\`]/g, // DOM innerHTML with dynamic content
        /document\.write\s*\(\s*[^'"]*[\+\$\`]/g, // document.write with variables
        /\$\(['"]\#[^'"]*['"]\)\.html\s*\(/g, // jQuery html() method
        /\.append\s*\(\s*[^'"]*[\+\$\`]/g, // DOM append with dynamic content
        /dangerouslySetInnerHTML/g, // React dangerouslySetInnerHTML
        /\.insertAdjacentHTML\s*\([^,]*,\s*[^'"]*[\+\$\`]/g, // insertAdjacentHTML
        /\.outerHTML\s*=\s*[^'"]*[\+\$\`]/g, // outerHTML assignment
    ];

    // SSRF - Server-Side Request Forgery
    private ssrfPatterns = [
        /fetch\s*\(\s*[^'"]*(?:req\.|request\.|input|user)/g, // fetch() with user input
        /axios\.(?:get|post|put|delete)\s*\(\s*[^'"]*(?:req\.|request\.|input|user)/g, // Axios with user input
        /request\s*\(\s*[^'"]*(?:req\.|input|user)/g, // HTTP request library
        /http\.(?:get|request)\s*\(\s*[^'"]*(?:req\.|input|user)/g, // Node.js http module
        /urllib\.request\.urlopen\s*\(\s*[^'"]*(?:request\.|input|user)/g, // Python urllib
        /requests\.(?:get|post)\s*\(\s*[^'"]*(?:request\.|input|user)/g, // Python requests
    ];

    // NoSQL Injection - MongoDB and other NoSQL databases
    private nosqlInjectionPatterns = [
        /db\.[a-zA-Z]+\.find\s*\(\s*\{[^}]*req\./g, // MongoDB find with req object
        /\.find\s*\(\s*\{[^}]*\$where/g, // MongoDB $where operator
        /\$where\s*:\s*[^'"]*[\+\$]/g, // $where with string concatenation
        /\.find\s*\(\s*req\.(?:body|query|params)/g, // Direct request object in find
        /\.findOne\s*\(\s*req\.(?:body|query|params)/g, // Direct request object in findOne
        /client\.search\s*\(\s*\{[^}]*req\./g, // Elasticsearch with request object
    ];

    // Prototype Pollution - JavaScript object manipulation
    private prototypePollutionPatterns = [
        /Object\.assign\s*\([^,]*,\s*(?:req\.|user|input)/g, // Object.assign with user input
        /_\.merge\s*\([^,]*,\s*(?:req\.|user|input)/g, // Lodash merge
        /\$\.extend\s*\([^,]*,\s*(?:req\.|user|input)/g, // jQuery extend
        /JSON\.parse\s*\(\s*(?:req\.|user|input)/g, // JSON.parse without validation
        /\.deepMerge\s*\([^,]*,\s*(?:req\.|user|input)/g, // Deep merge operations
        /\[\s*['"]__proto__['"]\s*\]/g, // Direct __proto__ access
        /\[\s*['"]constructor['"]\s*\]/g, // Constructor access
        /\[\s*['"]prototype['"]\s*\]/g, // Prototype access
    ];

    // ReDoS - Regular Expression Denial of Service
    private redosPatterns = [
        /\/\^?\([a-zA-Z\+\*]+\)\+\$?\//g, // Nested quantifiers (a+)+
        /\/\([^)]*\*\)\*/g, // Multiple nested quantifiers
        /\/\([a-zA-Z\|]+\)\*/g, // Alternation with quantifiers (a|a)*
        /\/\([a-zA-Z\+]+\)\+/g, // Nested plus quantifiers
        /\/\[[a-zA-Z\-]+\]\+\*/g, // Character class with nested quantifiers
        /\/\.\*\.\*/g, // Multiple .* patterns
        /\/\([^)]*\{[0-9]+,\}\)\+/g, // Nested quantifiers with explicit counts
    ];

    // Python-specific patterns
    private pythonUnsafePatterns = [
        /pickle\.loads?\s*\(/g, // Pickle deserialization
        /yaml\.load\s*\(/g, // Unsafe YAML loading (should use safe_load)
        /eval\s*\(/g, // Python eval
        /exec\s*\(/g, // Python exec
        /compile\s*\(/g, // Code compilation
        /\.__import__\s*\(/g, // Dynamic imports
        /getattr\s*\([^,]*,\s*[^'"]*[\+\$]/g, // Dynamic attribute access
    ];

    // Java-specific patterns
    private javaVulnerabilityPatterns = [
        // SQL Injection
        /Statement\.executeQuery\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
        /PreparedStatement\.setString\s*\(\s*\d+\s*,\s*[^)]*\+\s*/gi,
        /createQuery\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi, // JPA
        // Command Injection
        /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/gi,
        /ProcessBuilder\s*\([^)]*\+/gi,
        // Path Traversal
        /new\s+File\s*\([^)]*\+/gi,
        /Files\.readAllBytes\s*\([^)]*\+/gi,
        /FileInputStream\s*\([^)]*\+/gi,
        // Deserialization
        /ObjectInputStream\s*\(/gi,
        /readObject\s*\(\s*\)/gi,
        // LDAP Injection
        /DirContext\.search\s*\([^)]*\+/gi,
        // XPath Injection
        /XPath\.evaluate\s*\([^)]*\+/gi,
        // XXE
        /DocumentBuilderFactory\.newInstance\s*\(\s*\)/gi,
        /SAXParserFactory\.newInstance\s*\(\s*\)/gi,
    ];

    // C# specific patterns
    private csharpVulnerabilityPatterns = [
        // SQL Injection
        /SqlCommand\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
        /ExecuteReader\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
        /query\s*\+=\s*['"]/gi,
        // Command Injection
        /Process\.Start\s*\([^)]*\+/gi,
        /cmd\.exe.*?\+/gi,
        // Path Traversal
        /File\.ReadAllText\s*\([^)]*\+/gi,
        /File\.OpenRead\s*\([^)]*\+/gi,
        /Path\.Combine\s*\([^)]*Request\./gi,
        // Deserialization
        /BinaryFormatter\.Deserialize/gi,
        /JsonConvert\.DeserializeObject\s*</gi,
        // XSS
        /Html\.Raw\s*\(/gi,
        /Response\.Write\s*\([^)]*Request\./gi,
        // LDAP Injection
        /DirectorySearcher\s*\([^)]*\+/gi,
        // XXE
        /XmlDocument\.Load\s*\(/gi,
        /XDocument\.Load\s*\(/gi,
    ];

    // C++ specific patterns
    private cppVulnerabilityPatterns = [
        // Buffer Overflow
        /strcpy\s*\(/gi,
        /strcat\s*\(/gi,
        /sprintf\s*\(/gi,
        /gets\s*\(/gi,
        /scanf\s*\([^)]*%s/gi,
        // Memory Issues
        /malloc\s*\([^)]*\+/gi,
        /free\s*\([^)]*\)/gi, // Check for use-after-free patterns
        // Command Injection
        /system\s*\([^)]*\+/gi,
        /popen\s*\([^)]*\+/gi,
        /execve\s*\([^)]*\+/gi,
        // File Operations
        /fopen\s*\([^)]*\+/gi,
        /ifstream\s*\([^)]*\+/gi,
        // Format String
        /printf\s*\(\s*[^"'][^,)]*\)/gi, // printf without format string
        /fprintf\s*\([^,]*,\s*[^"'][^,)]*\)/gi,
        // SQL (if using C++ database libraries)
        /mysql_query\s*\([^)]*\+/gi,
        /sqlite3_exec\s*\([^)]*\+/gi,
    ];

    // PHP specific patterns  
    private phpVulnerabilityPatterns = [
        // SQL Injection
        /mysql_query\s*\(\s*['"]\s*SELECT\s+.*?\$_/gi,
        /mysqli_query\s*\([^)]*\$_/gi,
        /\$pdo->query\s*\([^)]*\$_/gi,
        /\$wpdb->get_results\s*\([^)]*\$_/gi, // WordPress
        // Command Injection
        /exec\s*\([^)]*\$_/gi,
        /system\s*\([^)]*\$_/gi,
        /shell_exec\s*\([^)]*\$_/gi,
        /passthru\s*\([^)]*\$_/gi,
        /proc_open\s*\([^)]*\$_/gi,
        // File Inclusion
        /include\s*\([^)]*\$_/gi,
        /require\s*\([^)]*\$_/gi,
        /include_once\s*\([^)]*\$_/gi,
        /require_once\s*\([^)]*\$_/gi,
        // Path Traversal
        /file_get_contents\s*\([^)]*\$_/gi,
        /readfile\s*\([^)]*\$_/gi,
        /fopen\s*\([^)]*\$_/gi,
        // Code Injection
        /eval\s*\([^)]*\$_/gi,
        /assert\s*\([^)]*\$_/gi,
        /create_function\s*\([^)]*\$_/gi,
        // Deserialization
        /unserialize\s*\([^)]*\$_/gi,
        // XSS
        /echo\s+\$_/gi,
        /print\s+\$_/gi,
        // LDAP Injection
        /ldap_search\s*\([^)]*\$_/gi,
        // XXE
        /simplexml_load_string\s*\([^)]*\$_/gi,
        /DOMDocument::loadXML\s*\([^)]*\$_/gi,
    ];

    // Template injection patterns
    private templateInjectionPatterns = [
        /Template\s*\(\s*[^'"]*[\+\$]/g, // Jinja2 template with user input
        /render_template_string\s*\(/g, // Flask render_template_string
        /from_string\s*\(\s*[^'"]*[\+\$]/g, // Template from string
        /\.render\s*\(\s*[^}]*user/g, // Template render with user data
    ];

    scanDocument(document: vscode.TextDocument): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];
        const text = document.getText();
        const lines = text.split('\n');

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            
            // Check for SQL injection
            vulnerabilities.push(...this.checkSqlInjection(line, lineIndex));
            
            // Check for API keys
            vulnerabilities.push(...this.checkApiKeys(line, lineIndex));
            
            // Check for hardcoded secrets
            vulnerabilities.push(...this.checkHardcodedSecrets(line, lineIndex));
            
            // Check for unsafe eval
            vulnerabilities.push(...this.checkUnsafeEval(line, lineIndex));
            
            // Check for path traversal
            vulnerabilities.push(...this.checkPathTraversal(line, lineIndex));
            
            // Check for XSS vulnerabilities
            vulnerabilities.push(...this.checkXSS(line, lineIndex));
            
            // Check for SSRF vulnerabilities
            vulnerabilities.push(...this.checkSSRF(line, lineIndex));
            
            // Check for NoSQL injection
            vulnerabilities.push(...this.checkNoSQLInjection(line, lineIndex));
            
            // Check for prototype pollution
            vulnerabilities.push(...this.checkPrototypePollution(line, lineIndex));
            
            // Check for ReDoS vulnerabilities
            vulnerabilities.push(...this.checkReDoS(line, lineIndex));
            
            // Check for Python-specific unsafe patterns
            vulnerabilities.push(...this.checkPythonUnsafe(line, lineIndex));
            
            // Check for template injection
            vulnerabilities.push(...this.checkTemplateInjection(line, lineIndex));
            
            // Language-specific vulnerability checks
            const languageId = document.languageId;
            if (languageId === 'java') {
                vulnerabilities.push(...this.checkJavaVulnerabilities(line, lineIndex));
            } else if (languageId === 'csharp') {
                vulnerabilities.push(...this.checkCSharpVulnerabilities(line, lineIndex));
            } else if (languageId === 'cpp' || languageId === 'c') {
                vulnerabilities.push(...this.checkCppVulnerabilities(line, lineIndex));
            } else if (languageId === 'php') {
                vulnerabilities.push(...this.checkPhpVulnerabilities(line, lineIndex));
            }
        }

        // Remove duplicates - same type on same line with same code
        const uniqueVulnerabilities = this.removeDuplicates(vulnerabilities);

        // Filter out ignored vulnerabilities
        return uniqueVulnerabilities.filter((vuln: SecurityVulnerability) => 
            !IgnoreManager.isIgnored(document, vuln.line, vuln.type)
        );
    }

    private checkSqlInjection(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.sqlInjectionPatterns) {
            let match;
            pattern.lastIndex = 0; // Reset regex
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'sql-injection',
                    message: 'Potential SQL injection vulnerability detected. Use parameterized queries instead.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use prepared statements or parameterized queries to prevent SQL injection attacks.',
                    fixAction: {
                        title: 'Use parameterized query',
                        replacement: this.getSqlInjectionFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkApiKeys(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.apiKeyPatterns) {
            let match;
            pattern.lastIndex = 0; // Reset regex
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'api-key',
                    message: 'Potential API key or secret token exposed in code.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Move sensitive credentials to environment variables or secure configuration files.',
                    fixAction: {
                        title: 'Move to environment variable',
                        replacement: this.getApiKeyFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkHardcodedSecrets(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.hardcodedSecretPatterns) {
            let match;
            pattern.lastIndex = 0; // Reset regex
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'hardcoded-secret',
                    message: 'Hardcoded secret detected. This poses a security risk.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use environment variables or secure credential management.',
                    fixAction: {
                        title: 'Use environment variable',
                        replacement: this.getSecretFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkUnsafeEval(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.unsafeEvalPatterns) {
            let match;
            pattern.lastIndex = 0; // Reset regex
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'unsafe-eval',
                    message: 'Unsafe code execution detected. This can lead to code injection attacks.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'warning',
                    code: match[0],
                    suggestion: 'Avoid using eval() or similar dynamic code execution methods.',
                    fixAction: {
                        title: 'Replace with safer alternative',
                        replacement: this.getUnsafeEvalFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private getSqlInjectionFix(code: string): string {
        // Provide language-specific fixes
        if (code.includes('cursor.execute')) {
            return 'cursor.execute("SELECT * FROM table WHERE id = %s", (user_id,))';
        } else if (code.includes('SqlCommand')) {
            return 'new SqlCommand("SELECT * FROM table WHERE id = @id", connection)';
        } else if (code.includes('executeQuery')) {
            return 'PreparedStatement stmt = connection.prepareStatement("SELECT * FROM table WHERE id = ?")';
        }
        return 'Use parameterized query instead of string concatenation';
    }

    private getApiKeyFix(code: string): string {
        const keyName = code.match(/(\w+)[_-]?(key|token|secret)/i)?.[0] || 'API_KEY';
        return `process.env.${keyName.toUpperCase()} || 'your-${keyName.toLowerCase()}-here'`;
    }

    private getSecretFix(code: string): string {
        if (code.includes('password')) {
            return 'process.env.DATABASE_PASSWORD';
        } else if (code.includes('private_key')) {
            return 'process.env.PRIVATE_KEY';
        }
        return 'process.env.SECRET_VALUE';
    }

    private getUnsafeEvalFix(code: string): string {
        if (code.includes('eval')) {
            return 'JSON.parse() // or use a safer parsing method';
        } else if (code.includes('Function')) {
            return '// Use a predefined function instead';
        } else if (code.includes('setTimeout') || code.includes('setInterval')) {
            return code.replace(/['"][^'"]*['"]/, 'functionReference');
        }
        return '// Use a safer alternative';
    }

    private checkPathTraversal(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.pathTraversalPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'path-traversal',
                    message: 'Path traversal vulnerability detected. Validate and sanitize file paths.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use path validation, whitelist allowed paths, or use path.resolve() with proper checks.',
                    fixAction: {
                        title: 'Add path validation',
                        replacement: this.getPathTraversalFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkXSS(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.xssPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'xss',
                    message: 'Cross-Site Scripting (XSS) vulnerability detected. Sanitize user input.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use proper encoding/escaping, Content Security Policy, or trusted sanitization libraries.',
                    fixAction: {
                        title: 'Sanitize user input',
                        replacement: this.getXSSFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkSSRF(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.ssrfPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'ssrf',
                    message: 'Server-Side Request Forgery (SSRF) vulnerability detected. Validate URLs.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Implement URL validation, use allowlists for allowed domains, or use a proxy.',
                    fixAction: {
                        title: 'Add URL validation',
                        replacement: this.getSSRFFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkNoSQLInjection(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.nosqlInjectionPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'nosql-injection',
                    message: 'NoSQL injection vulnerability detected. Sanitize database queries.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use proper input validation, avoid $where operators, and sanitize user input.',
                    fixAction: {
                        title: 'Sanitize NoSQL query',
                        replacement: this.getNoSQLInjectionFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkPrototypePollution(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.prototypePollutionPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'prototype-pollution',
                    message: 'Prototype pollution vulnerability detected. Avoid unsafe object operations.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'warning',
                    code: match[0],
                    suggestion: 'Use Object.create(null), validate object keys, or use safe merge libraries.',
                    fixAction: {
                        title: 'Use safe object operations',
                        replacement: this.getPrototypePollutionFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkReDoS(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.redosPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'redos',
                    message: 'Regular Expression Denial of Service (ReDoS) vulnerability detected.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'warning',
                    code: match[0],
                    suggestion: 'Avoid nested quantifiers, use atomic groups, or implement timeout for regex operations.',
                    fixAction: {
                        title: 'Optimize regex pattern',
                        replacement: this.getReDoSFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    // Fix suggestion methods for new vulnerability types
    private getPathTraversalFix(code: string): string {
        if (code.includes('fs.readFile')) {
            return 'fs.readFile(path.resolve(safeBasePath, sanitizedFileName))';
        } else if (code.includes('require')) {
            return '// Use static imports or validate module paths';
        } else if (code.includes('sendFile')) {
            return 'res.sendFile(path.join(__dirname, "safe", sanitizedPath))';
        }
        return 'path.resolve(basePath, sanitizedInput)';
    }

    private getXSSFix(code: string): string {
        if (code.includes('innerHTML')) {
            return 'element.textContent = sanitizedInput';
        } else if (code.includes('document.write')) {
            return '// Use DOM methods with proper escaping';
        } else if (code.includes('.html(')) {
            return '$("selector").text(sanitizedInput)';
        }
        return 'DOMPurify.sanitize(userInput)';
    }

    private getSSRFFix(code: string): string {
        if (code.includes('fetch')) {
            return 'fetch(validateAndSanitizeURL(userInput))';
        } else if (code.includes('axios')) {
            return 'axios.get(validateURL(userInput))';
        }
        return 'validateURL(userInput) && makeRequest(userInput)';
    }

    private getNoSQLInjectionFix(code: string): string {
        if (code.includes('find')) {
            return 'collection.find({field: sanitizeInput(userInput)})';
        } else if (code.includes('$where')) {
            return '// Avoid $where, use standard query operators';
        }
        return 'validateAndSanitizeQuery(userQuery)';
    }

    private getPrototypePollutionFix(code: string): string {
        if (code.includes('Object.assign')) {
            return 'Object.assign(Object.create(null), sanitizedInput)';
        } else if (code.includes('JSON.parse')) {
            return 'JSON.parse(input, secureReviver)';
        } else if (code.includes('merge')) {
            return 'safeMerge(target, sanitizedSource)';
        }
        return 'validateObjectKeys(userInput)';
    }

    private getReDoSFix(code: string): string {
        if (code.includes('(a+)+')) {
            return '/a+/ // Remove nested quantifiers';
        } else if (code.includes('.*.*')) {
            return '/.*/ // Use single .* instead of multiple';
        }
        return '// Optimize regex pattern to avoid catastrophic backtracking';
    }

    private checkPythonUnsafe(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.pythonUnsafePatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                let type: 'unsafe-eval' | 'hardcoded-secret' = 'unsafe-eval';
                let message = 'Unsafe Python operation detected.';
                
                if (match[0].includes('pickle')) {
                    message = 'Unsafe pickle deserialization detected. Use JSON or other safe formats.';
                } else if (match[0].includes('yaml.load')) {
                    message = 'Unsafe YAML loading detected. Use yaml.safe_load() instead.';
                } else if (match[0].includes('eval') || match[0].includes('exec')) {
                    message = 'Dangerous code execution detected. Avoid eval() and exec().';
                }

                vulnerabilities.push({
                    type,
                    message,
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use safer alternatives like JSON parsing or predefined functions.',
                    fixAction: {
                        title: 'Use safe alternative',
                        replacement: this.getPythonUnsafeFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private checkTemplateInjection(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.templateInjectionPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'xss', // Template injection is a form of XSS
                    message: 'Template injection vulnerability detected. Use predefined templates.',
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: 'Use predefined templates and sanitize template variables.',
                    fixAction: {
                        title: 'Use safe template',
                        replacement: this.getTemplateInjectionFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private getPythonUnsafeFix(code: string): string {
        if (code.includes('pickle.loads')) {
            return 'json.loads(data) # Use JSON instead of pickle';
        } else if (code.includes('yaml.load')) {
            return 'yaml.safe_load(data) # Use safe_load instead';
        } else if (code.includes('eval')) {
            return '# Use ast.literal_eval() for safe evaluation';
        } else if (code.includes('exec')) {
            return '# Use predefined functions instead of exec';
        }
        return '# Use a safer alternative';
    }

    private getTemplateInjectionFix(code: string): string {
        if (code.includes('Template(')) {
            return 'Template(predefined_template_string)';
        } else if (code.includes('render_template_string')) {
            return 'render_template(safe_template_name, data)';
        }
        return 'use_predefined_template(template_name, data)';
    }

    // Java-specific vulnerability checks
    private checkJavaVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.javaVulnerabilityPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                let type: any = 'java-vulnerability';
                let message = 'Java security vulnerability detected.';
                let suggestion = this.getJavaFix(match[0]);

                if (match[0].includes('executeQuery') || match[0].includes('createQuery')) {
                    type = 'sql-injection';
                    message = 'SQL injection vulnerability in Java code.';
                } else if (match[0].includes('Runtime') || match[0].includes('ProcessBuilder')) {
                    type = 'command-injection';
                    message = 'Command injection vulnerability detected.';
                } else if (match[0].includes('File') || match[0].includes('Files')) {
                    type = 'path-traversal';
                    message = 'Path traversal vulnerability detected.';
                } else if (match[0].includes('ObjectInputStream')) {
                    type = 'unsafe-deserialization';
                    message = 'Unsafe deserialization detected.';
                }

                vulnerabilities.push({
                    type: type,
                    message: message,
                    suggestion: suggestion,
                    line: lineIndex + 1,
                    column: match.index!,
                    code: match[0],
                    severity: 'error'
                });
            }
        }

        return vulnerabilities;
    }

    // C# specific vulnerability checks  
    private checkCSharpVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.csharpVulnerabilityPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                let type: any = 'csharp-vulnerability';
                let message = 'C# security vulnerability detected.';
                let suggestion = this.getCSharpFix(match[0]);

                if (match[0].includes('SqlCommand') || match[0].includes('ExecuteReader')) {
                    type = 'sql-injection';
                    message = 'SQL injection vulnerability in C# code.';
                } else if (match[0].includes('Process.Start')) {
                    type = 'command-injection';
                    message = 'Command injection vulnerability detected.';
                } else if (match[0].includes('File.') || match[0].includes('Path.')) {
                    type = 'path-traversal';
                    message = 'Path traversal vulnerability detected.';
                } else if (match[0].includes('Deserialize')) {
                    type = 'unsafe-deserialization';
                    message = 'Unsafe deserialization detected.';
                }

                vulnerabilities.push({
                    type: type,
                    message: message,
                    suggestion: suggestion,
                    line: lineIndex + 1,
                    column: match.index!,
                    code: match[0],
                    severity: 'error'
                });
            }
        }

        return vulnerabilities;
    }

    // C++ specific vulnerability checks
    private checkCppVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.cppVulnerabilityPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                let type: any = 'cpp-vulnerability';
                let message = 'C++ security vulnerability detected.';
                let suggestion = this.getCppFix(match[0]);

                if (match[0].includes('strcpy') || match[0].includes('strcat') || match[0].includes('sprintf')) {
                    type = 'buffer-overflow';
                    message = 'Buffer overflow vulnerability detected.';
                } else if (match[0].includes('system') || match[0].includes('popen')) {
                    type = 'command-injection';
                    message = 'Command injection vulnerability detected.';
                } else if (match[0].includes('printf') || match[0].includes('fprintf')) {
                    type = 'format-string';
                    message = 'Format string vulnerability detected.';
                } else if (match[0].includes('malloc') || match[0].includes('free')) {
                    type = 'memory-vulnerability';
                    message = 'Memory management vulnerability detected.';
                }

                vulnerabilities.push({
                    type: type,
                    message: message,
                    suggestion: suggestion,
                    line: lineIndex + 1,
                    column: match.index!,
                    code: match[0],
                    severity: 'error'
                });
            }
        }

        return vulnerabilities;
    }

    // PHP specific vulnerability checks
    private checkPhpVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        for (const pattern of this.phpVulnerabilityPatterns) {
            let match;
            pattern.lastIndex = 0;
            
            while ((match = pattern.exec(line)) !== null) {
                let type: any = 'php-vulnerability';
                let message = 'PHP security vulnerability detected.';
                let suggestion = this.getPhpFix(match[0]);

                if (match[0].includes('mysql_query') || match[0].includes('mysqli_query')) {
                    type = 'sql-injection';
                    message = 'SQL injection vulnerability in PHP code.';
                } else if (match[0].includes('exec') || match[0].includes('system') || match[0].includes('shell_exec')) {
                    type = 'command-injection';
                    message = 'Command injection vulnerability detected.';
                } else if (match[0].includes('include') || match[0].includes('require')) {
                    type = 'file-inclusion';
                    message = 'File inclusion vulnerability detected.';
                } else if (match[0].includes('file_get_contents') || match[0].includes('fopen')) {
                    type = 'path-traversal';
                    message = 'Path traversal vulnerability detected.';
                } else if (match[0].includes('unserialize')) {
                    type = 'unsafe-deserialization';
                    message = 'Unsafe deserialization detected.';
                } else if (match[0].includes('echo') || match[0].includes('print')) {
                    type = 'xss';
                    message = 'XSS vulnerability detected.';
                }

                vulnerabilities.push({
                    type: type,
                    message: message,
                    suggestion: suggestion,
                    line: lineIndex + 1,
                    column: match.index!,
                    code: match[0],
                    severity: 'error'
                });
            }
        }

        return vulnerabilities;
    }

    // Fix suggestions for Java
    private getJavaFix(code: string): string {
        if (code.includes('executeQuery') || code.includes('createQuery')) {
            return 'Use PreparedStatement with parameterized queries: "SELECT * FROM users WHERE id = ?"';
        } else if (code.includes('Runtime') || code.includes('ProcessBuilder')) {
            return 'Validate input and use ProcessBuilder with separate arguments';
        } else if (code.includes('File') || code.includes('Files')) {
            return 'Use Path.normalize() and validate file paths against whitelist';
        } else if (code.includes('ObjectInputStream')) {
            return 'Use secure serialization libraries like Jackson or validate object types';
        }
        return 'Apply proper input validation and use secure alternatives';
    }

    // Fix suggestions for C#
    private getCSharpFix(code: string): string {
        if (code.includes('SqlCommand') || code.includes('ExecuteReader')) {
            return 'Use SqlParameter with parameterized queries: cmd.Parameters.Add("@id", SqlDbType.Int)';
        } else if (code.includes('Process.Start')) {
            return 'Validate input and use Process.Start with ProcessStartInfo';
        } else if (code.includes('File.') || code.includes('Path.')) {
            return 'Use Path.GetFullPath() and validate against allowed directories';
        } else if (code.includes('Deserialize')) {
            return 'Use System.Text.Json or validate types before deserialization';
        }
        return 'Apply proper input validation and sanitization';
    }

    // Fix suggestions for C++
    private getCppFix(code: string): string {
        if (code.includes('strcpy') || code.includes('strcat')) {
            return 'Use strncpy() or std::string for safer string operations';
        } else if (code.includes('sprintf')) {
            return 'Use snprintf() with buffer size limits';
        } else if (code.includes('gets')) {
            return 'Use fgets() with buffer size limit';
        } else if (code.includes('system') || code.includes('popen')) {
            return 'Validate input and use execve() with separate arguments';
        } else if (code.includes('printf') || code.includes('fprintf')) {
            return 'Always use format strings: printf("%s", user_input)';
        } else if (code.includes('malloc')) {
            return 'Use smart pointers or RAII patterns';
        }
        return 'Use safe alternatives and validate all inputs';
    }

    /**
     * Remove duplicate vulnerabilities - same type on same line with overlapping positions
     */
    private removeDuplicates(vulnerabilities: SecurityVulnerability[]): SecurityVulnerability[] {
        const filtered: SecurityVulnerability[] = [];

        for (const vuln of vulnerabilities) {
            // Check if there's already a similar vulnerability
            const isDuplicate = filtered.some(existing => 
                existing.line === vuln.line && 
                existing.type === vuln.type &&
                // Check for overlapping positions (within 10 characters)
                Math.abs(existing.column - vuln.column) < 10
            );

            if (!isDuplicate) {
                filtered.push(vuln);
            } else {
                // If duplicate but this one has better fix, replace it
                const existingIndex = filtered.findIndex(existing => 
                    existing.line === vuln.line && 
                    existing.type === vuln.type &&
                    Math.abs(existing.column - vuln.column) < 10
                );
                
                if (existingIndex !== -1 && vuln.fixAction && !filtered[existingIndex].fixAction) {
                    filtered[existingIndex] = vuln;
                }
            }
        }

        return filtered;
    }

    // Fix suggestions for PHP
    private getPhpFix(code: string): string {
        if (code.includes('mysql_query') || code.includes('mysqli_query')) {
            return 'Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?")';
        } else if (code.includes('exec') || code.includes('system')) {
            return 'Use escapeshellarg() and validate input before execution';
        } else if (code.includes('include') || code.includes('require')) {
            return 'Use whitelist validation and basename() to prevent directory traversal';
        } else if (code.includes('file_get_contents') || code.includes('fopen')) {
            return 'Validate file paths and use realpath() to prevent traversal';
        } else if (code.includes('unserialize')) {
            return 'Use json_decode() or validate data before unserializing';
        } else if (code.includes('echo') || code.includes('print')) {
            return 'Use htmlspecialchars() to escape output: echo htmlspecialchars($_GET["data"])';
        }
        return 'Apply proper input validation and output encoding';
    }
}