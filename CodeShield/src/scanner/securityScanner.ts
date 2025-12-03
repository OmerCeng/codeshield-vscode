import * as vscode from 'vscode';
import { SecurityVulnerability } from '../types/vulnerability';
import { IgnoreManager } from '../utils/ignoreManager';

export class SecurityScanner {
    private sqlInjectionPatterns = [
        // SQL Injection patterns - catches various naming conventions
        /['"]\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*['"]/g, // String concatenation in SQL
        /\b(query|sql|cmd|command)\b\s*=\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi,
        /\b(execute|exec|query|run)\b\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi,
        /cursor\.\b(execute|exec)\b\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*%\s*/gi, // Python string formatting
        /Statement\.\b(executeQuery|executeUpdate|execute)\b\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi, // Java
        /\b(SqlCommand|SqlDataAdapter|MySqlCommand|NpgsqlCommand)\b\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi, // C# / .NET
        /db\.\b(query|execute|run|exec|raw)\b\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi, // Generic DB query
        /\b(f['"]|\.format\()\s*.*?(?:SELECT|INSERT|UPDATE|DELETE)/gi, // Python f-strings and format
    ];

    private apiKeyPatterns = [
        // Common API key patterns - More flexible to catch variations
        /\b(api[_-]?key|apikey|api)\b\s*[:=]\s*['"][a-zA-Z0-9_-]{8,}['"]/gi,
        /\b(secret[_-]?key|secretkey|secret)\b\s*[:=]\s*['"][a-zA-Z0-9_-]{8,}['"]/gi,
        /\b(access[_-]?token|accesstoken|token)\b\s*[:=]\s*['"][a-zA-Z0-9_-]{8,}['"]/gi,
        /\b(auth[_-]?token|authtoken)\b\s*[:=]\s*['"][a-zA-Z0-9_-]{8,}['"]/gi,
        /bearer\s+[a-zA-Z0-9_-]{20,}/gi,
        /sk-[a-zA-Z0-9]{20,}/g, // OpenAI API keys
        /pk-[a-zA-Z0-9]{20,}/g, // Stripe public keys
        /AKIA[0-9A-Z]{16}/g, // AWS Access Key
        /ya29\.[a-zA-Z0-9_-]{68}/g, // Google OAuth token
        /ghp_[a-zA-Z0-9]{36}/g, // GitHub personal access token
    ];

    private hardcodedSecretPatterns = [
        /\b(password|passwd|pwd|pass)\b\s*[:=]\s*['"][^'"]{4,}['"]/gi,
        /\b(private[_-]?key|privatekey|pkey)\b\s*[:=]\s*['"]-----BEGIN/gi,
        /\b(connection[_-]?string|connectionstring|conn[_-]?str)\b\s*[:=]\s*['"].*password=/gi,
        /\b(db[_-]?password|dbpassword|database[_-]?pwd)\b\s*[:=]\s*['"][^'"]{4,}['"]/gi,
    ];

    private unsafeEvalPatterns = [
        /\beval\s*\(/g,
        /\bFunction\s*\(/g,
        /\b(setTimeout|setInterval)\s*\(\s*['"][^'"]*['"]\s*,/g,
        /\b(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*['"][^'"]*\$\{/g, // Command injection
        /\b(system|shell_exec|exec|passthru|popen)\s*\(/g, // PHP command execution
        /\b(Runtime\.getRuntime\(\)\.exec)\s*\(/g, // Java command execution
        /\b(Process\.Start|ProcessStartInfo)\s*\(/g, // C# process execution
        /\b(__import__|compile|execfile)\s*\(/g, // Python dynamic imports
    ];

    // Path Traversal - File system operations with user input
    private pathTraversalPatterns = [
        /\b(fs\.|filesystem\.|file\.)?(readFile|read|writeFile|write|readFileSync|writeFileSync)\s*\(\s*[^,)]*\+\s*/g, // Node.js fs operations
        /\b(require|import)\s*\(\s*[^)]*\+\s*/g, // Dynamic require/import with user input
        /\b(res\.|response\.)?(sendFile|download|send)\s*\(\s*[^)]*\+\s*/g, // Express file operations
        /\bopen\s*\(\s*[^,)]*\+\s*/g, // Python open() with concatenation
        /\b(createReadStream|createWriteStream|readdir|readdirSync)\s*\(\s*[^,)]*\+\s*/g, // Node.js stream operations
        /\b(File|FileReader|FileWriter|FileInputStream|FileOutputStream)\s*\(\s*[^)]*\+\s*/g, // Java file operations
        /\b(Path\.Combine|File\.ReadAllText|File\.WriteAllText|File\.Open)\s*\(\s*[^)]*\+\s*/g, // C# file operations
        /\b(include|require|include_once|require_once)\s*\(\s*[^)]*\+\s*/g, // PHP file inclusion
    ];

    // XSS - Cross-Site Scripting vulnerabilities
    private xssPatterns = [
        /\.(innerHTML|innerText|outerHTML)\s*=\s*[^'"]*[\+\$\`]/g, // DOM manipulation with dynamic content
        /\b(document\.write|document\.writeln)\s*\(\s*[^'"]*[\+\$\`]/g, // document.write with variables
        /\$\(['"]\#?[^'"]*['"]\)\.\b(html|append|prepend|after|before|replaceWith)\b\s*\(/g, // jQuery DOM methods
        /\.(append|prepend|after|before|replaceWith)\s*\(\s*[^'"]*[\+\$\`]/g, // DOM manipulation
        /\bdangerouslySetInnerHTML\b/g, // React dangerouslySetInnerHTML
        /\.(insertAdjacentHTML|insertAdjacentText|insertAdjacentElement)\s*\([^,]*,\s*[^'"]*[\+\$\`]/g, // Adjacent HTML insertion
        /\b(v-html|ng-bind-html)\s*=/g, // Vue.js and AngularJS unsafe binding
        /\{\{\{.*?\}\}\}/g, // Handlebars/Mustache unescaped output
        /\[innerHTML\]\s*=\s*[^'"]*[\+\$\`]/g, // Angular innerHTML binding
    ];

    // SSRF - Server-Side Request Forgery
    private ssrfPatterns = [
        /\b(fetch|Request)\s*\(\s*[^'"]*(?:req\.|request\.|params\.|query\.|body\.|input|user)/g, // fetch() with user input
        /\b(axios|http|https)\.\b(get|post|put|delete|patch|request)\b\s*\(\s*[^'"]*(?:req\.|request\.|params\.|query\.|body\.|input|user)/g, // HTTP libraries with user input
        /\b(request|got|superagent|needle)\s*\(\s*[^'"]*(?:req\.|params\.|query\.|body\.|input|user)/g, // HTTP request libraries
        /\b(urllib|urllib2|urllib3)\.\b(request|urlopen)\b\s*\(\s*[^'"]*(?:request\.|params\.|input|user)/g, // Python urllib
        /\b(requests|httpx|aiohttp)\.\b(get|post|put|delete|patch|request)\b\s*\(\s*[^'"]*(?:request\.|params\.|input|user)/g, // Python requests
        /\b(HttpClient|WebClient|RestClient)\.\b(GetAsync|PostAsync|SendAsync)\b\s*\(\s*[^'"]*(?:request\.|input|user)/g, // C# HTTP clients
        /\b(URL|URI)\s*\(\s*[^'"]*(?:req\.|request\.|params\.|query\.|input|user)/g, // URL construction with user input
    ];

    // NoSQL Injection - MongoDB and other NoSQL databases
    private nosqlInjectionPatterns = [
        /\b(db|collection|model)\.[a-zA-Z]+\.\b(find|findOne|findMany|update|updateOne|updateMany|delete|deleteOne|deleteMany)\b\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.|body\.)/g, // MongoDB operations with req object
        /\.\b(find|findOne|findMany)\b\s*\(\s*\{[^}]*\$where/g, // MongoDB $where operator
        /\$where\s*:\s*[^'"]*[\+\$\`]/g, // $where with string concatenation
        /\.\b(find|findOne|findMany)\b\s*\(\s*(?:req\.|request\.|params\.|query\.)(?:body|query|params)/g, // Direct request object in find
        /\b(client|index)\.\b(search|query)\b\s*\(\s*\{[^}]*(?:req\.|request\.|params\.|query\.)/g, // Elasticsearch with request object
        /\b(redis|cache)\.\b(get|set|hget|hset)\b\s*\(\s*(?:req\.|request\.|params\.|input)/g, // Redis injection
        /\b(collection|table)\.\b(where|filter)\b\s*\(\s*(?:req\.|request\.|params\.|query\.)/g, // Generic NoSQL where/filter
    ];

    // Prototype Pollution - JavaScript object manipulation
    private prototypePollutionPatterns = [
        /\b(Object)\.\b(assign|create|defineProperty|defineProperties|setPrototypeOf)\b\s*\([^,]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user|input)/g, // Object methods with user input
        /\b(_|lodash)\.\b(merge|mergeWith|defaultsDeep|extend|assign)\b\s*\([^,]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user|input)/g, // Lodash merge
        /\$\.\b(extend|merge)\b\s*\([^,]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user|input)/g, // jQuery extend
        /\b(JSON)\.\b(parse)\b\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|user|input)/g, // JSON.parse without validation
        /\.\b(deepMerge|deepExtend|deepAssign)\b\s*\([^,]*,\s*(?:req\.|request\.|params\.|query\.|body\.|user|input)/g, // Deep merge operations
        /\[\s*(?:['"]__proto__['"]|`__proto__`)\s*\]/g, // Direct __proto__ access
        /\[\s*(?:['"]constructor['"]|`constructor`)\s*\]\s*\[\s*(?:['"]prototype['"]|`prototype`)\s*\]/g, // Constructor prototype access
        /\.\b(__proto__|constructor|prototype)\b\s*=/g, // Direct prototype assignment
        /\b(set|put|extend)\b\s*\(\s*[^,]*,\s*['"](__proto__|constructor|prototype)['"]/g, // Setting dangerous properties
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
        /\b(new\s+)?RegExp\s*\(\s*[^)]*\(\w*\+\)\+/g, // Dynamic regex with nested quantifiers
        /\/\(.+\|\1\)+\//g, // Backreference alternation
        /\/\(\[\^\]\]*\)\*\(\[\^\]\]*\)\*/g, // Multiple negated character classes
        /\/\w\{\d+,\}\+/g, // Large min quantifier with +
        /\/\(\?:\w+\)\*/g, // Non-capturing group with *
    ];

    // Python-specific patterns
    private pythonUnsafePatterns = [
        /\b(pickle|cPickle|dill)\.(loads?|Unpickler)\s*\(/g, // Pickle deserialization (all variants)
        /\byaml\.(load|unsafe_load|full_load)\s*\(/g, // Unsafe YAML loading (should use safe_load)
        /\b(eval|exec|execfile)\s*\(/g, // Python eval/exec
        /\bcompile\s*\(/g, // Code compilation
        /\.__import__\s*\(/g, // Dynamic imports
        /\bgetattr\s*\([^,]*,\s*[^'"]*[\+\$]/g, // Dynamic attribute access
        /\b(os\.)?system\s*\(/g, // OS system calls
        /\bsubprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/g, // Shell injection
        /\bimportlib\.import_module\s*\([^)]*\+/g, // Dynamic module import
        /\b__builtins__\[/g, // Builtins manipulation
        /\binput\s*\(\)\s*(?!.*(?:strip|lower|upper|replace|validate))/g, // Unvalidated input
    ];

    // Java-specific patterns
    private javaVulnerabilityPatterns = [
        // SQL Injection
        /\b(Statement|PreparedStatement)\.(executeQuery|executeUpdate|execute)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi,
        /\bPreparedStatement\.setString\s*\(\s*\d+\s*,\s*[^)]*\+\s*/gi,
        /\bcreateQuery\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi, // JPA
        /\b(entityManager|session)\.createNativeQuery\s*\([^)]*\+/gi, // Native queries
        // Command Injection
        /\bRuntime\.getRuntime\(\)\.exec\s*\([^)]*\+/gi,
        /\bProcessBuilder\s*\([^)]*\+/gi,
        /\bnew\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList)?\s*\([^)]*\+/gi,
        // Path Traversal
        /\bnew\s+File\s*\([^)]*\+/gi,
        /\bFiles\.(readAllBytes|readAllLines|newInputStream|newOutputStream)\s*\([^)]*\+/gi,
        /\b(FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\([^)]*\+/gi,
        // Deserialization
        /\bObjectInputStream\s*\(/gi,
        /\breadObject\s*\(\s*\)/gi,
        /\bXMLDecoder\.readObject/gi,
        // LDAP Injection
        /\bDirContext\.(search|lookup)\s*\([^)]*\+/gi,
        /\bLdapContext\.search\s*\([^)]*\+/gi,
        // XPath Injection
        /\bXPath\.(evaluate|compile)\s*\([^)]*\+/gi,
        // XXE
        /\bDocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/gi,
        /\bSAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/gi,
        /\bXMLInputFactory\.newInstance\s*\(\s*\)(?!.*setProperty)/gi,
        // SSRF
        /\bnew\s+URL\s*\([^)]*request\./gi,
        /\bHttpURLConnection\.openConnection\s*\([^)]*\+/gi,
        // Reflection abuse
        /\bClass\.forName\s*\([^)]*\+/gi,
        /\bMethod\.invoke\s*\([^,]*,\s*[^)]*\+/gi,
    ];

    // C# specific patterns
    private csharpVulnerabilityPatterns = [
        // SQL Injection
        /\b(SqlCommand|MySqlCommand|NpgsqlCommand|OracleCommand)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi,
        /\b(ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\s*\+\s*/gi,
        /\bquery\s*\+=\s*['"](?:SELECT|INSERT|UPDATE|DELETE)/gi,
        /\bCommandText\s*=\s*[^;]*\+/gi,
        // Command Injection
        /\bProcess\.Start\s*\([^)]*\+/gi,
        /\bProcessStartInfo\s*\([^)]*\+/gi,
        /\bcmd\.exe.*?\+/gi,
        /\bpowershell\.exe.*?\+/gi,
        // Path Traversal
        /\bFile\.(ReadAllText|ReadAllBytes|ReadAllLines|OpenRead|OpenWrite|Create)\s*\([^)]*\+/gi,
        /\bDirectory\.(GetFiles|GetDirectories|CreateDirectory)\s*\([^)]*\+/gi,
        /\bPath\.Combine\s*\([^)]*(?:Request\.|HttpContext\.|User)/gi,
        /\bFileStream\s*\([^)]*\+/gi,
        // Deserialization
        /\bBinaryFormatter\.Deserialize/gi,
        /\bJsonConvert\.DeserializeObject\s*</gi,
        /\bXmlSerializer\.Deserialize/gi,
        /\bDataContractSerializer/gi,
        // XSS
        /\bHtml\.Raw\s*\(/gi,
        /\bResponse\.Write\s*\([^)]*(?:Request\.|User)/gi,
        /\b@Html\.Raw\s*\(/gi,
        // LDAP Injection
        /\bDirectorySearcher\s*\([^)]*\+/gi,
        /\bDirectoryEntry\s*\([^)]*\+/gi,
        // XXE
        /\bXmlDocument\.Load\s*\((?!.*XmlReaderSettings)/gi,
        /\bXDocument\.Load\s*\((?!.*LoadOptions)/gi,
        /\bXmlReader\.Create\s*\(\s*[^,)]*\s*(?:,\s*null)?\s*\)/gi,
        // SSRF
        /\bnew\s+WebClient\s*\(\).*?\.(?:Download|Upload)\w+\s*\([^)]*(?:Request\.|User)/gi,
        /\bHttpClient\s*\(\).*?\.(?:GetAsync|PostAsync)\s*\([^)]*\+/gi,
    ];

    // C++ specific patterns
    private cppVulnerabilityPatterns = [
        // Buffer Overflow
        /\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|fscanf)\s*\(/gi,
        /\bstrcpy_s\s*\([^,]*,\s*[^,]*,\s*(?!sizeof)/gi, // strcpy_s with hardcoded size
        /\bstrncpy\s*\([^,]*,\s*[^,]*,\s*sizeof\s*\([^)]*\)\s*\+/gi, // strncpy with wrong size
        /\bmemcpy\s*\([^,]*,\s*[^,]*,\s*[^)]*\+/gi, // memcpy with calculated size
        // Memory Issues
        /\bmalloc\s*\([^)]*\+/gi,
        /\balloca\s*\(/gi, // Stack allocation (dangerous)
        /\b(new|delete)\s+(?!\[).*?;.*?\1/gi, // Double free/delete patterns
        /\bdelete\s+(?!\[)[^;]*;.*?\1/gi, // Use after delete
        /\brealloc\s*\([^,]*,\s*[^)]*\+/gi,
        // Command Injection
        /\b(system|popen|execve|execl|execlp|execle|execv|execvp|execvpe)\s*\([^)]*\+/gi,
        // File Operations
        /\b(fopen|freopen|open|creat)\s*\([^)]*\+/gi,
        /\b(ifstream|ofstream|fstream)\s*\([^)]*\+/gi,
        // Format String
        /\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf)\s*\(\s*[^"'][^,)]*\)/gi, // printf without format string
        /\b(printf|fprintf)\s*\([^,]*,\s*[^"'][^,)]*\)/gi,
        // SQL (if using C++ database libraries)
        /\bmysql_query\s*\([^)]*\+/gi,
        /\bsqlite3_exec\s*\([^)]*\+/gi,
        /\bPQexec\s*\([^)]*\+/gi, // PostgreSQL
        // Integer Overflow
        /\bstatic_cast<(?:int|unsigned|long|short)>\s*\([^)]*\+[^)]*\*/gi,
        // Race Conditions
        /\baccess\s*\(.*?fopen/gi, // TOCTOU
        /\bstat\s*\(.*?(?:open|fopen)/gi,
    ];

    // PHP specific patterns  
    private phpVulnerabilityPatterns = [
        // SQL Injection
        /\b(mysql_query|mysqli_query|pg_query|mssql_query)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\$_/gi,
        /\bmysqli_query\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/gi,
        /\$(?:pdo|db|conn)->(?:query|exec|prepare)\s*\([^)]*\$_/gi,
        /\$wpdb->(?:get_results|get_var|query)\s*\([^)]*\$_/gi, // WordPress
        // Command Injection
        /\b(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\([^)]*\$_/gi,
        /\bbackticks.*?\$_/gi, // Backtick execution
        // File Inclusion
        /\b(include|require|include_once|require_once)\s*\([^)]*\$_/gi,
        /\b(fopen|file_get_contents|readfile|file|parse_ini_file)\s*\([^)]*\$_/gi,
        // Path Traversal
        /\b(fopen|file_get_contents|readfile|unlink|rmdir|copy|rename)\s*\([^)]*\$_/gi,
        /\b(move_uploaded_file)\s*\([^,]*,\s*[^)]*\$_/gi,
        // XSS
        /\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)(?!.*?htmlspecialchars)/gi,
        /\bprint\s+\$_(?:GET|POST|REQUEST|COOKIE)(?!.*?htmlspecialchars)/gi,
        /\b<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)(?!.*?htmlspecialchars)/gi,
        // Deserialization
        /\bunserialize\s*\(\s*\$_/gi,
        // Code Injection
        /\beval\s*\(\s*\$_/gi,
        /\bassert\s*\(\s*\$_/gi,
        /\bcreate_function\s*\([^)]*\$_/gi,
        /\bpreg_replace\s*\(.*?\/e['"].*?\$_/gi, // preg_replace with /e modifier
        // LDAP Injection
        /\bldap_search\s*\([^)]*\$_/gi,
        // XXE
        /\bsimplexml_load_(?:string|file)\s*\(\s*\$_(?!.*?LIBXML_NOENT)/gi,
        /\b(?:new\s+)?DOMDocument\s*\(\).*?load(?:XML)?\s*\(\s*\$_/gi,
        // File Upload
        /\bmove_uploaded_file\s*\([^)]*\$_FILES.*?(?!.*?\.(?:jpg|png|gif|pdf))/gi,
        // Open Redirect
        /\bheader\s*\(['"]Location:\s*['"]\s*\.\s*\$_/gi,
    ];

    // Go specific patterns
    private goVulnerabilityPatterns = [
        // SQL Injection
        /\b(db|conn)\.(Query|QueryRow|Exec|QueryContext|ExecContext)\s*\([^)]*\+/gi,
        /\b(db|conn)\.Prepare\s*\([^)]*\+/gi,
        // Command Injection
        /\bexec\.Command\s*\([^)]*\+/gi,
        /\bexec\.CommandContext\s*\([^,]*,\s*[^)]*\+/gi,
        // Path Traversal
        /\b(os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*\+/gi,
        /\bos\.OpenFile\s*\([^)]*\+/gi,
        /\bfilepath\.Join\s*\([^)]*(?:r\.|req\.|request\.)/gi,
        // SSRF
        /\bhttp\.(Get|Post|Head|PostForm)\s*\([^)]*(?:r\.|req\.|request\.)/gi,
        /\bhttp\.NewRequest\s*\([^,]*,\s*[^)]*(?:r\.|req\.|request\.)/gi,
        // Unsafe Reflection
        /\breflect\.(ValueOf|TypeOf)\s*\([^)]*(?:userInput|req\.)/gi,
        // Template Injection
        /\btemplate\.(New|ParseFiles|ParseGlob)\s*\([^)]*\+/gi,
        // YAML Deserialization
        /\byaml\.Unmarshal\s*\([^,]*(?:req\.|request\.)/gi,
        // XML External Entity
        /\bxml\.Unmarshal\s*\([^,]*(?:req\.|request\.)/gi,
        // Memory Issues
        /\bunsafe\.Pointer/gi,
        // Race Conditions
        /\bgo\s+func\s*\([^)]*\)\s*\{[^}]*(?:shared|global)Variable/gi,
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
            } else if (languageId === 'go') {
                vulnerabilities.push(...this.checkGoVulnerabilities(line, lineIndex));
            } else if (languageId === 'dart') {
                vulnerabilities.push(...this.checkDartVulnerabilities(line, lineIndex));
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
                    severity: 'error',
                    fixAction: {
                        title: 'Apply Java security fix',
                        replacement: suggestion
                    }
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
                    severity: 'error',
                    fixAction: {
                        title: 'Apply C# security fix',
                        replacement: suggestion
                    }
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
                    severity: 'error',
                    fixAction: {
                        title: 'Apply C++ security fix',
                        replacement: suggestion
                    }
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
                    severity: 'error',
                    fixAction: {
                        title: 'Apply PHP security fix',
                        replacement: suggestion
                    }
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

    // Go-specific vulnerability checks
    private checkGoVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];
        
        // Go-specific patterns - sadece temel olanları
        const patterns = [
            { 
                regex: /exec\.Command\s*\(\s*[^,)]*\+\s*/g,
                message: 'Command injection vulnerability detected in Go code.',
                suggestion: 'Use separate arguments instead of string concatenation.'
            },
            { 
                regex: /db\.Query\s*\(\s*['"]\s*SELECT\s+.*?\s*\+\s*/gi,
                message: 'SQL injection vulnerability detected in Go database query.',
                suggestion: 'Use prepared statements with placeholders.'
            },
            { 
                regex: /fmt\.Sprintf\s*\(\s*['"]\s*SELECT\s+.*?%[sdv]/gi,
                message: 'SQL injection vulnerability detected in Go fmt.Sprintf.',
                suggestion: 'Avoid fmt.Sprintf for SQL queries. Use prepared statements.'
            },
            { 
                regex: /ioutil\.ReadFile\s*\(\s*[^,)]*\+\s*/g,
                message: 'Path traversal vulnerability detected in Go file operation.',
                suggestion: 'Validate file paths and use filepath.Clean().'
            }
        ];

        for (const pattern of patterns) {
            let match;
            pattern.regex.lastIndex = 0;
            
            while ((match = pattern.regex.exec(line)) !== null) {
                vulnerabilities.push({
                    type: 'go-vulnerability',
                    message: pattern.message,
                    line: lineIndex + 1,
                    column: match.index,
                    severity: 'error',
                    code: match[0],
                    suggestion: pattern.suggestion,
                    fixAction: {
                        title: 'Apply Go security fix',
                        replacement: this.getGoFix(match[0])
                    }
                });
            }
        }

        return vulnerabilities;
    }

    private getGoFix(code: string): string {
        if (code.includes('exec.Command')) {
            return 'exec.Command("command", arg1, arg2) // Use separate arguments';
        } else if (code.includes('db.Query')) {
            return 'db.Query("SELECT * FROM table WHERE id = ?", userID)';
        } else if (code.includes('fmt.Sprintf')) {
            return 'db.Query("SELECT * FROM table WHERE id = ?", userID)';
        } else if (code.includes('ioutil.ReadFile')) {
            return 'ioutil.ReadFile(filepath.Clean(safePath))';
        }
        return 'Apply secure Go practices';
    }

    // Dart-specific vulnerability checks
    private checkDartVulnerabilities(line: string, lineIndex: number): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];

        // Dart-specific patterns
        const dartPatterns = [
            // Debug info leaks in Flutter
            /debugPrint\s*\(\s*[^)]*(?:password|token|key|secret|api)/gi,
            /print\s*\(\s*[^)]*(?:password|token|key|secret|api)/gi,
            
            // Insecure HTTP in Flutter/Dart
            /http:\/\/[^"'\s]+/g,
            /Uri\.parse\s*\(\s*['"]\s*http:/gi,
            
            // Hardcoded API keys (Dart style)
            /const\s+String\s+\w*(?:api|key|secret|token)\w*\s*=\s*['"]/gi,
            /final\s+String\s+\w*(?:api|key|secret|token)\w*\s*=\s*['"]/gi,
            
            // Firebase config exposure
            /apiKey\s*:\s*['"]/gi,
            /databaseURL\s*:\s*['"]/gi,
            /messagingSenderId\s*:\s*['"]/gi,
            
            // Unsafe file operations
            /File\s*\(\s*[^)]*\+/g, // File path concatenation
            /Directory\s*\(\s*[^)]*\+/g, // Directory path concatenation
        ];

        dartPatterns.forEach((pattern, index) => {
            let match;
            while ((match = pattern.exec(line)) !== null) {
                vulnerabilities.push({
                    type: this.getDartVulnerabilityType(index),
                    message: this.getDartVulnerabilityMessage(index),
                    line: lineIndex + 1,
                    column: match.index + 1,
                    severity: this.getDartVulnerabilitySeverity(index),
                    code: match[0],
                    suggestion: this.getDartFix(match[0], index),
                    fixAction: {
                        title: `Fix ${this.getDartVulnerabilityType(index)}`,
                        replacement: this.getDartFix(match[0], index)
                    }
                });
            }
        });

        return vulnerabilities;
    }

    private getDartVulnerabilityType(patternIndex: number): 'unsafe-eval' | 'ssrf' | 'api-key' | 'path-traversal' {
        const types: ('unsafe-eval' | 'ssrf' | 'api-key' | 'path-traversal')[] = [
            'unsafe-eval', 'unsafe-eval', // Debug prints
            'ssrf', 'ssrf', // HTTP issues
            'api-key', 'api-key', // Hardcoded secrets
            'api-key', 'api-key', 'api-key', // Firebase config
            'path-traversal', 'path-traversal' // File operations
        ];
        return types[patternIndex] || 'unsafe-eval';
    }

    private getDartVulnerabilityMessage(patternIndex: number): string {
        const messages = [
            'Debug information leak: Sensitive data in debugPrint()',
            'Debug information leak: Sensitive data in print()',
            'Insecure HTTP: Use HTTPS for production',
            'Insecure HTTP: Use HTTPS in Uri.parse()',
            'Hardcoded API key: Store in environment variables',
            'Hardcoded secret: Use secure configuration',
            'Firebase API key exposed: Use environment config',
            'Database URL exposed: Use secure configuration', 
            'Messaging sender ID exposed: Use environment config',
            'Path traversal: Unsafe file path construction',
            'Path traversal: Unsafe directory path construction'
        ];
        return messages[patternIndex] || 'Dart security issue detected';
    }

    private getDartVulnerabilitySeverity(patternIndex: number): 'error' | 'warning' | 'info' {
        // Debug leaks: warning, HTTP: error, API keys: error, Path traversal: warning
        return [2, 2, 0, 0, 0, 0, 0, 0, 0, 2, 2][patternIndex] === 0 ? 'error' : 
               [2, 2, 0, 0, 0, 0, 0, 0, 0, 2, 2][patternIndex] === 2 ? 'warning' : 'error';
    }

    private getDartFix(code: string, patternIndex: number): string {
        const fixes = [
            'Use kDebugMode check: if (kDebugMode) debugPrint("Safe info only")',
            'Use kDebugMode check: if (kDebugMode) print("Safe info only")', 
            'Use HTTPS: https://api.example.com',
            'Use HTTPS: Uri.parse("https://api.example.com")',
            'Store in environment: const apiKey = String.fromEnvironment("API_KEY")',
            'Use secure config: Load from secure storage',
            'Environment config: String.fromEnvironment("FIREBASE_API_KEY")',
            'Environment config: String.fromEnvironment("DATABASE_URL")',
            'Environment config: String.fromEnvironment("MESSAGING_SENDER_ID")',
            'Use path.join() or validate input path',
            'Use path.join() or validate input directory'
        ];
        return fixes[patternIndex] || 'Apply Dart security best practices';
    }
}