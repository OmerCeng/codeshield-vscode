# CodeShield 🛡️

Automatically detect security vulnerabilities in your code with intelligent fix suggestions.

## Features

CodeShield provides comprehensive security analysis for multiple programming languages with real-time vulnerability detection and automated fix suggestions.

### 🔍 **Security Vulnerability Detection**
- **SQL Injection** - Detects unsafe database queries and string concatenation
- **Cross-Site Scripting (XSS)** - Identifies script injection vulnerabilities  
- **Command Injection** - Finds OS command execution risks
- **Path Traversal** - Catches directory traversal attacks
- **API Key Exposure** - Locates hardcoded secrets and tokens
- **Unsafe Deserialization** - Spots object injection risks
- **Buffer Overflow** - Identifies memory boundary violations (C++)
- **And 8+ more vulnerability types**

### 🛠️ **Smart Code Fixes**
- One-click security improvements via VS Code's Quick Fix (💡)
- Parameterized query suggestions for SQL injection
- Environment variable recommendations for secrets
- Safe alternative function suggestions
- Detailed explanations for each vulnerability type
- Ignore functionality for false positives (❌ Ignore button)

### 🌐 **Multi-Language Support**
Supports 8 programming languages with language-specific vulnerability patterns

| Language | Vulnerabilities Detected |
|----------|---------------------------|
| **JavaScript/TypeScript** | SQL Injection, XSS, Command Injection, Path Traversal, API Keys, SSRF, Prototype Pollution, ReDoS |
| **Python** | SQL Injection, Command Injection, Path Traversal, Pickle Deserialization, Template Injection, Unsafe Imports |
| **Java** | SQL Injection, Command Injection, Path Traversal, Unsafe Deserialization, LDAP Injection, XXE |
| **C#** | SQL Injection, XSS, Command Injection, Path Traversal, Unsafe Deserialization |
| **C++** | Buffer Overflow, Format String, Memory Issues, Command Injection, SQL Injection |
| **PHP** | SQL Injection, XSS, Command Injection, File Inclusion, Path Traversal, Unsafe Deserialization |
| **Go** | SQL Injection, Command Injection, Path Traversal, API Key Exposure, Memory Safety |
| **Dart/Flutter** | Debug Info Leaks, Insecure HTTP, Hardcoded API Keys, Path Traversal, Firebase Config Exposure |

## Getting Started

### Installation
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "CodeShield"
4. Click Install

### Usage
1. **Open any supported code file** - CodeShield activates automatically
2. **View security issues** - Vulnerabilities appear as colored wavy underlines
3. **Get details** - Hover over highlighted code for explanations
4. **Apply fixes** - Click the 💡 light bulb for quick fixes
5. **Ignore warnings** - Use ❌ Ignore button to hide specific vulnerabilities
6. **Manual scan** - Use Command Palette (Ctrl+Shift+P) → "CodeShield: Scan Current File for Security Issues"

## Examples

### SQL Injection Detection
```javascript
// ❌ Vulnerable - String concatenation in SQL query
query = "SELECT * FROM users WHERE id = " + userId;

// ✅ Secure - Use parameterized queries
const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
const result = stmt.get(userId);
```

### XSS Prevention
```javascript
// ❌ Vulnerable - DOM innerHTML with user input
element.innerHTML = userContent + "<div>";

// ✅ Secure - Use textContent or sanitize
element.textContent = userContent;
```

### API Key Security
```javascript
// ❌ Vulnerable - Hardcoded OpenAI API key
const apiKey = "sk-1234567890abcdefghijklmnop";

// ✅ Secure - Environment variable
const apiKey = process.env.OPENAI_API_KEY;
```

### Path Traversal Prevention
```javascript
// ❌ Vulnerable - File path concatenation
fs.readFile(basePath + userInput, callback);

// ✅ Secure - Path validation and sanitization
const safePath = path.join(basePath, path.basename(userInput));
fs.readFile(safePath, callback);
```

### Unsafe Eval Detection
```javascript
// ❌ Vulnerable - Dynamic code execution
eval("var result = " + userInput);

// ✅ Secure - Use JSON.parse for data
const result = JSON.parse(userInput);
```

## Extension Commands

You can access these commands via Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

| Command | Description |
|---------|-------------|
| `CodeShield: Scan Current File for Security Issues` | Manually scan the active file for vulnerabilities |
| `CodeShield: Scan Workspace for Security Issues` | Scan all files in the current workspace |
| `CodeShield: Explain Security Vulnerability` | Open detailed explanation for selected vulnerability |
| `CodeShield: Ignore Security Vulnerability` | Add vulnerability to ignore list |

## Configuration

CodeShield works out of the box with no configuration required. All scanning happens automatically when you open supported file types.

## Requirements

- Visual Studio Code version 1.74.0 or higher
- No additional software or dependencies required

## Supported File Extensions

CodeShield automatically activates for these file types:
- `.js`, `.jsx` (JavaScript)
- `.ts`, `.tsx` (TypeScript) 
- `.py` (Python)
- `.java` (Java)
- `.cs` (C#)
- `.cpp`, `.c`, `.h` (C/C++)
- `.php` (PHP)
- `.go` (Go)
- `.dart` (Dart/Flutter)
- `.sql` (SQL files)

## Known Issues

None at this time. If you encounter any issues, please report them on GitHub.

## Contributing

We welcome contributions! Please submit issues and pull requests on GitHub.

## License

This extension is licensed under the MIT License.

---

**Secure your code with CodeShield** 🛡️

