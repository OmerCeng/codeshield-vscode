# CodeShield 🛡️

Automatically detect security vulnerabilities in your code with intelligent fix suggestions and real-time protection.

## Features

CodeShield provides comprehensive security analysis for multiple programming languages with real-time vulnerability detection, smart fix suggestions, and an unobtrusive developer experience.

### 🔍 **Security Vulnerability Detection**
- **SQL Injection** - Detects unsafe database queries, string concatenation, template literals, f-strings
- **Cross-Site Scripting (XSS)** - Identifies script injection via innerHTML, document.write, jQuery, Angular, Vue
- **Command Injection** - Finds OS command execution risks including eval, exec, execSync, spawn
- **Path Traversal** - Catches directory traversal attacks in file operations
- **API Key Exposure** - Locates hardcoded secrets, tokens, and service credentials in code and comments
- **Unsafe Deserialization** - Spots object injection risks (pickle, Marshal, ObjectInputStream, BinaryFormatter)
- **Buffer Overflow** - Identifies memory boundary violations (C/C++)
- **SSRF** - Server-Side Request Forgery via HTTP client calls with user-controlled URLs
- **NoSQL Injection** - MongoDB, Redis, Elasticsearch query injection
- **Prototype Pollution** - JavaScript object prototype manipulation
- **ReDoS** - Regular Expression Denial of Service patterns
- **And more...**

### 🛠️ **Smart Developer Tools**

#### 📊 Status Bar
Real-time vulnerability counter always visible in the status bar:
- Shows `$(shield) CodeShield: 2 critical | 5 warnings` at a glance
- Red background for critical issues, yellow for warnings
- Click to open the Problems panel

#### 💬 "Why is this dangerous?" Hover Tooltips
Hover over any flagged line to see:
- **CWE/OWASP reference** for the vulnerability type
- **Real attack scenario** explaining how it gets exploited
- **Impact** description of what an attacker can achieve
- **Quick fix hint** pointing to the safe alternative

#### ✨ Secure Code Autocomplete
When you start typing a dangerous pattern, CodeShield suggests the safe version:
- `cursor.execute(` → parameterized query snippet
- `innerHTML` → `textContent` alternative
- `yaml.load(` → `yaml.safe_load` reminder
- `subprocess.run(` → safe argument array form
- And 10+ more secure snippets

#### 🔐 Secret Detection in Comments
Catches credentials left in `//`, `#`, and `/* */` comments:
- API keys, tokens, passwords in TODO/FIXME comments
- OpenAI `sk-`, AWS `AKIA`, GitHub `ghp_` tokens
- Alerts you to rotate the credential immediately

#### 🚫 Ignore System
Manage false positives without losing visibility:
- **Ignore individual issues** — click `$(eye-closed) Ignore` on any CodeLens
- **Ignore All in File** — one click to suppress all issues in the current file
- Ignored items remain visible as `[Ignored]` hints in the Problems panel
- Ignore state persists across sessions per workspace

### 🌐 **Multi-Language Support**
12 programming languages with language-specific vulnerability patterns:

| Language | Vulnerabilities Detected |
|----------|--------------------------|
| **JavaScript/TypeScript** | SQL Injection, XSS, Command Injection, Path Traversal, API Keys, SSRF, Prototype Pollution, ReDoS |
| **Python** | SQL Injection, Command Injection, Path Traversal, Pickle Deserialization, Template Injection, Unsafe Imports |
| **Java** | SQL Injection, Command Injection, Path Traversal, Unsafe Deserialization, LDAP Injection, XXE |
| **C#** | SQL Injection, XSS, Command Injection, Path Traversal, Unsafe Deserialization, LDAP, XXE |
| **C/C++** | Buffer Overflow, Format String, Memory Issues, Command Injection, SQL Injection |
| **PHP** | SQL Injection, XSS, Command Injection, File Inclusion, Path Traversal, Unsafe Deserialization |
| **Go** | SQL Injection, Command Injection, Path Traversal, SSRF, Unsafe Reflection |
| **Ruby** | SQL Injection (ActiveRecord), Command Injection, eval, Marshal.load, YAML.load, Path Traversal, SSRF |
| **Kotlin** | SQLite rawQuery, WebView JS, Runtime.exec, Sensitive Logging, Hardcoded Secrets, Plain HTTP |
| **Dart/Flutter** | Debug Info Leaks, Insecure HTTP, Hardcoded API Keys, Firebase Config Exposure |
| **SQL** | Inline query construction |

## Getting Started

### Installation
1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X` / `Cmd+Shift+X`)
3. Search for **"CodeShield"**
4. Click Install

### Usage
1. **Open any supported file** — CodeShield activates automatically
2. **View issues** — Vulnerabilities appear as colored wavy underlines in the editor
3. **Hover for details** — See the attack scenario and CWE reference on hover
4. **Check the status bar** — Vulnerability count shown at the bottom of the screen
5. **Click CodeLens** — Use `$(clippy) Copy Safe Example` to copy the secure alternative
6. **Ignore false positives** — Click `$(eye-closed) Ignore` or **Ignore All in This File**
7. **Manual scan** — Command Palette (`Ctrl+Shift+P`) → `CodeShield: Scan Current File`

## Examples

### SQL Injection Detection
```javascript
// ❌ Vulnerable — string concatenation
const query = "SELECT * FROM users WHERE id = " + userId;

// ❌ Vulnerable — template literal
const q = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ Secure — parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

### API Key Exposure
```javascript
// ❌ Vulnerable — hardcoded in source
const apiKey = "sk-proj-abc123xyz456realkey";

// ✅ Secure — environment variable
const apiKey = process.env.OPENAI_API_KEY;
```

### Command Injection
```javascript
// ❌ Vulnerable — string concatenation in exec
execSync("rm -rf " + filePath);

// ✅ Secure — argument array
execSync("rm", ["-rf", sanitizedPath]);
```

### Secret in Comment
```javascript
// TODO: remove this — api_key = "sk-abc123realkey"   ❌ CodeShield flags this
```

### Ruby SQL Injection
```ruby
# ❌ Vulnerable — ActiveRecord string interpolation
users = User.where("name = '#{params[:name]}'")

# ✅ Secure — parameterized
users = User.where("name = ?", params[:name])
```

### Kotlin Hardcoded Secret
```kotlin
// ❌ Vulnerable — visible after APK decompile
val apiKey = "sk-abc123xyz456789realkey"

// ✅ Secure — from BuildConfig / environment
val apiKey = BuildConfig.API_KEY
```

## Extension Commands

| Command | Description |
|---------|-------------|
| `CodeShield: Scan Current File` | Manually scan the active file |
| `CodeShield: Scan Workspace` | Scan all supported files in the workspace |
| `CodeShield: Analyze Selected Code` | Scan only the highlighted code block |
| `CodeShield: Ignore Security Vulnerability` | Ignore a specific vulnerability |
| `CodeShield: Ignore All Issues in Current File` | Suppress all issues in the file |
| `CodeShield: Copy Safe Code Example` | Copy the secure alternative to clipboard |

## Configuration

CodeShield works out of the box with no configuration required.

### Optional Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codeshield.enableSqlInjectionDetection` | `true` | Enable SQL injection detection |
| `codeshield.enableApiKeyDetection` | `true` | Enable API key / secret detection |
| `codeshield.notifications.showPopup` | `true` | Show popup on file save |
| `codeshield.notifications.minSeverity` | `warning` | Minimum severity for notifications |

## Supported File Extensions

`.js` `.jsx` `.ts` `.tsx` `.py` `.java` `.cs` `.cpp` `.c` `.h` `.php` `.go` `.rb` `.kt` `.dart` `.sql`

## Requirements

- Visual Studio Code 1.74.0 or higher
- No additional software or dependencies required

## Known Issues

None at this time. If you encounter any issues, please [report them on GitHub](https://github.com/OmerCeng/codeshield-vscode/issues).

## License

MIT License

---

**Secure your code with CodeShield** 🛡️
