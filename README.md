# CodeShield 🛡️

A VS Code extension that detects security vulnerabilities in real time across 12 programming languages, with hover explanations, secure code autocomplete, and a persistent ignore system.

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://marketplace.visualstudio.com/items?itemName=vscodecodeshield.vs-codeshield)
[![VS Code](https://img.shields.io/badge/VS%20Code-1.74%2B-blue.svg)](https://code.visualstudio.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## What's New in v0.1.0

- **Status Bar** — live vulnerability counter at the bottom of the screen
- **Hover Tooltips** — hover any flagged line for attack scenario, CWE reference, and fix hint
- **Secure Autocomplete** — type a dangerous pattern and get the safe version suggested
- **Comment Secret Scanning** — catches credentials left inside `//` / `#` / `/* */` comments
- **Ignore All in File** — suppress all issues in one click; they remain visible as hints
- **Ruby support** — ActiveRecord injection, Marshal.load, YAML.load, SSRF, eval, hardcoded secrets
- **Kotlin/Android support** — rawQuery, WebView JS, Runtime.exec, sensitive logcat, plain HTTP
- **Pattern improvements** — template literal SQL, execSync concat, GitLab/Slack tokens, case-insensitive API key matching

## Features

### 🔍 Vulnerability Detection

| Category | What's detected |
|----------|----------------|
| SQL Injection | String concat, template literals, f-strings, `.format()`, raw queries |
| XSS | innerHTML, document.write, jQuery `.html()`, dangerouslySetInnerHTML, Vue `v-html`, Angular `[innerHTML]` |
| Command Injection | eval, exec, execSync, spawn, Runtime.exec, Process.Start, shell_exec |
| Path Traversal | fs operations, File(), open(), include/require, direct user input |
| API Keys & Secrets | OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google OAuth, JWT, PEM keys |
| Secrets in Comments | Keys/tokens left in TODO/FIXME/remove-me comments |
| Unsafe Deserialization | pickle, Marshal.load, YAML.load, ObjectInputStream, BinaryFormatter |
| SSRF | fetch, axios, requests, urllib, HttpClient, http.Get with user-controlled URLs |
| NoSQL Injection | MongoDB find/update/delete, $where, Elasticsearch, Redis |
| Prototype Pollution | Object.assign, _.merge, $.extend, `__proto__` access |
| Buffer Overflow | strcpy, sprintf, gets, scanf (C/C++) |
| ReDoS | Nested quantifiers, catastrophic backtracking patterns |

### 🛠️ Developer Tools

**Status Bar** — `$(shield) CodeShield: 2 critical | 5 warnings` always visible; click to open Problems panel.

**Hover Tooltips** — Hover over flagged code to see the CWE reference, a real-world attack scenario, and a fix suggestion — without leaving the editor.

**Secure Autocomplete** — Suggestions for safe alternatives appear when you type dangerous patterns (`cursor.execute(`, `innerHTML`, `yaml.load(`, etc.).

**Ignore System** — Ignore individual issues or all issues in a file. Ignored items remain visible as `[Ignored]` in the Problems panel, so nothing is silently hidden.

### 🌐 Language Support

12 languages: **JavaScript · TypeScript · Python · Java · C# · C/C++ · PHP · Go · Ruby · Kotlin · Dart/Flutter · SQL**

Each language has dedicated vulnerability patterns beyond the generic cross-language rules.

## Quick Start

```
Extensions → Search "CodeShield" → Install
```

Open any supported file — scanning starts automatically. Issues appear as wavy underlines; hover for details.

## Usage

```
1. Open a file                      → auto-scan runs
2. Hover flagged code               → see attack scenario + fix hint
3. Click $(clippy) CodeLens         → copy safe code example to clipboard
4. Click $(eye-closed) Ignore       → hide a specific issue
5. Click "Ignore All in This File"  → suppress all issues (shown as hints)
6. Check status bar                 → quick count of active issues
```

## Examples

### SQL Injection
```javascript
// ❌ Vulnerable
const q = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ Safe
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

### Hardcoded API Key
```javascript
// ❌ Vulnerable
const key = "sk-proj-abc123xyz456realkey";

// ✅ Safe
const key = process.env.OPENAI_API_KEY;
```

### Secret in Comment
```python
# TODO: remove — api_key = "AKIA1234567890EXAMPLE"   ← CodeShield flags this
```

### Ruby (ActiveRecord)
```ruby
# ❌ Vulnerable
users = User.where("name = '#{params[:name]}'")

# ✅ Safe
users = User.where("name = ?", params[:name])
```

### Kotlin (Android)
```kotlin
// ❌ Vulnerable
val cursor = db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)

// ✅ Safe
val cursor = db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
```

## Commands

| Command | Shortcut |
|---------|----------|
| Scan Current File | Command Palette → `CodeShield: Scan Current File` |
| Scan Workspace | Command Palette → `CodeShield: Scan Workspace` |
| Analyze Selection | Right-click → `Analyze Selected Code` |
| Ignore All in File | Command Palette → `CodeShield: Ignore All Issues in Current File` |

## Configuration

Works out of the box. Optional settings under `codeshield.*` in VS Code settings:

| Key | Default | Description |
|-----|---------|-------------|
| `enableSqlInjectionDetection` | `true` | SQL injection scanning |
| `enableApiKeyDetection` | `true` | Secret/token scanning |
| `notifications.showPopup` | `true` | Popup on file save |
| `notifications.minSeverity` | `warning` | Minimum notification severity |

## Contributing

Issues and PRs welcome on [GitHub](https://github.com/OmerCeng/codeshield-vscode).

## License

MIT
