# Changelog

All notable changes to the CodeShield extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.11]

### Added
- **Interactive Vulnerability Dashboard**: Beautiful side-panel view for all critical security issues
  - Automatically shows on file save when critical vulnerabilities are detected
  - Click "View All" in notification to open interactive dashboard
  - Lists all critical issues with line numbers, types, and code snippets
  - Click any vulnerability to instantly navigate to its location in code
  - Clean, professional UI with color-coded severity indicators

- **Smart Code Snippet Analyzer**: Analyze selected code without opening new windows
  - Right-click on selected code → "Analyze Selected Code for Security Issues"
  - Scans only the selected portion of your file
  - Shows results inline without disrupting your workflow
  - Perfect for quick security checks during code reviews
  - "View Details" button navigates directly to first vulnerability

- **Auto-Notification for Critical Issues**: Automatic alerts for high-risk vulnerabilities
  - Pop-up notifications appear automatically when saving files with critical issues
  - Shows count and brief summary of detected vulnerabilities
  - "View All" opens detailed interactive dashboard
  - "Dismiss" closes notification without interrupting work
  - Only alerts for severity: 'error' level issues (reduces notification noise)

### Enhanced
- **Massively Expanded Security Patterns**: All vulnerability detectors significantly improved
  - **Java**: Added 15+ new patterns for SSRF, reflection abuse, XXE, LDAP injection
  - **C#**: Added 20+ patterns for LDAP, XXE, SSRF, improved deserialization detection
  - **C++**: Added 12+ patterns for integer overflow, race conditions, TOCTOU vulnerabilities
  - **PHP**: Added 15+ patterns for file upload, open redirect, XXE, improved injection detection
  - **Python**: Added subprocess shell injection, builtins manipulation, unvalidated input detection
  - **Go**: Complete pattern set for SQL injection, command injection, path traversal, SSRF, unsafe reflection
  - **ReDoS**: Added 6 new dangerous regex patterns including backreference alternation
  - All patterns now include more method variations and library-specific functions

### Improved
- Better detection of vulnerability variations across different coding styles
- Enhanced notification system with actionable buttons (Fix Now, Ignore, Details)
- Improved user experience with context-aware features

## [0.0.10]

### Enhanced
- **Massively Improved Pattern Detection**: All security vulnerability patterns now catch significantly more naming variations
  - API Key Detection: Now catches `apikey`, `api`, `api_key`, `apiKey`, `token`, `authtoken` and all camelCase/snake_case variations
  - Password Detection: Now catches `password`, `passwd`, `pwd`, `pass`, `dbpassword`, `database_pwd` and all variations
  - SQL Injection: Enhanced to detect `query`, `sql`, `cmd`, `command`, `exec`, `execute`, `run` method variations across all database libraries
  - Command Execution: Expanded to detect `eval`, `exec`, `execSync`, `spawn`, `system`, `shell_exec`, `Runtime.exec`, `Process.Start` across all languages
  - Path Traversal: Now detects all file operations including `readFile`, `writeFile`, `File`, `open`, `include`, `require` variations
  - XSS Detection: Enhanced DOM manipulation detection for `innerHTML`, `append`, `prepend`, `v-html`, `ng-bind-html`, `dangerouslySetInnerHTML`
  - SSRF Detection: Now catches all HTTP libraries including `fetch`, `axios`, `requests`, `urllib`, `httpx`, `HttpClient`, `WebClient`
  - NoSQL Injection: Expanded MongoDB, Redis, and Elasticsearch operation detection
  - Prototype Pollution: Enhanced `Object.assign`, `merge`, `extend`, `__proto__` access detection

### Improved
- **Reduced False Negatives**: Pattern flexibility means fewer security vulnerabilities will be missed
- **Better Language Coverage**: Each pattern now includes variations from multiple languages (JavaScript, Python, Java, C#, PHP, Go)
- **Smarter Variable Name Detection**: Word boundary detection (`\b`) ensures accurate matching without over-triggering
- **Case-Insensitive Matching**: Most patterns now use `/gi` flags for better coverage

### Technical
- All 9 major vulnerability pattern categories updated with 2-3x more detection patterns
- Added support for alternative method names (e.g., `executeQuery`, `executeUpdate`, `execute`)
- Enhanced regex patterns to catch library-specific variations (e.g., Lodash, jQuery, Express)
- Improved detection of dangerous property access (`__proto__`, `constructor`, `prototype`)

## [0.0.9] 

### Added
- **Dart/Flutter Language Support**: Comprehensive security vulnerability detection for Flutter applications
  - Debug information leak detection in `debugPrint()` and `print()` statements
  - Insecure HTTP detection for production Flutter apps
  - Hardcoded API key detection (`const String`, `final String` patterns)
  - Firebase configuration exposure detection (apiKey, databaseURL, messagingSenderId)
  - Path traversal detection in `File()` and `Directory()` operations
  - Flutter-specific security patterns and fix suggestions
- Dart code examples and security best practices in documentation
- Enhanced multi-language support (now 8 languages total)

### Changed
- Updated supported languages count from 7 to 8
- Enhanced README documentation with Dart/Flutter security examples
- Improved vulnerability type system to include Dart-specific patterns
- Updated file scanning to include `.dart` files in workspace scans

### Security
- Added Flutter production security checks
- Enhanced mobile app security vulnerability detection
- Improved API key exposure detection for mobile application

## [0.0.3] 

### Added
- **Go Language Support**: Complete security vulnerability detection for Go applications
  - SQL injection detection in `db.Query()` and `fmt.Sprintf()`
  - Command injection detection in `exec.Command()`
  - Path traversal detection in `ioutil.ReadFile()` and `os.Open()`
  - Go-specific quick fixes and security suggestions
- Go code examples in documentation
- Enhanced multi-language support (now 7 languages total)

### Changed
- Updated supported languages count from 6 to 7
- Enhanced README documentation with Go security examples
- Improved vulnerability type system to include Go-specific patterns
- Updated vulnerability explainer with Go security best practices

### Fixed
- Screenshot paths in README for better GitHub display
- Documentation consistency across all supported languages
- Vulnerability detection accuracy improvements

## [0.0.2] 

### Added
- Enhanced security detection patterns
- Improved SQL injection detection across all languages
- Better command injection pattern recognition
- Extended API key pattern matching

### Changed
- Refined vulnerability messages and suggestions
- Enhanced quick fix accuracy
- Improved documentation structure

## [0.0.1] 

### Added
- Initial release of CodeShield
- Security vulnerability detection for 6 programming languages (JavaScript, TypeScript, Python, Java, C#, C++, PHP, SQL)
- 15+ vulnerability types detection:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Path Traversal
  - API Key Exposure
  - Unsafe Deserialization
  - Buffer Overflow (C++)
  - And more...
- Smart code fixes with one-click suggestions
- Real-time vulnerability scanning
- Ignore functionality for false positives
- Minimalist UI with wavy underlines and CodeLens
- Detailed vulnerability explanations
- Command Palette integration
- Context menu integration
- Multi-language support with language-specific patterns

### Features
- **Real-time Detection**: Automatic scanning on file open and save
- **Quick Fixes**: One-click security improvements via VS Code Quick Fix (💡)
- **Ignore System**: Ability to ignore specific vulnerabilities with ❌ Ignore button  
- **Smart UI**: Minimalist wavy underlines, colored overview rulers, CodeLens integration
- **Multi-language**: Comprehensive support for 6+ programming languages
- **Extensible**: Modular architecture for easy expansion

### Security
- 0 vulnerabilities found in dependencies (npm audit)
- Secure coding practices implemented
- No hardcoded secrets or sensitive data
- Safe file operations and input validation