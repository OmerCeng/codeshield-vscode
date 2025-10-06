# Changelog

All notable changes to the CodeShield extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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