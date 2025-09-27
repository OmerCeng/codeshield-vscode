# Contributing to CodeShield

We welcome contributions to CodeShield! This document provides guidelines for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use issue templates** when available
3. **Provide detailed information**:
   - VS Code version
   - CodeShield version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior

### Suggesting Features

1. **Open an issue** with the "feature request" label
2. **Describe the use case** clearly
3. **Explain the benefit** to users
4. **Provide examples** if applicable

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Commit your changes** (`git commit -m 'Add amazing feature'`)
7. **Push to the branch** (`git push origin feature/amazing-feature`)
8. **Open a Pull Request**

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/codeshield.git
   cd codeshield
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Compile TypeScript**
   ```bash
   npm run compile
   ```

4. **Run in VS Code**
   - Press `F5` to launch extension development host
   - Test your changes in the new VS Code window

## Project Structure

```
src/
├── extension.ts              # Main extension entry point
├── scanner/
│   └── securityScanner.ts    # Core vulnerability detection
├── providers/
│   ├── diagnosticProvider.ts # VS Code diagnostics integration
│   ├── codeActionProvider.ts # Quick fix suggestions
│   ├── codeLensProvider.ts   # CodeLens integration
│   └── decorationProvider.ts # Visual decorations
├── utils/
│   ├── vulnerabilityExplainer.ts # Detailed explanations
│   └── ignoreManager.ts      # Ignore functionality
└── types/
    └── vulnerability.ts      # Type definitions
```

## Adding New Vulnerability Types

1. **Add pattern** to `securityScanner.ts`
2. **Add explanation** to `vulnerabilityExplainer.ts`
3. **Add quick fix** to `codeActionProvider.ts`
4. **Add tests** for the new vulnerability type
5. **Update documentation**

## Testing

```bash
# Run linting
npm run lint

# Compile TypeScript
npm run compile

# Run tests (when available)
npm test
```

## Coding Standards

- **TypeScript**: Use strict typing
- **ESLint**: Follow configured rules
- **Comments**: Document complex logic
- **Naming**: Use descriptive variable and function names
- **Security**: Follow secure coding practices

## Questions?

Feel free to open an issue for any questions about contributing!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.