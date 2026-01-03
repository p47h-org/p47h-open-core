# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.10.x  | :white_check_mark: |
| < 0.10  | :x:                |

## Reporting a Vulnerability

The P47H team takes security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email us at: **security@p47h.com**

Include the following information:

- Type of vulnerability (e.g., buffer overflow, SQL injection, XSS, etc.)
- Location of the affected source code (file path, line numbers)
- Step-by-step instructions to reproduce
- Proof of concept or exploit code (if available)
- Potential impact of the vulnerability

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability within 7 days
- **Remediation**: Critical vulnerabilities will be patched within 30 days
- **Credit**: We will credit reporters in our security advisories (unless you prefer anonymity)

### Scope

The following are in scope:

- `p47h-open-core` crates
- Cryptographic implementations
- Key derivation functions
- Storage encryption

The following are out of scope:

- Third-party dependencies (please report to the respective maintainers)
- Social engineering attacks
- Physical security issues

## Security Best Practices

When using P47H Open Core:

1. **Never hardcode secrets** - Always use environment variables for sensitive data
2. **Use strong passwords** - Argon2id is secure, but weak passwords are still weak
3. **Keep dependencies updated** - Run `cargo audit` regularly
4. **Validate inputs** - Sanitize all user inputs before cryptographic operations

---

Thank you for helping keep P47H and our users safe!
