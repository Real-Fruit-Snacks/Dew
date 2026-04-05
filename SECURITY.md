# Security Policy

## Supported Versions

Only the latest release of Dew is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Dew, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Dew/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Dew is a penetration testing tool designed for authorized security assessments. The following behaviors are **features, not bugs**:

- Reverse shell functionality over encrypted HTTPS
- XChaCha20-Poly1305 authenticated encryption of command payloads
- Jittered callback intervals to avoid detection
- WinHTTP-based TLS transport with self-signed certificate support
- Pre-shared key authentication
- Piped command execution via CreateProcess

These capabilities exist by design for legitimate security testing. Reports that simply describe Dew working as intended will be closed.

## Responsible Use

Dew is intended for authorized penetration testing, security research, and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
