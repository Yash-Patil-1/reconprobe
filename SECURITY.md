# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active development |
| < 1.0   | ❌ No longer supported |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in ReconProbe, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email**: Send details to [yashpatil7714@gmail.com](mailto:yashpatil7714@gmail.com)
2. **Encryption**: If possible, use PGP encryption (key available on request)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Any suggested fix (if known)

### What to Expect

- **Acknowledgment**: Within 48 hours of reporting
- **Validation**: We'll confirm the vulnerability and assess its impact
- **Fix timeline**: Critical issues targeted within 7 days; moderate issues within 30 days
- **Disclosure**: We'll coordinate a public disclosure date once the fix is released

### Scope

ReconProbe is a **penetration testing tool** designed for authorized security assessments. Vulnerabilities include:

- Remote code execution in scan results processing
- Credential leakage in logs or outputs
- SSRF or unintended data exposure via scan modules
- Dependency vulnerabilities with CVSS 7.0+

### Hall of Fame

With your permission, we'll credit you in our release notes for responsible disclosures.

---

_Last updated: May 2026_
