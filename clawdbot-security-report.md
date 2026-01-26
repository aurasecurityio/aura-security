# SECURITY AUDIT REPORT

**Target Repository:** https://github.com/clawdbot/clawdbot
**Audit Date:** January 25, 2026
**Auditor:** AuraSecurity Automated Scanner + Manual Review
**Classification:** Public Disclosure

---

## EXECUTIVE SUMMARY

A comprehensive security audit was conducted on the clawdbot repository. The audit identified multiple vulnerabilities across dependency packages, including one critical severity issue and over 15 high severity issues. These vulnerabilities could potentially be exploited for authentication bypass, denial of service attacks, cross-site scripting, and request smuggling.

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 1 | Unpatched |
| High | 15+ | Unpatched |
| Medium | 6+ | Unpatched |
| Secrets Flagged | 50+ | Requires Review |

---

## CRITICAL VULNERABILITIES

### CVE-2025-7783 - Unsafe Random Function in form-data

**Severity:** CRITICAL
**Package:** form-data
**Installed Version:** 2.3.3
**Fixed Version:** 2.5.4, 3.0.4, or 4.0.4
**Location:** pnpm-lock.yaml

**Description:**
The form-data package uses an unsafe random function for generating multipart form boundaries. This makes boundary values predictable, which could allow attackers to craft malicious requests that exploit boundary prediction.

**Potential Impact:**
- Request smuggling attacks
- Data injection in multipart form submissions
- Bypass of security controls that rely on boundary randomness

**Reference:** https://avd.aquasec.com/nvd/cve-2025-7783

---

## HIGH SEVERITY VULNERABILITIES

### CVE-2025-15284 - Denial of Service in qs

**Severity:** HIGH
**Package:** qs
**Installed Versions:** 6.5.3, 6.13.0, 6.14.0
**Fixed Version:** 6.14.1
**Location:** pnpm-lock.yaml, vendor packages

**Description:**
The qs package is vulnerable to denial of service via improper input validation in array parsing. A maliciously crafted query string can cause excessive resource consumption.

**Potential Impact:**
- Service unavailability
- Resource exhaustion
- Application crashes

**Reference:** https://avd.aquasec.com/nvd/cve-2025-15284

---

### CVE-2025-65945 - Improper Signature Verification in jws

**Severity:** HIGH
**Package:** jws (JSON Web Signature)
**Installed Versions:** 3.2.2, 4.0.0
**Fixed Version:** 3.2.3, 4.0.1
**Location:** vendor/a2ui/specification/*/eval/pnpm-lock.yaml

**Description:**
The node-jws package has improper signature verification in the HS256 algorithm. This vulnerability allows attackers to potentially forge JWT tokens that pass verification.

**Potential Impact:**
- Authentication bypass
- Privilege escalation
- Identity spoofing
- Unauthorized access to protected resources

**Reference:** https://avd.aquasec.com/nvd/cve-2025-65945

---

### CVE-2025-12816 - Cryptographic Verification Bypass in node-forge

**Severity:** HIGH
**Package:** node-forge
**Installed Version:** 1.3.1
**Fixed Version:** 1.3.2
**Location:** vendor/a2ui/specification/*/eval/pnpm-lock.yaml

**Description:**
An interpretation conflict vulnerability in node-forge allows bypassing cryptographic verifications. This affects applications relying on node-forge for cryptographic operations.

**Potential Impact:**
- Bypass of certificate validation
- Man-in-the-middle attacks
- Acceptance of invalid cryptographic signatures

**Reference:** https://avd.aquasec.com/nvd/cve-2025-12816

---

### CVE-2025-66031 - ASN.1 Unbounded Recursion in node-forge

**Severity:** HIGH
**Package:** node-forge
**Installed Version:** 1.3.1
**Fixed Version:** 1.3.2
**Location:** vendor/a2ui/specification/*/eval/pnpm-lock.yaml

**Description:**
The ASN.1 parser in node-forge is vulnerable to unbounded recursion, which can lead to stack overflow and denial of service when processing maliciously crafted ASN.1 data.

**Potential Impact:**
- Denial of service
- Application crashes
- Stack overflow exploitation

**Reference:** https://avd.aquasec.com/nvd/cve-2025-66031

---

### CVE-2026-22610 - Cross-Site Scripting in Angular Template Compiler

**Severity:** HIGH
**Package:** @angular/compiler, @angular/core
**Installed Version:** 21.0.3
**Fixed Version:** 21.1.0-rc.0, 21.0.7, 20.3.16, 19.2.18
**Location:** vendor/a2ui/renderers/angular/package-lock.json

**Description:**
A cross-site scripting vulnerability exists in the Angular Template Compiler. If user-controlled input reaches Angular templates without proper sanitization, attackers can inject malicious scripts.

**Potential Impact:**
- Session hijacking
- Credential theft
- Malware distribution
- Defacement of user interfaces

**Reference:** https://avd.aquasec.com/nvd/cve-2026-22610

---

## SECRETS ANALYSIS

The repository contains a `.secrets.baseline` file with 50+ flagged entries. Analysis indicates:

| Category | Count | Risk Level |
|----------|-------|------------|
| Test Fixtures | ~30 | Low (Intentional) |
| Documentation Examples | ~15 | Low (Placeholders) |
| Configuration Files | ~5 | Medium (Review Required) |

### Files Requiring Manual Review:

1. **apps/macos/Tests/ClawdbotIPCTests/**
   - AnthropicAuthResolverTests.swift (line 26, 42)
   - GatewayEndpointStoreTests.swift (line 61)
   - GatewayLaunchAgentManagerTests.swift (line 13)

2. **apps/shared/ClawdbotKit/Sources/ClawdbotKit/**
   - GatewayChannel.swift (line 100)

3. **.env.example**
   - Contains Twilio credential placeholders
   - Verify no real credentials are present

4. **appcast.xml**
   - High entropy base64 strings (lines 90, 138, 212)
   - Likely signing signatures but should be verified

---

## EXPLOITABILITY ASSESSMENT

### Can This Be Hacked?

**YES.** The following attack vectors are viable:

1. **JWT Authentication Bypass**
   - The jws vulnerability (CVE-2025-65945) allows forging JWT tokens
   - If the application uses JWTs for authentication, attackers could gain unauthorized access
   - Exploitation requires knowledge of the signing algorithm but not the secret key

2. **Denial of Service**
   - The qs vulnerability (CVE-2025-15284) can crash the service
   - Attack vector: Send malformed query strings to any endpoint parsing query parameters
   - Low skill required, high availability impact

3. **Cross-Site Scripting**
   - The Angular vulnerability (CVE-2026-22610) enables XSS attacks
   - Attack vector: Inject malicious input that reaches Angular templates
   - Can lead to session theft and account takeover

4. **Request Smuggling**
   - The form-data vulnerability (CVE-2025-7783) enables boundary prediction
   - Attack vector: Craft multipart requests with predicted boundaries
   - Can bypass security controls and inject malicious data

---

## VULNERABILITY DISTRIBUTION

```
Location                                          | Vulnerabilities
--------------------------------------------------|----------------
pnpm-lock.yaml                                    | 2 (1 CRIT, 1 HIGH)
vendor/a2ui/renderers/angular/package-lock.json   | 2 (2 HIGH)
vendor/a2ui/specification/0.8/eval/pnpm-lock.yaml | 6 (6 HIGH)
vendor/a2ui/specification/0.9/eval/pnpm-lock.yaml | 6 (6 HIGH)
--------------------------------------------------|----------------
TOTAL                                             | 16+ vulnerabilities
```

---

## TOOLS USED

| Tool | Version | Purpose |
|------|---------|---------|
| Trivy | Latest | Vulnerability scanning |
| Gitleaks | Latest | Secret detection |
| detect-secrets | 1.5.0 | Secret baseline analysis |
| Manual grep | - | Pattern analysis |
| AuraSecurity | 0.7.0 | Automated security audit |

---

## RECOMMENDATIONS

### Immediate Actions (Critical)

1. Update form-data package to version 2.5.4 or higher
2. Update jws package to version 3.2.3 or 4.0.1
3. Update node-forge package to version 1.3.2

### High Priority Actions

4. Update qs package to version 6.14.1
5. Update Angular packages to version 21.1.0 or higher
6. Run `pnpm audit fix` to auto-patch compatible updates

### Medium Priority Actions

7. Review all entries in .secrets.baseline file
8. Audit test files for accidentally committed real credentials
9. Implement automated dependency scanning in CI/CD pipeline
10. Set up Dependabot or similar for automated security updates

---

## SCAN COMMANDS FOR VERIFICATION

Reproduce these findings with:

```bash
# Clone repository
git clone https://github.com/clawdbot/clawdbot.git
cd clawdbot

# Run Trivy vulnerability scan
trivy fs . --severity HIGH,CRITICAL --scanners vuln

# Run secret detection
gitleaks detect --source .

# Check npm/pnpm vulnerabilities
pnpm audit
```

---

## DISCLAIMER

This security audit was performed using automated tools and manual review techniques. While every effort has been made to identify security issues, this report may not capture all vulnerabilities. The findings represent the state of the repository at the time of the audit. Security is an ongoing process, and regular audits are recommended.

---

## REPORT METADATA

- **Report ID:** AURA-2026-0125-CLAWDBOT
- **Generated:** January 25, 2026
- **Scanner:** AuraSecurity v0.7.0
- **Repository Commit:** HEAD (shallow clone)
- **Total Files Scanned:** 4,418

---

*This report was generated by AuraSecurity (https://aurasecurity.io)*
