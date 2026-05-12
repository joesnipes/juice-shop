# Remediation Plan - SCA

- Branch: `security-fixes/sca-20260511-200206`
- Validation: `npm install --package-lock=false --ignore-scripts` passed; `npm run build:server` passed.

## Fixed

### JS-PROD-015 - Vulnerable HTML Sanitizer Allows XSS Bypass
- Severity/CWE/OWASP: MEDIUM, CWE-79, A03:2021-Injection
- GitHub security links: https://github.com/joesnipes/juice-shop/security/dependabot/2, https://github.com/joesnipes/juice-shop/security/dependabot/3
- Vulnerable snippet: `"sanitize-html": "1.4.2"` and `"@types/sanitize-html": "^1.27.2"`
- Changed snippet: `"sanitize-html": "^2.17.0"` and `"@types/sanitize-html": "^2.16.0"`
- Why it fixes: moves the direct sanitizer dependency to a maintained 2.x version containing XSS bypass fixes.
- Functionality preservation: keeps the existing sanitizer wrapper and call sites unchanged.

## Deferred

### JS-PROD-003 - JWT dependency component
- Severity/CWE/OWASP: CRITICAL, CWE-321, A02:2021-Cryptographic Failures
- GitHub security links: https://github.com/joesnipes/juice-shop/security/dependabot/1, https://github.com/joesnipes/juice-shop/security/dependabot/10
- Vulnerable snippet: `"jsonwebtoken": "0.4.0"`
- Changed snippet: no safe dependency-only change made.
- Decision required: jsonwebtoken upgrade should be paired with key rotation and JWT code hardening to avoid breaking authentication or retaining insecure legacy key settings.
