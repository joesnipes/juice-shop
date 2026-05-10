# SCA Remediation Manifest

- **Branch type:** SCA
- **Branch:** `security-fixes/sca-20260510-152412`
- **Pull request:** https://github.com/joesnipes/juice-shop/pull/3
- **Source artifact:** `output/canonical-findings.json`
- **Fixed:** 0
- **Developer decision required:** 2

No confirmed dependency-only findings were present. The confirmed dependency-related items are hybrid findings whose safe remediation requires coordinated source-code and challenge-design decisions.

## CANON-HYBRID-003 - developer_decision_required

- **Severity:** critical
- **CWE/OWASP:** CWE-321; CWE-347; CWE-798 / A02:2021-Cryptographic Failures; A07:2021-Identification and Authentication Failures
- **GitHub security links:** https://github.com/advisories/GHSA-c7hr-j4mj-j2w6, https://github.com/advisories/GHSA-6g6m-m6h5-w9gf, https://github.com/advisories/GHSA-8cf7-32gw-wr33
- **Vulnerable file/lines:** `package.json:135,156`; `lib/insecurity.ts:22-57,156-164,188-199`
- **Vulnerable snippet:** `"express-jwt": "0.1.3", "jsonwebtoken": "0.4.0"; const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'; export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`
- **Changed snippet:** none; no safe dependency-only change applied
- **Why deferred:** Modern JWT dependency upgrades require authentication API and verification behavior changes and must be paired with removal/rotation of source-controlled signing keys.
- **Functionality preservation:** No dependency change was made, preserving login/token/challenge behavior.
- **Validation:** not run; manifest-only proposal.
- **Residual risk:** JWT advisories and hardcoded key remain until maintainers approve a coordinated JWT/key-management migration.

## CANON-HYBRID-006 - developer_decision_required

- **Severity:** critical
- **CWE/OWASP:** CWE-94; CWE-913 / A03:2021-Injection; API8:2023-Security Misconfiguration
- **GitHub security link:** https://github.com/advisories/GHSA-8g4m-cjm2-96wq
- **Vulnerable file/lines:** `package.json:167`; `routes/b2bOrder.ts:16-24`
- **Vulnerable snippet:** `"notevil": "^1.3.3"; const orderLinesData = body.orderLinesData || ''; const sandbox = { safeEval, orderLinesData }; vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })`
- **Changed snippet:** none; no safe dependency-only change applied
- **Why deferred:** Replacing/removing `notevil` must be coordinated with eliminating attacker-controlled evaluation in the B2B endpoint and preserving or intentionally changing challenge behavior.
- **Functionality preservation:** No dependency change was made, preserving B2B/challenge behavior.
- **Validation:** not run; manifest-only proposal.
- **Residual risk:** Sandbox escape remains until maintainers approve production-safe parsing or a challenge-mode split.
