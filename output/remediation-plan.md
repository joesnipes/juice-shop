# Remediation Plan

- SCA branch: none created. No confirmed dependency-only remediation could be applied safely without approving a Node/runtime and JWT middleware upgrade path.
- SAST branch: `security-fixes/sast-20260510-210334`
- PR URL: https://github.com/joesnipes/juice-shop/pull/9
- Direct GitHub security alert URLs were unavailable in `output/findings.json`/SARIF, so repository code-scanning/dependabot search URLs are recorded.

## Validation

- `node --check routes/login.js && node --check routes/search.js && node --check lib/insecurity.js && node --check routes/b2bOrder.js && node --check routes/fileUpload.js && node --check routes/profileImageUrlUpload.js && node --check routes/basket.js && node --check server.js`: passed.
- `npm run lint`: failed before linting because `node_modules` is missing `acorn`.
- `npm test`: failed before tests because frontend `ng` is not installed.
- Environment note: `node --version` reported `v23.11.0`; `package.json` declares supported Node `8 - 12`.

## Fixed SAST findings

- `PROD-AUDIT-001` (`CWE-89`, critical): parameterized login SQL in `routes/login.js:24-31`; preserves login response and challenge flow while removing SQL injection.
- `PROD-AUDIT-002` (`CWE-89`, critical): parameterized product search SQL in `routes/search.js:9-11`; preserves public substring search and response format.
- `PROD-AUDIT-004` (`CWE-347`, critical): pinned JWT authorization middleware to `RS256` in `lib/insecurity.js:25`; dependency upgrade remains SCA developer action.
- `PROD-AUDIT-005` (`CWE-94`, critical): replaced `notevil`/`vm` execution with `JSON.parse()` in `routes/b2bOrder.js:7-10`; valid JSON orders still receive the same response shape.
- `PROD-AUDIT-006` (`CWE-22`, high): constrained ZIP extraction to `uploads/complaints` in `routes/fileUpload.js:25-35`; valid entries still extract there.
- `PROD-AUDIT-007` (`CWE-611`, high): disabled XML entity expansion and removed reflected XML content in `routes/fileUpload.js:55-61`; deprecated XML flow still returns 410.
- `PROD-AUDIT-008` (`CWE-918`, high): validated URL scheme/credentials/DNS/private ranges and disabled redirects in `routes/profileImageUrlUpload.js:18-74`; public HTTP/HTTPS image URLs remain supported.
- `PROD-AUDIT-009` (`CWE-639`, high): enforced authenticated basket ownership in `routes/basket.js:9-13`; own-basket response shape remains unchanged.
- `PROD-AUDIT-010` (`CWE-862`, high): required admin authorization for product PUT in `server.js:192`.
- `PROD-AUDIT-011` (`CWE-548`, medium): required admin authorization before support log listing/file serving in `server.js:137-140`.
- `PROD-AUDIT-013` (`CWE-862`, medium): required admin authorization for user listing in `server.js:185`.
- `PROD-AUDIT-014` (`CWE-601`, low): replaced substring redirect allowlist with exact parsed URL component comparison in `lib/insecurity.js:103-116`.

## Developer decision required

- `PROD-AUDIT-003` (`CWE-798`): hardcoded JWT private key. Safe remediation requires secret manager/KMS selection, deployment configuration, key rotation, and token invalidation policy.
- `PROD-AUDIT-004` SCA component (`CWE-347`/A06): `express-jwt`/`jsonwebtoken` upgrade requires runtime/API compatibility decision for this Node 8-12-era application.
- `PROD-AUDIT-012` (`CWE-916`): MD5 password storage. Safe remediation requires password-hash algorithm approval, dependency/schema migration, seeded credential migration, and reset/rehash flow.

See `output/remediation-plan.json` for vulnerable snippets, changed snippets, GitHub/SARIF search URLs, validation status, rationale, and residual risk for every fixed or deferred finding.
