# Remediation Plan

- Branch type: SAST
- Branch: `security-fixes/sast-20260511-183242`
- Fixed findings: JS-AUDIT-001, JS-AUDIT-002, JS-AUDIT-004, JS-AUDIT-005, JS-AUDIT-006, JS-AUDIT-007, JS-AUDIT-008, JS-AUDIT-010, JS-AUDIT-011, JS-AUDIT-012
- Developer decision required: JS-AUDIT-003, JS-AUDIT-009
- SCA findings fixed: none; no separate confirmed dependency-only finding was present in the supplied reports.

## Validation

- `npm install --ignore-scripts --no-audit --no-fund`: passed; installed dependencies for local validation.
- `npm run build:server`: passed.
- `npm run test:server`: failed before tests ran because `libxmljs2` native bindings were unavailable after lifecycle scripts were disabled during dependency installation.

## Fixed findings

### JS-AUDIT-001 — CRITICAL — CWE-89 — A03:2021 Injection

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/262
- Vulnerable: `routes/login.ts:32-35` — raw login SQL interpolated `req.body.email` and password hash.
- Changed: `routes/login.ts:34-41` — SQL now uses `:email` and `:password` replacements.
- Why fixed: user input is bound as data and cannot alter the SQL predicate.
- Functionality: login response, TOTP handling, and basket setup are preserved.

### JS-AUDIT-002 — CRITICAL — CWE-89 — A03:2021 Injection

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/263
- Vulnerable: `routes/search.ts:20-24` — search criteria interpolated into `LIKE` SQL.
- Changed: `routes/search.ts:21-25` — criteria is passed via Sequelize replacements.
- Why fixed: the search term is no longer SQL syntax.
- Functionality: contains-search behavior and response shape are preserved.

### JS-AUDIT-004 — CRITICAL — CWE-200/CWE-548/CWE-538

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/265
- Vulnerable: `server.ts:267-286,714-718` — public FTP/key/log/docs/metrics routes.
- Changed: `server.ts:275-291,718` — FTP requires auth, encryption key routes deny all, logs/metrics require accounting role, API docs require auth.
- Why fixed: sensitive operational resources are no longer anonymously listed or downloaded.
- Functionality: authenticated access remains for required operational routes.
- Residual risk: order PDFs should eventually be served through owner-scoped signed URLs.

### JS-AUDIT-005 — CRITICAL — CWE-915/CWE-266

- GitHub: unavailable in source report.
- Vulnerable: `server.ts:407-420,478-515` — public registration could mass-assign role fields.
- Changed: `server.ts:412-425` — strips `role` and `deluxeToken`, then forces `role='customer'`.
- Why fixed: client-supplied privilege attributes cannot be persisted during registration.
- Functionality: normal registration remains available.

### JS-AUDIT-006 — HIGH — CWE-639/CWE-862

- GitHub: unavailable in source report.
- Vulnerable: `routes/basket.ts:18-31; routes/order.ts:35-50` — basket lookup by URL id only.
- Changed: `routes/basket.ts:19-32; routes/order.ts:36` — basket lookup includes authenticated `UserId`.
- Why fixed: users cannot read or check out another user's basket id.
- Functionality: owners can still read and check out their own baskets.

### JS-AUDIT-007 — HIGH — CWE-918

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/270
- Vulnerable: `routes/profileImageUrlUpload.ts:18-32` — arbitrary server-side fetch.
- Changed: `routes/profileImageUrlUpload.ts:32-55,76-107` — enforces HTTPS, no credentials, DNS/private-IP blocking, no redirects, timeout, image content type, and size limits.
- Why fixed: attacker-controlled URLs cannot target internal/private services.
- Functionality: valid HTTPS public image uploads still work; invalid URLs fall back to link storage.

### JS-AUDIT-008 — HIGH — CWE-311/CWE-312/CWE-359

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/273
- Vulnerable: `models/card.ts:38-46; routes/payment.ts:21-32` — full PAN persisted.
- Changed: `models/card.ts:39-48` — only last four digits are stored via a model setter.
- Why fixed: database disclosure no longer exposes full payment card numbers.
- Functionality: masked card display still returns twelve asterisks plus last four digits.

### JS-AUDIT-010 — HIGH — CWE-200/CWE-201

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/275
- Vulnerable: `routes/currentUser.ts:17-32` — arbitrary requested fields copied from user data.
- Changed: `routes/currentUser.ts:25-33` — allowlist limits selectable fields to safe profile fields.
- Why fixed: password hashes, TOTP secrets, roles, and tokens cannot be serialized by `fields=`.
- Functionality: default response and safe field selection are preserved.

### JS-AUDIT-011 — MEDIUM — CWE-601

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/274
- Vulnerable: `lib/insecurity.ts:135-140` — substring redirect allowlist.
- Changed: `lib/insecurity.ts:136-156` — parses URLs, rejects userinfo, and compares components exactly.
- Why fixed: malicious domains containing an allowlisted URL string no longer pass validation.
- Functionality: exact allowlisted destinations continue to redirect.

### JS-AUDIT-012 — MEDIUM — CWE-614/CWE-1004/CWE-352

- GitHub: https://github.com/joesnipes/juice-shop/security/code-scanning/278 and https://github.com/joesnipes/juice-shop/security/code-scanning/276
- Vulnerable: `lib/insecurity.ts:188-196; server.ts:180-182` — insecure token cookies and permissive CORS.
- Changed: `lib/insecurity.ts:210,218-222; routes/updateUserProfile.ts:40; server.ts:180-188` — JWT cookies use HttpOnly/SameSite/Secure where appropriate and CORS is restricted to configured base URL.
- Why fixed: scripts cannot read the cookie, cross-site cookie sending is restricted, and arbitrary origins are not allowed.
- Functionality: same-origin and configured-origin browser flows continue to work.

## Developer decisions required

- JS-AUDIT-003: hardcoded JWT private key/JWT library migration requires secret rotation, deployment configuration, and key management decisions. Public `/encryptionkeys` routes were denied as a partial risk reduction.
- JS-AUDIT-009: MD5 password migration requires hash versioning, rehash-on-login or forced resets, and rollout planning to avoid account lockout.

Full structured details are in `output/remediation-plan.json`.
