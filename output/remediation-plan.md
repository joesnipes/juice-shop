# Remediation Plan

- SCA branch: not created (no confirmed SCA/dependency findings in `output/findings.json`).
- SAST branch: `security-fixes/sast-20260510-213121`
- SAST pull request: https://github.com/joesnipes/juice-shop/pull/12
- Fixed SAST findings: AUDIT-001, AUDIT-002, AUDIT-003, AUDIT-004, AUDIT-005, AUDIT-006, AUDIT-007, AUDIT-008, AUDIT-010, AUDIT-011, AUDIT-012
- Deferred SAST findings: AUDIT-009, AUDIT-013
- Validation: `npm run build:server` failed because `tsc` was not found; `npm run lint` failed because `eslint` was not found.

## Fixed findings

### AUDIT-001 — CWE-89 / A03:2021-Injection
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-001`
- Vulnerable: `routes/login.ts:34` used interpolated SQL with email and password.
- Changed: `routes/login.ts:34` uses `?` replacements for email and hashed password.
- Why fixed: user input is bound as data, not SQL syntax.
- Functionality: login response, basket creation, and TOTP flow are preserved.

### AUDIT-002 — CWE-89 / A03:2021-Injection
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-002`
- Vulnerable: `routes/search.ts:23` interpolated search criteria into SQL.
- Changed: `routes/search.ts:23` binds both LIKE terms as replacements.
- Why fixed: the criteria cannot alter SQL structure.
- Functionality: partial product search and JSON response shape are preserved.

### AUDIT-003 — CWE-94 / A03:2021-Injection
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-003`
- Vulnerable: `routes/trackOrder.ts:18` used `$where` JavaScript with user input.
- Changed: `routes/trackOrder.ts:18` uses `{ orderId: id }`.
- Why fixed: no server-side JavaScript is constructed or evaluated.
- Functionality: order lookup and missing-order fallback are preserved.

### AUDIT-004 — CWE-94 / A03:2021-Injection
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-004`
- Vulnerable: `routes/showProductReviews.ts:36` used `$where` JavaScript with product id.
- Changed: `routes/showProductReviews.ts:36` uses `{ product: id }`.
- Why fixed: structured predicates replace executable query strings.
- Functionality: review retrieval and liked flag behavior are preserved.

### AUDIT-005 — CWE-918 / A10:2021-Server-Side Request Forgery
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-005`
- Vulnerable: `routes/profileImageUrlUpload.ts:24` fetched arbitrary URLs.
- Changed: `routes/profileImageUrlUpload.ts:31-55` validates HTTP(S), ports, and DNS-resolved addresses before fetch.
- Why fixed: private, localhost, link-local, and non-HTTP(S) destinations are blocked before server-side fetch.
- Functionality: public remote image upload still works; failed fetches still fall back to storing the link.

### AUDIT-006 — CWE-22 / A01:2021-Broken Access Control
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-006`
- Vulnerable: `routes/fileUpload.ts:41-45` resolved archive entries but wrote with the original path.
- Changed: `routes/fileUpload.ts:41-46` resolves against `uploads/complaints` and requires the destination to stay under that root.
- Why fixed: traversal entries are drained instead of written outside the upload directory.
- Functionality: valid ZIP complaint extraction continues under the same folder.

### AUDIT-007 — CWE-611 / A05:2021-Security Misconfiguration
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-007`
- Vulnerable: `routes/fileUpload.ts:83` parsed XML with `noent: true`.
- Changed: `routes/fileUpload.ts:84` parses with `noent: false`.
- Why fixed: external entities are not expanded into parser output.
- Functionality: deprecated XML upload error handling remains.

### AUDIT-008 — CWE-798 / A02:2021-Cryptographic Failures
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-008`
- Vulnerable: `lib/insecurity.ts:23` hardcoded a JWT private key and `server.ts:276-278` served `/encryptionkeys`.
- Changed: `lib/insecurity.ts:21-28` uses environment-provided or runtime-generated RSA keys; `server.ts:276-277` returns 404 for `/encryptionkeys`.
- Why fixed: signing material is no longer embedded in source or exposed over HTTP.
- Functionality: JWT auth remains functional; stable production keys can be supplied through environment variables.
- Residual risk: rotate previously exposed keys and move production secrets to managed storage.

### AUDIT-010 — CWE-94 / A03:2021-Injection
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-010`
- Vulnerable: `routes/dataErasure.ts:72-74` spread `req.body` into `res.render`.
- Changed: `routes/dataErasure.ts:50-82` passes only `email` and `securityAnswer` view locals.
- Why fixed: attacker-controlled render options cannot be merged into Express view rendering.
- Functionality: privacy request creation, cookie clearing, and result rendering are preserved.

### AUDIT-011 — CWE-200 / A01:2021-Broken Access Control
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-011`
- Vulnerable: `server.ts:280-283` listed and served log files publicly.
- Changed: `server.ts:279-280` returns 404 for `/support/logs`.
- Why fixed: access logs are no longer retrievable over HTTP.
- Functionality: file logging remains; only public log browsing/downloads are removed.

### AUDIT-012 — CWE-601 / A01:2021-Broken Access Control
- GitHub security finding link: unavailable direct link; search URL `https://github.com/joesnipes/juice-shop/security/code-scanning?query=AUDIT-012`
- Vulnerable: `lib/insecurity.ts:135-140` allowed redirects by substring match.
- Changed: `lib/insecurity.ts:140-153` parses URLs and requires exact `href` equality with allowlisted URLs.
- Why fixed: untrusted URLs cannot pass by embedding a trusted URL as text.
- Functionality: existing exact allowlisted redirects continue to work.

## Deferred findings requiring developer decisions

### AUDIT-009 — CWE-916 / A02:2021-Cryptographic Failures
- Vulnerable: `lib/insecurity.ts:48` uses unsalted MD5.
- Status: `developer_decision_required`.
- Reason: safe remediation requires schema changes for per-user salts, data migration, and a rehash-on-login plan. A partial change could lock users out or break seed data.

### AUDIT-013 — CWE-311 / A02:2021-Cryptographic Failures
- Vulnerable: `models/card.ts:39-46` stores full payment card numbers.
- Status: `developer_decision_required`.
- Reason: safe remediation requires payment-provider tokenization or encryption design, managed keys, schema migration, and retention/compliance decisions.

## Validation details

```text
npm run build:server
→ failed: sh: tsc: command not found

npm run lint
→ failed: sh: eslint: command not found
```
