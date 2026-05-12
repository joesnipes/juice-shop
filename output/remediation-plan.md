# Remediation Plan - SAST

- Branch: `security-fixes/sast-20260511-200206`
- Fixed: JS-PROD-001, JS-PROD-002, JS-PROD-006, JS-PROD-007, JS-PROD-008, JS-PROD-009, JS-PROD-012, JS-PROD-013, JS-PROD-014
- Deferred for developer/product decision: JS-PROD-003, JS-PROD-004, JS-PROD-005, JS-PROD-010, JS-PROD-011

## Validation

- `npm run build:server`: passed
- `npx eslint lib/insecurity.ts routes/login.ts routes/search.ts routes/trackOrder.ts routes/basket.ts routes/currentUser.ts routes/fileUpload.ts routes/profileImageUrlUpload.ts`: passed
- `npm run lint`: failed; frontend lint could not run because `ng` was not found in the local frontend install.
- `npm rebuild libxmljs2 && npm run test:server`: failed; 213 passing, 2 pending, 6 failing. Failures include challenge assertions now intentionally blocked by remediation plus baseline date expectations.
- `npm run rsn`: failed because vulnerable challenge snippets changed; cache was not updated.

## Fixed Findings

- JS-PROD-001 (CWE-89, A03): login SQL now uses Sequelize replacements instead of interpolated email/password. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/316
- JS-PROD-002 (CWE-89, A03): product search now uses a bound LIKE parameter with wildcard escaping. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/317
- JS-PROD-006 (CWE-94, A03): order tracking no longer uses MarsDB `$where`; it queries `{ orderId: id }`. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/328
- JS-PROD-007 (CWE-22, A05): ZIP paths are constrained to the upload directory, XML entity expansion/network access is disabled, and YAML uses safeLoad. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/329
- JS-PROD-008 (CWE-639, A01): basket reads are bound to authenticated `UserId`. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/321
- JS-PROD-009 (CWE-918, A10): profile image fetches validate public HTTP(S), block private DNS resolutions, disable redirects, and timeout. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/322
- JS-PROD-012 (CWE-200, A01): whoami field selection is constrained to safe public fields. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/325
- JS-PROD-013 (CWE-614, A05): JWT cookie is set with HttpOnly, SameSite=Lax, and HTTPS-aware Secure. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/327
- JS-PROD-014 (CWE-601, A01): redirect allowlist compares parsed scheme/host/path exactly. Link: https://github.com/joesnipes/juice-shop/security/code-scanning/326

Full vulnerable/changed snippets and rationale are in `output/remediation-plan.json`.
