# SAST Remediation Manifest

- **Branch type:** SAST
- **Branch:** `security-fixes/sast-20260510-152412`
- **Pull request:** https://github.com/joesnipes/juice-shop/pull/4
- **Source artifact:** `output/canonical-findings.json`
- **Fixed:** 0
- **Developer decision required:** 14
- **Validation:** not run; no source-code changes were applied.

All confirmed source-code findings are in intentionally vulnerable OWASP Juice Shop training/challenge paths or require product/security architecture choices. To avoid silently breaking challenge functionality, each item is deferred for maintainer decision instead of applying behavior-changing fixes.

| ID | Severity | CWE / OWASP | Vulnerable file/lines | Vulnerable snippet | Changed snippet | Status | Functionality preservation / decision needed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CANON-SAST-001 | critical | CWE-89 / A03:2021-Injection; API8:2023-Security Misconfiguration | `routes/login.ts:32-35` | `models.sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email || ''}' ...\`)` | none | developer_decision_required | Parameterized login would fix SQLi but break login SQLi challenges; no change applied. |
| CANON-SAST-002 | critical | CWE-89 / A03:2021-Injection; API8:2023-Security Misconfiguration | `routes/search.ts:20-24` | `models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' ...\`)` | none | developer_decision_required | Parameterized search would break union SQLi/schema challenges; no change applied. |
| CANON-HYBRID-003 | critical | CWE-321; CWE-347; CWE-798 / A02:2021; A07:2021 | `lib/insecurity.ts:22-57,156-164,188-199` | hardcoded RSA private key; `jwt.sign(..., privateKey, ...)`; role trust from token claims | none | developer_decision_required | Requires key management, rotation, JWT migration, and challenge decisions. Advisory links: GHSA-c7hr-j4mj-j2w6, GHSA-6g6m-m6h5-w9gf, GHSA-8cf7-32gw-wr33. |
| CANON-SAST-004 | high | CWE-639; CWE-862 / A01:2021; API1:2023 | `routes/basket.ts:18-31`; `routes/order.ts:35-50` | basket lookup by `id` only | none | developer_decision_required | User-scoped lookup would alter cross-basket challenge/checkout behavior. |
| CANON-SAST-005 | high | CWE-918 / A10:2021; API7:2023 | `routes/profileImageUrlUpload.ts:18-32` | `const response = await fetch(url)` | none | developer_decision_required | SSRF controls require allowlist/proxy policy and may restrict valid image URLs. |
| CANON-HYBRID-006 | critical | CWE-94; CWE-913 / A03:2021; API8:2023 | `routes/b2bOrder.ts:16-24` | `vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })` | none | developer_decision_required | Removing eval requires declarative import format or production/challenge mode split. Advisory link: GHSA-8g4m-cjm2-96wq. |
| CANON-SAST-007 | high | CWE-611; CWE-200 / A05:2021; A03:2021 | `routes/fileUpload.ts:75-99` | `libxml.parseXml(..., { noent: true, ... }); next(new Error(... xmlString ...))` | none | developer_decision_required | Disabling entity expansion and disclosure would alter XML upload challenge responses. |
| CANON-SAST-008 | high | CWE-22; CWE-73 / A01:2021; A05:2021 | `routes/fileUpload.ts:27-49` | weak path containment check and write to `uploads/complaints/` + entry path | none | developer_decision_required | Correct archive containment would prevent traversal challenge behavior. |
| CANON-SAST-009 | high | CWE-840; CWE-352 / A04:2021; API6:2023 | `routes/wallet.ts:21-29` | `WalletModel.increment({ balance: req.body.balance }, ...)` | none | developer_decision_required | Real fix needs payment provider, ledger, idempotency, and amount policy. |
| CANON-SAST-010 | critical | CWE-548; CWE-200 / A01:2021; A05:2021 | `server.ts:267-283,714-718` | public `serveIndex` on `/ftp`, `/encryptionkeys`, `/support/logs`; public `/metrics` | none | developer_decision_required | Lockdown affects training flows and operational visibility; production-hardening mode needed. |
| CANON-SAST-011 | high | CWE-311; CWE-312 / A02:2021 | `models/card.ts:38-46`; `routes/payment.ts:21-33` | full `cardNum` storage; response-only masking | none | developer_decision_required | Tokenization/encryption requires schema and payment-flow migration. |
| CANON-SAST-012 | high | CWE-916; CWE-327 / A02:2021; A07:2021 | `lib/insecurity.ts:43`; `models/user.ts:74-78` | `crypto.createHash('md5')`; password setter stores MD5 | none | developer_decision_required | Argon2/bcrypt migration needs dependency choice, hash versioning, and seeded-user compatibility. |
| CANON-SAST-013 | critical | CWE-266; CWE-915 / A01:2021; API3:2023 | `server.ts:407-421,478-505`; `models/user.ts:80-99` | generated `POST /api/Users`; role accepts privileged values | none | developer_decision_required | DTO allowlist/admin flow changes may break generated API and challenges. |
| CANON-SAST-014 | medium | CWE-601 / A01:2021; A05:2021 | `lib/insecurity.ts:135-140`; `routes/redirect.ts:13-20` | `url.includes(allowedUrl)` before `res.redirect(toUrl)` | none | developer_decision_required | Exact allowlist validation would intentionally change open-redirect challenge behavior. |

## GitHub security links

Direct GitHub code-scanning alert URLs were not present in the supplied findings/SARIF artifacts. Advisory URLs are included where available for hybrid dependency-related findings.
