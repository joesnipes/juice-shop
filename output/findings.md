# Standardized Vulnerability Findings Report

- Source findings: `output/canonical-findings.json`
- Threat model: `output/threat-model.md`
- Generated: 2026-05-10T19:21:44Z

## Summary

- Total findings: **19**
- Triage counts: confirmed=14, needs_review=3, false_positive=2
- Severity counts: critical=6, high=8, medium=3, low=0, info=2

## Findings

### CANON-SAST-001 - Authentication SQL injection permits login bypass

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.8`)
- **Confidence:** 0.98
- **File/Lines:** `routes/login.ts` @ `32-35`
- **CWE:** CWE-89
- **OWASP:** A03:2021-Injection; API8:2023-Security Misconfiguration
- **Evidence quality:** strong: direct external route registration in server.ts:594 and direct interpolation of req.body.email in routes/login.ts:34.
- **Exploitability rationale:** The public POST /rest/user/login route passes attacker-controlled email directly into a raw SQL template string. A production attacker can alter the WHERE clause to authenticate as another account, including privileged users, before JWT issuance.
- **Remediation:** Replace raw string interpolation with parameterized Sequelize replacements/bind parameters, validate email format before query execution, and add regression tests for SQL metacharacters.

```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

### CANON-SAST-002 - Product search SQL injection leaks database data

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.1`)
- **Confidence:** 0.98
- **File/Lines:** `routes/search.ts` @ `20-24`
- **CWE:** CWE-89
- **OWASP:** A03:2021-Injection; API8:2023-Security Misconfiguration
- **Evidence quality:** strong: direct public route in server.ts:600 and challenge verification code expects user table/schema leakage in routes/search.ts:26-63.
- **Exploitability rationale:** The public GET /rest/products/search endpoint places req.query.q into a SQL LIKE clause. The 200-character truncation does not neutralize SQL syntax; UNION payloads can exfiltrate users, password hashes, schema, and other SQLite content.
- **Remediation:** Use parameterized LIKE queries with bound replacements, escape wildcard characters intentionally, and enforce query allowlists/length limits after parameterization.

```
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

### CANON-HYBRID-003 - Hardcoded JWT private key and vulnerable JWT stack enable token forgery

- **Type:** SAST/SCA
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.8`)
- **Confidence:** 0.96
- **File/Lines:** `lib/insecurity.ts` @ `22-57,156-164,188-199`
- **CWE:** CWE-321; CWE-347; CWE-798
- **OWASP:** A02:2021-Cryptographic Failures; A07:2021-Identification and Authentication Failures
- **Evidence quality:** strong: private key literal in lib/insecurity.ts:23, token signing in line 56, role trust in lines 156-164, package versions in package.json:135 and 156; npm advisories GHSA-c7hr-j4mj-j2w6, GHSA-6g6m-m6h5-w9gf, GHSA-8cf7-32gw-wr33 are related.
- **Exploitability rationale:** The signing private key is embedded in source and used to sign all authentication tokens. Any party with repository/container access can mint arbitrary role claims; public routes then trust decoded token roles for accounting/admin-like actions. SCA confirms very old direct dependencies jsonwebtoken 0.4.0 and express-jwt 0.1.3 are in use, increasing verification bypass risk, but the hardcoded key alone is sufficient for exploitation.
- **Remediation:** Move signing keys to a KMS/secret manager, rotate keys, remove source-controlled keys, pin accepted algorithms in jwt.verify/express-jwt, upgrade jsonwebtoken and express-jwt to maintained versions, and authorize privileged actions from server-side policy not self-contained mutable claims.

```
const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'; export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' }); export const isAccounting = () => { const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req)); if (decodedToken?.data?.role === roles.accounting) next() }
```

### CANON-SAST-004 - Broken object-level authorization exposes and checks out other users' baskets

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `8.8`)
- **Confidence:** 0.95
- **File/Lines:** `routes/basket.ts; routes/order.ts` @ `routes/basket.ts:18-31; routes/order.ts:35-50`
- **CWE:** CWE-639; CWE-862
- **OWASP:** A01:2021-Broken Access Control; API1:2023-Broken Object Property Level Authorization
- **Evidence quality:** strong: /rest/basket/:id and /rest/basket/:id/checkout require authentication in server.ts:398-399 but route code queries only by id. Challenge code explicitly detects cross-basket access in routes/basket.ts:21-24.
- **Exploitability rationale:** Authenticated users can supply arbitrary basket IDs. Middleware appends the caller's UserId but these queries do not constrain by UserId/bid, so a user can read another basket and submit checkout for it, causing item removal, order creation, inventory changes, and wallet effects.
- **Remediation:** For all basket operations query by both basket id and authenticated UserId/bid. Return 404/403 for mismatches and add customer A/customer B authorization tests.

```
const basket = await BasketModel.findOne({ where: { id }, include: [...] }); BasketModel.findOne({ where: { id }, include: [...] })
```

### CANON-SAST-005 - Server-side request forgery through profile image URL fetch

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `8.6`)
- **Confidence:** 0.94
- **File/Lines:** `routes/profileImageUrlUpload.ts` @ `18-32`
- **CWE:** CWE-918
- **OWASP:** A10:2021-Server-Side Request Forgery; API7:2023-Server Side Request Forgery
- **Evidence quality:** strong: direct route at server.ts:311 and direct fetch of req.body.imageUrl in routes/profileImageUrlUpload.ts:24.
- **Exploitability rationale:** An authenticated user controls imageUrl, and the server fetches it without scheme, host, DNS, private-IP, metadata-IP, timeout, redirect, content-type, or byte-limit controls. This can reach internal services and write attacker-controlled responses into a public uploads directory.
- **Remediation:** Require HTTPS and an allowlist or dedicated media proxy; block private, loopback, link-local and metadata ranges after DNS resolution; disable unsafe redirects; set strict timeouts and max response size; validate MIME by content.

```
const url = req.body.imageUrl; const response = await fetch(url); ... Readable.fromWeb(response.body as any).pipe(fileStream)
```

### CANON-HYBRID-006 - B2B order endpoint evaluates attacker-supplied code with vulnerable notevil sandbox

- **Type:** SAST/SCA
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.0`)
- **Confidence:** 0.9
- **File/Lines:** `routes/b2bOrder.ts` @ `16-24`
- **CWE:** CWE-94; CWE-913
- **OWASP:** A03:2021-Injection; API8:2023-Security Misconfiguration
- **Evidence quality:** strong: authenticated B2B route registration in server.ts:423 and 645, direct evaluation in routes/b2bOrder.ts:23, direct dependency notevil ^1.3.3 in package.json:167 and SCA GHSA-8g4m-cjm2-96wq.
- **Exploitability rationale:** Authenticated callers of POST /b2b/v2/orders can provide orderLinesData that is evaluated as code. The notevil package is explicitly flagged for sandbox escape (GHSA-8g4m-cjm2-96wq) and this code wraps it in a Node vm context, which is not a security boundary. Successful exploitation can execute code in the application process.
- **Remediation:** Remove evaluation entirely. Parse a declarative JSON schema for order lines, validate with a schema validator, and run complex imports in an isolated worker/container without access to secrets or filesystem.

```
const orderLinesData = body.orderLinesData || ''; const sandbox = { safeEval, orderLinesData }; vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
```

### CANON-SAST-007 - XML upload enables XXE and response disclosure

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `8.1`)
- **Confidence:** 0.9
- **File/Lines:** `routes/fileUpload.ts` @ `75-99`
- **CWE:** CWE-611; CWE-200
- **OWASP:** A05:2021-Security Misconfiguration; A03:2021-Injection
- **Evidence quality:** strong: route registration in server.ts:309 and noent parser option plus reflected parsed XML in routes/fileUpload.ts:83-87.
- **Exploitability rationale:** The unauthenticated /file-upload route accepts XML and parses it with entity expansion enabled (noent: true). Parsed XML content and parser errors are returned in error messages, making local file disclosure via external entities plausible in production deployments where libxml entity resolution is available.
- **Remediation:** Disable external entity and DTD processing, avoid returning parsed content/errors to clients, use a hardened XML parser with strict size/depth limits, and require authentication if uploads are business-only.

```
vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 }); next(new Error('... ' + utils.trunc(xmlString, 400) + ...))
```

### CANON-SAST-008 - ZIP upload path traversal writes outside complaint upload directory

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `7.8`)
- **Confidence:** 0.88
- **File/Lines:** `routes/fileUpload.ts` @ `27-49`
- **CWE:** CWE-22; CWE-73
- **OWASP:** A01:2021-Broken Access Control; A05:2021-Security Misconfiguration
- **Evidence quality:** strong: unauthenticated /file-upload route in server.ts:309, write path from entry.path in routes/fileUpload.ts:41-45, and challenge code recognizes write to ftp/legal.md in line 43.
- **Exploitability rationale:** ZIP entry names are attacker-controlled. The containment check only verifies that the resolved path contains the repository root, not that it remains below uploads/complaints, so entries such as ../../ftp/legal.md can overwrite other application files under the process working tree.
- **Remediation:** Resolve the destination under a fixed base directory and require dest.startsWith(base + path.sep), reject absolute paths/symlinks/.. segments, generate server-side filenames, and scan archives before extraction.

```
const absolutePath = path.resolve('uploads/complaints/' + fileName); if (absolutePath.includes(path.resolve('.'))) { entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName)) }
```

### CANON-SAST-009 - Wallet balance can be inflated by client-supplied amount

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `8.0`)
- **Confidence:** 0.9
- **File/Lines:** `routes/wallet.ts` @ `21-29`
- **CWE:** CWE-840; CWE-352
- **OWASP:** A04:2021-Insecure Design; API6:2023-Unrestricted Access to Sensitive Business Flows
- **Evidence quality:** strong: authenticated route registration in server.ts:625 with appendUserId and direct balance increment from request body in routes/wallet.ts:27.
- **Exploitability rationale:** An authenticated user only needs an owned card record; the server then trusts req.body.balance and directly increments wallet funds. No payment processor confirmation, amount bounds, currency validation, or idempotency is enforced.
- **Remediation:** Create server-side top-up intents, verify settled payment events from a payment provider, enforce positive bounded amounts, use idempotency keys, and store immutable ledger entries instead of direct balance mutation.

```
const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null; await WalletModel.increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } })
```

### CANON-SAST-010 - Sensitive operational directories are publicly browsable

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.0`)
- **Confidence:** 0.93
- **File/Lines:** `server.ts` @ `267-283,714-718`
- **CWE:** CWE-548; CWE-200
- **OWASP:** A01:2021-Broken Access Control; A05:2021-Security Misconfiguration
- **Evidence quality:** strong: direct Express static/serveIndex registrations without auth in server.ts:267-283 and public metrics route at line 718.
- **Exploitability rationale:** Anonymous clients can browse/download FTP files, encryption key files, logs, and metrics. In production this exposes order PDFs, operational logs, public keys/key metadata, endpoint inventory, and potentially tokens/PII in logs.
- **Remediation:** Remove public directory indexing, move generated/sensitive files outside the web root, gate support logs and metrics behind admin auth and network allowlists, and redact logs.

```
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })); app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', ...)); app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', ...)); app.get('/metrics', metrics.serveMetrics())
```

### CANON-SAST-011 - Payment card PANs are stored in full

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `7.5`)
- **Confidence:** 0.87
- **File/Lines:** `models/card.ts; routes/payment.ts` @ `models/card.ts:38-46; routes/payment.ts:21-33`
- **CWE:** CWE-311; CWE-312
- **OWASP:** A02:2021-Cryptographic Failures
- **Evidence quality:** strong: full cardNum model storage in models/card.ts and response-only masking in routes/payment.ts.
- **Exploitability rationale:** The database stores complete card numbers and only masks them when returning API responses. Any SQL injection, DB leak, backup exposure, or operator compromise exposes full PAN data, creating direct PCI-like impact.
- **Remediation:** Do not store PANs. Use payment-provider tokens. If unavoidable, encrypt with managed keys, minimize retention, split duties, and never expose full PAN to application queries unless strictly required.

```
cardNum: { type: DataTypes.INTEGER, validate: { min: 1000000000000000, max: 9999999999999998 } }; displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4)
```

### CANON-SAST-012 - Weak unsalted MD5 password hashing

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** HIGH (security-severity `7.4`)
- **Confidence:** 0.9
- **File/Lines:** `lib/insecurity.ts; models/user.ts` @ `lib/insecurity.ts:43; models/user.ts:74-78`
- **CWE:** CWE-916; CWE-327
- **OWASP:** A02:2021-Cryptographic Failures; A07:2021-Identification and Authentication Failures
- **Evidence quality:** strong: direct MD5 function and model password setter; impact chained to confirmed SQLi findings.
- **Exploitability rationale:** Passwords are stored as fast unsalted MD5 hashes. Confirmed SQL injection and full database access paths make offline cracking practical and fast, enabling account takeover beyond the initial exploit.
- **Remediation:** Migrate passwords to Argon2id or bcrypt with per-password salts and a work factor, implement hash versioning, and rehash on next login or forced reset.

```
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex'); this.setDataValue('password', security.hash(clearTextPassword))
```

### CANON-SAST-013 - Generated user registration can set privileged role

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** CRITICAL (security-severity `9.0`)
- **Confidence:** 0.88
- **File/Lines:** `server.ts; models/user.ts` @ `server.ts:407-421,478-505; models/user.ts:80-99`
- **CWE:** CWE-266; CWE-915
- **OWASP:** A01:2021-Broken Access Control; API3:2023-Broken Object Property Level Authorization
- **Evidence quality:** strong: public POST /api/Users path intentionally allowed in server.ts:361 and middleware in 407-421; generated resource includes User model in 482-505; model role allowlist includes privileged roles.
- **Exploitability rationale:** The public user creation flow is handled by a generated Finale resource, and the User model accepts role values including admin/accounting. The route middleware trims email/password but does not remove role from attacker-supplied request bodies, enabling mass-assignment privilege escalation.
- **Remediation:** Use an explicit registration DTO/allowlist that only accepts email/password/security fields, force role server-side to customer, and separate admin user management behind privileged endpoints.

```
app.post('/api/Users', ...); finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`], excludeAttributes: exclude }); role: { type: DataTypes.STRING, defaultValue: 'customer', validate: { isIn: [['customer', 'deluxe', 'accounting', 'admin']] } }
```

### CANON-SAST-014 - Open redirect allowlist can be bypassed with substring match

- **Type:** SAST
- **Triage:** confirmed
- **Severity:** MEDIUM (security-severity `6.1`)
- **Confidence:** 0.86
- **File/Lines:** `lib/insecurity.ts; routes/redirect.ts` @ `lib/insecurity.ts:135-140; routes/redirect.ts:13-20`
- **CWE:** CWE-601
- **OWASP:** A01:2021-Broken Access Control; A05:2021-Security Misconfiguration
- **Evidence quality:** strong: direct public route registration in server.ts:656 and substring allowlist check in lib/insecurity.ts:138.
- **Exploitability rationale:** The public /redirect route redirects to attacker-controlled to= values if they contain any allowlisted URL as a substring. An attacker can craft a malicious URL that embeds an allowed URL in query/path/userinfo and use the trusted domain as a phishing or token-leak primitive.
- **Remediation:** Parse URLs with the URL API and compare exact scheme, hostname, port, and path against an allowlist. Prefer server-side redirect IDs instead of arbitrary URLs.

```
allowed = allowed || url.includes(allowedUrl); if (security.isRedirectAllowed(toUrl)) { res.redirect(toUrl) }
```

### CANON-SCA-015 - vm2 critical sandbox escapes via juicy-chat-bot are reachable but exploit path depends on library internals

- **Type:** SCA
- **Triage:** needs_review
- **Severity:** HIGH (security-severity `8.0`)
- **Confidence:** 0.72
- **File/Lines:** `routes/chatbot.ts; package.json` @ `routes/chatbot.ts:17,50,73-104,213-243; package.json:158`
- **CWE:** CWE-94; CWE-693
- **OWASP:** A06:2021-Vulnerable and Outdated Components
- **Evidence quality:** moderate: reachability to vulnerable component is clear, but exploitability depends on juicy-chat-bot internals. Related advisories include multiple vm2 GHSAs from the supplied artifact.
- **Exploitability rationale:** The application exposes authenticated chatbot queries to juicy-chat-bot, which pulls vulnerable vm2 versions per SCA. Source evidence confirms user-controlled req.body.query reaches bot.respond, but this audit did not prove that arbitrary attacker JavaScript reaches vm2 in the dependency; therefore this remains a production risk requiring dependency-level validation rather than a confirmed RCE.
- **Remediation:** Upgrade juicy-chat-bot/vm2 to non-vulnerable maintained versions or remove vm2-backed functionality. Add tests or dependency review to prove user input cannot reach vm2 code execution.

```
import Bot from 'juicy-chat-bot'; bot = new Bot(...); const response = await bot.respond(req.body.query, `${user.id}`)
```

### CANON-SCA-016 - marsdb command injection alert lacks a proven user-controlled command sink

- **Type:** SCA
- **Triage:** needs_review
- **Severity:** MEDIUM (security-severity `5.5`)
- **Confidence:** 0.68
- **File/Lines:** `data/mongodb.ts; routes/trackOrder.ts` @ `data/mongodb.ts:7-10; routes/trackOrder.ts:18`
- **CWE:** CWE-77
- **OWASP:** A06:2021-Vulnerable and Outdated Components
- **Evidence quality:** moderate: dependency is used, but supplied advisory details and local code do not establish the exact production command-injection path.
- **Exploitability rationale:** MarsDB is a direct dependency and is used for orders/reviews. A separate source-level NoSQL/$where injection risk exists when challenge mode allows unsanitized IDs, but the SCA command-injection advisory was not tied to a specific reachable command execution sink during this review.
- **Remediation:** Replace MarsDB with a maintained datastore/query layer, remove $where-style dynamic predicates, and validate the advisory-specific vulnerable API against application usage.

```
export const ordersCollection = new MarsDB.Collection('orders'); db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
```

### CANON-SCA-017 - sanitize-html legacy XSS advisories are mitigated in current feedback path but version remains risky

- **Type:** SCA
- **Triage:** needs_review
- **Severity:** MEDIUM (security-severity `5.8`)
- **Confidence:** 0.66
- **File/Lines:** `lib/insecurity.ts; models/feedback.ts; models/user.ts` @ `lib/insecurity.ts:60-69; models/feedback.ts:42-55; models/user.ts:60-71`
- **CWE:** CWE-79
- **OWASP:** A03:2021-Injection; A06:2021-Vulnerable and Outdated Components
- **Evidence quality:** moderate: direct package usage with user content is confirmed, but an end-to-end browser execution payload was not proven in this audit.
- **Exploitability rationale:** sanitize-html 1.4.2 is vulnerable per SCA and is used on user-controlled feedback/user fields. The application recursively re-sanitizes in non-challenge mode, which may reduce simple bypasses, but the dependency is old and source review did not conclusively prove all rendered contexts are safe. This is not marked false positive because production XSS risk remains plausible.
- **Remediation:** Upgrade sanitize-html, define a strict explicit allowlist per field, output-encode by render context, and add browser regression tests for known sanitize-html bypass payloads.

```
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html); export const sanitizeSecure = (html: string): string => { const sanitized = sanitizeHtml(html); ... }
```

### CANON-SCA-018 - crypto-js PBKDF2 advisory is not reachable for application password hashing

- **Type:** SCA
- **Triage:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Confidence:** 0.86
- **File/Lines:** `package-lock.json; routes/order.ts` @ `package-lock.json:6996; routes/order.ts:9,43-45`
- **CWE:** CWE-916
- **OWASP:** A06:2021-Vulnerable and Outdated Components
- **Evidence quality:** strong for false-positive disposition: reachable pdfkit usage is PDF generation, not PBKDF2-based credential protection. The real weak password hashing issue is separately confirmed as CANON-SAST-012.
- **Exploitability rationale:** The advisory is for crypto-js PBKDF2 weakness through pdfkit. Source usage of pdfkit only generates order PDFs; application password hashing uses Node crypto MD5 in lib/insecurity.ts, not crypto-js PBKDF2. No source-code path was found where attacker-controlled password/key derivation relies on crypto-js PBKDF2.
- **Remediation:** Keep dependency updated as hygiene, but prioritize replacing MD5 password hashing. Do not track this advisory as an exploitable production PBKDF2 issue unless future code uses crypto-js PBKDF2 for secrets.

```
import PDFDocument from 'pdfkit'; const doc = new PDFDocument()
```

### CANON-SCA-019 - ReDoS and resource-exhaustion-only dependency alerts lack demonstrated business-impact attack path

- **Type:** SCA
- **Triage:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Confidence:** 0.8
- **File/Lines:** `artifacts/github_security_mcp_findings.json` @ `536-559,701-772,1278-1440`
- **CWE:** CWE-400; CWE-1333
- **OWASP:** A06:2021-Vulnerable and Outdated Components
- **Evidence quality:** adequate for false-positive/informational grouping: alerts are dependency-only and no confirmed reachable high-impact sink was found in source review.
- **Exploitability rationale:** The supplied alerts primarily describe DoS/ReDoS in transitive tooling or parser packages. This review did not identify a source-code path with attacker-controlled input, measurable production impact, and no platform-level mitigation. Per audit hard exclusions, DoS without clear significant business impact is not prioritized as an actionable vulnerability.
- **Remediation:** Upgrade dependencies during normal maintenance, but do not block production release on these grouped alerts absent a demonstrated request path and impact model.

```
Alerts include braces, moment, sanitize-html ReDoS, http-cache-semantics, parseuri, micromatch and similar resource-exhaustion advisories.
```

