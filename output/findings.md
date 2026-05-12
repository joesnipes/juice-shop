# Standardized Vulnerability Findings Report

- **Scan ID:** prod-audit-2026-05-11
- **Scan Date:** 2026-05-11T00:00:00Z
- **Commit:** `381fd83a484942d8a850f0187984a65ac34f920a`
- **Mode:** full
- **Source Canonical File:** `/Users/barrydawson/Desktop/repo/juice-shop/output/canonical-security-findings.json`

## Summary

- **Total findings:** 21
- **By status:** confirmed=15, false_positive=5, needs_review=1
- **By severity:** CRITICAL=6, HIGH=7, MEDIUM=2, LOW=1, INFO=5

## Top Actionable Findings
- JS-PROD-001: unauthenticated SQL injection in login enables auth bypass.
- JS-PROD-003: hardcoded JWT signing key plus vulnerable JWT library enables token forgery.
- JS-PROD-005: public user registration can mass-assign privileged roles.
- JS-PROD-006: public MarsDB $where injection reaches a vulnerable command-injection sink.
- JS-PROD-004: public key/log/PDF/metrics routes expose secrets and PII.

## Detailed Findings

### JS-PROD-001 — SQL Injection / Authentication Bypass
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.8`)
- **Location:** `routes/login.ts`:34
- **CWE:** CWE-89  
- **OWASP:** A03:2021-Injection  
- **Source IDs:** codeql:316
- **Snippet:** `models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })`
- **Exploit Rationale:** Unauthenticated request body values are interpolated directly into a login SQL statement before authentication. An attacker can close the email string and alter the WHERE clause to authenticate as another user or extract user records.
- **Recommended Fix:** Use parameterized Sequelize replacements/bind variables for email and password hash, and add centralized schema validation. Replace MD5 password verification with Argon2id/bcrypt comparison.

### JS-PROD-002 — SQL Injection / Data Exfiltration
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.1`)
- **Location:** `routes/search.ts`:23
- **CWE:** CWE-89  
- **OWASP:** A03:2021-Injection  
- **Source IDs:** codeql:317
- **Snippet:** `models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)`
- **Exploit Rationale:** The public search parameter is length-limited but not parameterized or escaped. UNION-based payloads can read other tables such as Users or sqlite_master.
- **Recommended Fix:** Use parameterized LIKE clauses with replacements, escape wildcard characters intentionally, and return only product DTO fields.

### JS-PROD-003 — JWT Forgery / Hardcoded Signing Key
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.8`)
- **Location:** `lib/insecurity.ts`:23
- **CWE:** CWE-321  
- **OWASP:** A02:2021-Cryptographic Failures  
- **Source IDs:** codeql:318, dependabot:1, dependabot:10
- **Snippet:** `const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'; export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })`
- **Exploit Rationale:** The JWT signing private key is embedded in source, and jsonwebtoken 0.4.0 is affected by verification-bypass advisories. Since role and user id are trusted from JWTs in authorization helpers, disclosure of source or key material enables minting admin/accounting tokens.
- **Recommended Fix:** Move signing keys to a secret manager, rotate keys, upgrade jsonwebtoken to a maintained version, enforce algorithms/issuer/audience, and avoid trusting client token role claims without server-side authorization checks.

### JS-PROD-004 — Sensitive File and Operational Data Exposure
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.0`)
- **Location:** `server.ts`:277
- **CWE:** CWE-200  
- **OWASP:** A01:2021-Broken Access Control  
- **Source IDs:** codeql:319
- **Snippet:** `app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' })); app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })); app.get('/metrics', metrics.serveMetrics())`
- **Exploit Rationale:** Unauthenticated directory listings and static routes expose encryption keys, logs, order PDFs under /ftp, API documentation, and metrics. These assets can contain secrets, PII, tokens, endpoint inventory, and operational telemetry.
- **Recommended Fix:** Remove public directory listings, serve private files only through authorized controllers, restrict metrics/docs to internal networks or auth, and move key material outside the web root.

### JS-PROD-005 — Mass Assignment Privilege Escalation
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.0`)
- **Location:** `server.ts`:500
- **CWE:** CWE-915  
- **OWASP:** A01:2021-Broken Access Control  
- **Source IDs:** codeql:320
- **Snippet:** `finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`], excludeAttributes: exclude, pagination: false })`
- **Exploit Rationale:** Public POST /api/Users reaches the generated User resource. The User model includes writable role, deluxeToken, totpSecret, isActive, and profileImage fields, and registration middleware only trims email/password fields rather than allowlisting safe fields.
- **Recommended Fix:** Replace generated public create with an explicit registration controller and DTO allowlist; force role=customer server-side and reject privileged fields.

### JS-PROD-006 — NoSQL Server-Side JavaScript Injection / Command Injection
- **Status:** confirmed
- **Severity:** CRITICAL (security-severity `9.8`)
- **Location:** `routes/trackOrder.ts`:18
- **CWE:** CWE-94  
- **OWASP:** A03:2021-Injection  
- **Source IDs:** codeql:328, dependabot:5
- **Snippet:** `db.ordersCollection.find({ $where: `this.orderId === '${id}'` })`
- **Exploit Rationale:** MarsDB evaluates $where selectors through an unsafe Function constructor. The public order tracking route builds the $where JavaScript expression from a route parameter, enabling code injection when unsafe challenge mode is enabled or equivalent production config is deployed.
- **Recommended Fix:** Remove $where entirely; query by structured fields, e.g. { orderId: id }, validate id with a strict order-id regex, and replace MarsDB or upgrade to a maintained safe datastore.

### JS-PROD-007 — Unsafe File Upload Parsing: Zip Slip, XXE, YAML Bomb
- **Status:** confirmed
- **Severity:** HIGH (security-severity `8.6`)
- **Location:** `routes/fileUpload.ts`:42
- **CWE:** CWE-22  
- **OWASP:** A05:2021-Security Misconfiguration  
- **Source IDs:** codeql:329
- **Snippet:** `const absolutePath = path.resolve('uploads/complaints/' + fileName); entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName)); libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true }); yaml.load(data)`
- **Exploit Rationale:** The public /file-upload route processes ZIP, XML, and YAML in memory. ZIP entry paths are joined without canonical base-directory enforcement; XML enables entity expansion; YAML load accepts complex input. These can overwrite files, disclose local files, or exhaust resources.
- **Recommended Fix:** Require authentication/authorization, extract archives with canonical path checks under a dedicated non-web directory, disable XML external entities, use safe YAML schema/limits, and process uploads in an isolated worker with quotas.

### JS-PROD-008 — Insecure Direct Object Reference on Basket
- **Status:** confirmed
- **Severity:** HIGH (security-severity `8.1`)
- **Location:** `routes/basket.ts`:19
- **CWE:** CWE-639  
- **OWASP:** A01:2021-Broken Access Control  
- **Source IDs:** codeql:321
- **Snippet:** `const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })`
- **Exploit Rationale:** Authenticated users can request /rest/basket/:id and the route fetches solely by URL id, not by the current user's basket/UserId. Checkout similarly loads the basket by id before charging the current user.
- **Recommended Fix:** Bind basket queries to the authenticated user, e.g. where { id, UserId: currentUser.id }, and reject mismatches before reading or checking out.

### JS-PROD-009 — Server-Side Request Forgery
- **Status:** confirmed
- **Severity:** HIGH (security-severity `8.0`)
- **Location:** `routes/profileImageUrlUpload.ts`:24
- **CWE:** CWE-918  
- **OWASP:** A10:2021-Server-Side Request Forgery  
- **Source IDs:** codeql:322
- **Snippet:** `const response = await fetch(url)`
- **Exploit Rationale:** An authenticated user controls imageUrl and the server fetches it without scheme/host allowlisting, DNS pinning, private-IP blocking, redirect restrictions, timeout, or response-size limit. This can reach internal services or cloud metadata endpoints.
- **Recommended Fix:** Allowlist image hosts or require direct file upload; block private/link-local/metadata IP ranges after DNS resolution, restrict redirects, and enforce timeouts and byte limits.

### JS-PROD-010 — Plaintext Payment Card Storage
- **Status:** confirmed
- **Severity:** HIGH (security-severity `8.0`)
- **Location:** `models/card.ts`:39
- **CWE:** CWE-311  
- **OWASP:** A02:2021-Cryptographic Failures  
- **Source IDs:** codeql:323
- **Snippet:** `cardNum: { type: DataTypes.INTEGER, validate: { isInt: true, min: 1000000000000000, max: 9999999999999998 } }`
- **Exploit Rationale:** The Cards table stores full PAN-equivalent card numbers as application data. Response-time masking in routes/payment.ts does not protect at-rest data or reduce PCI exposure after database compromise.
- **Recommended Fix:** Do not store card numbers. Use a PCI-compliant payment processor/tokenization vault and store only token, brand, and last four digits.

### JS-PROD-011 — Weak Password Hashing
- **Status:** confirmed
- **Severity:** HIGH (security-severity `7.8`)
- **Location:** `lib/insecurity.ts`:43
- **CWE:** CWE-916  
- **OWASP:** A02:2021-Cryptographic Failures  
- **Source IDs:** codeql:324
- **Snippet:** `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')`
- **Exploit Rationale:** User passwords are stored as unsalted MD5 hashes via models/user.ts line 77. Any database disclosure enables rapid offline cracking and credential stuffing.
- **Recommended Fix:** Use Argon2id or bcrypt with per-password salts and calibrated work factors; migrate existing hashes on next login.

### JS-PROD-012 — Sensitive Field Disclosure
- **Status:** confirmed
- **Severity:** HIGH (security-severity `7.5`)
- **Location:** `routes/currentUser.ts`:29
- **CWE:** CWE-200  
- **OWASP:** A01:2021-Broken Access Control  
- **Source IDs:** codeql:325
- **Snippet:** `for (const field of requestedFields) { if (user?.data[field as keyof typeof user.data] !== undefined) { baseUser[field] = user?.data[field as keyof typeof user.data] } }`
- **Exploit Rationale:** Authenticated users can request arbitrary fields from their in-memory user object. The object is populated from SELECT * at login and includes password hash, role, deluxeToken, isActive, and TOTP secret.
- **Recommended Fix:** Ignore caller-selected fields for sensitive objects; return a fixed DTO allowlist and never cache password/TOTP secrets in authenticated session state.

### JS-PROD-013 — Insecure Cookie Attributes / CSRF Exposure
- **Status:** confirmed
- **Severity:** MEDIUM (security-severity `6.5`)
- **Location:** `lib/insecurity.ts`:195
- **CWE:** CWE-614  
- **OWASP:** A05:2021-Security Misconfiguration  
- **Source IDs:** codeql:327
- **Snippet:** `res.cookie('token', token)`
- **Exploit Rationale:** JWT cookies are set without HttpOnly, Secure, or SameSite. Combined with permissive CORS in server.ts lines 181-182 and cookie-authenticated state-changing routes, token theft and cross-site request abuse are plausible.
- **Recommended Fix:** Set HttpOnly, Secure, SameSite=Lax/Strict, enforce HTTPS/HSTS, restrict CORS origins, and add CSRF tokens for cookie-authenticated state changes.

### JS-PROD-014 — Open Redirect
- **Status:** confirmed
- **Severity:** LOW (security-severity `3.1`)
- **Location:** `lib/insecurity.ts`:138
- **CWE:** CWE-601  
- **OWASP:** A01:2021-Broken Access Control  
- **Source IDs:** codeql:326
- **Snippet:** `allowed = allowed || url.includes(allowedUrl)`
- **Exploit Rationale:** The redirect allowlist checks substrings rather than exact origin/path. A malicious domain containing an allowed URL as a substring can pass and receive the redirect.
- **Recommended Fix:** Parse URLs and compare exact scheme, host, port, and approved path prefixes; prefer server-side route names over arbitrary redirect URLs.

### JS-PROD-015 — Vulnerable HTML Sanitizer Allows XSS Bypass
- **Status:** confirmed
- **Severity:** MEDIUM (security-severity `6.1`)
- **Location:** `lib/insecurity.ts`:60
- **CWE:** CWE-79  
- **OWASP:** A03:2021-Injection  
- **Source IDs:** dependabot:2, dependabot:3
- **Snippet:** `export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)`
- **Exploit Rationale:** sanitize-html 1.4.2 is directly used for user-controlled feedback/user fields and has XSS bypass advisories. Tests demonstrate malformed nested tags can survive sanitization as an iframe with javascript: URL.
- **Recommended Fix:** Upgrade sanitize-html to the latest 2.x release, add regression tests for known bypasses, and rely on contextual output encoding in the Angular frontend.

### JS-PROD-016 — JWT Legacy Key Type / Algorithm Enforcement Ambiguity
- **Status:** needs_review
- **Severity:** HIGH (security-severity `7.5`)
- **Location:** `lib/insecurity.ts`:191
- **CWE:** CWE-327  
- **OWASP:** A02:2021-Cryptographic Failures  
- **Source IDs:** dependabot:8
- **Snippet:** `jwt.verify(token, publicKey, (err: Error | null, decoded: any) => { ... })`
- **Exploit Rationale:** The vulnerable jsonwebtoken version is reachable in token verification and algorithms are not explicitly allowed. Exploitability of GHSA-8cf7-32gw-wr33 depends on accepted key types and runtime parsing of the configured RSA public key, so it requires dynamic verification.
- **Recommended Fix:** Upgrade jsonwebtoken and pass algorithms: ['RS256'] plus issuer/audience validation. Add negative tests for none/HS256/legacy-key tokens.

### JS-PROD-017 — sanitize-html transformTags XSS advisory
- **Status:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Location:** `lib/insecurity.ts`:60
- **CWE:** CWE-79  
- **OWASP:** A03:2021-Injection  
- **Source IDs:** dependabot:18
- **Snippet:** `sanitizeHtmlLib(html)`
- **Exploit Rationale:** The specific GHSA-qhxp-v273-g94h advisory requires use of the custom transformTags option. Repository usage calls sanitizeHtmlLib without transformTags.
- **Recommended Fix:** No action for this advisory; keep the general sanitizer upgrade tracked by JS-PROD-015.

### JS-PROD-018 — express-jwt jwks-rsa algorithm bypass advisory
- **Status:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Location:** `lib/insecurity.ts`:54
- **CWE:** CWE-287  
- **OWASP:** A07:2021-Identification and Authentication Failures  
- **Source IDs:** dependabot:4
- **Snippet:** `export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)`
- **Exploit Rationale:** The cited GHSA-6g6m-m6h5-w9gf exploit condition involves jwks-rsa key retrieval. This application passes a static secret/public key and does not use jwks-rsa. JWT risk remains covered by JS-PROD-003/016.
- **Recommended Fix:** No action for this exact advisory beyond upgrading auth libraries as part of JS-PROD-003.

### JS-PROD-019 — sanitize-html option-specific advisories not reachable
- **Status:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Location:** `lib/insecurity.ts`:60
- **CWE:** CWE-20  
- **OWASP:** A06:2021-Vulnerable and Outdated Components  
- **Source IDs:** dependabot:6, dependabot:7, dependabot:11
- **Snippet:** `sanitizeHtmlLib(html)`
- **Exploit Rationale:** These advisories require allowedIframeHostnames/allowIframeRelativeUrls or style attribute configurations. Repository usage does not configure those options.
- **Recommended Fix:** No action for these exact advisories; general package upgrade is still recommended in JS-PROD-015.

### JS-PROD-020 — jsonwebtoken key retrieval function advisory
- **Status:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Location:** `lib/insecurity.ts`:191
- **CWE:** CWE-287  
- **OWASP:** A07:2021-Identification and Authentication Failures  
- **Source IDs:** dependabot:9
- **Snippet:** `jwt.verify(token, publicKey, ...)`
- **Exploit Rationale:** GHSA-hjrf-2m68-5959 depends on a poorly implemented key retrieval function. This code passes a static publicKey, not a retrieval callback.
- **Recommended Fix:** No action for this exact advisory; upgrade jsonwebtoken for the confirmed advisories.

### JS-PROD-021 — Dependency Denial-of-Service advisories excluded from prioritized findings
- **Status:** false_positive
- **Severity:** INFO (security-severity `0.0`)
- **Location:** `server.ts`:681
- **CWE:** CWE-400  
- **OWASP:** A06:2021-Vulnerable and Outdated Components  
- **Source IDs:** dependabot:12, dependabot:13, dependabot:14, dependabot:15, dependabot:16, dependabot:17, dependabot:19, dependabot:20, dependabot:21, dependabot:22
- **Snippet:** `const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } }); app.get('/metrics', metrics.serveMetrics())`
- **Exploit Rationale:** Multer, file-type, socket.io, and sanitize-html ReDoS advisories are dependency DoS conditions. Although some packages are reachable, the review policy hard-excludes DoS/resource-exhaustion findings without demonstrated significant business impact or a non-DoS security consequence.
- **Recommended Fix:** Upgrade dependencies during maintenance, but do not prioritize as exploitable security findings under the stated policy.

