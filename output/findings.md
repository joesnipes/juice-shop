# Security Vulnerability Report — OWASP Juice Shop

**Repository:** `joesnipes/juice-shop`  
**Report Date:** 2026-05-11  
**Scan Tool:** Barrys Special AI Vuln Audit v1.0.0  
**Threat Model:** [output/threat-model.md](./threat-model.md)  
**Source Audit:** [output/audit-findings.json](./audit-findings.json)

---

## Executive Summary

This security audit of the OWASP Juice Shop codebase identified **47 security findings** across the application stack. The audit was conducted treating the codebase as a production e-commerce application, disregarding its intentional training purpose.

### Key Statistics

- **Total Findings:** 47
- **Confirmed Vulnerabilities:** 44
- **Needs Review:** 2
- **False Positives:** 1

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| **Critical** | 9 | 19.1% |
| **High** | 24 | 51.1% |
| **Medium** | 11 | 23.4% |
| **Low** | 3 | 6.4% |

### OWASP Top 10 2021 Coverage

| Category | Count |
|----------|-------|
| A01: Broken Access Control | 11 |
| A02: Cryptographic Failures | 5 |
| A03: Injection | 14 |
| A04: Insecure Design | 2 |
| A05: Security Misconfiguration | 7 |
| A06: Vulnerable and Outdated Components | 5 |
| A07: Identification and Authentication Failures | 5 |
| A08: Software and Data Integrity Failures | 2 |
| A10: Server-Side Request Forgery (SSRF) | 1 |

### Critical Risk Summary

The application contains **9 critical-severity vulnerabilities** that enable:

1. **Complete authentication bypass** via SQL injection (JS-AUDIT-001)
2. **Full database exfiltration** via UNION-based SQL injection (JS-AUDIT-002)
3. **JWT forgery** via hard-coded RSA private key (JS-AUDIT-003)
4. **Remote code execution** via multiple vectors:
   - Server-side template injection (JS-AUDIT-009)
   - Unsafe code evaluation in B2B orders (JS-AUDIT-010)
   - NoSQL injection leading to RCE (JS-AUDIT-043)
5. **Privilege escalation** via mass-assignment (JS-AUDIT-014)
6. **Password compromise** via CSRF + weak password change flow (JS-AUDIT-025)

**Immediate Action Required:** The combination of SQL injection, JWT forgery, and RCE vulnerabilities allows an unauthenticated attacker to achieve full system compromise within minutes.

---

## Detailed Findings

### Critical Severity (9 findings)

#### JS-AUDIT-001: SQL Injection / Authentication Bypass in login endpoint

**Severity:** Critical (CVSS 9.8)  
**Status:** Confirmed  
**CWE:** CWE-89 (SQL Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/login.ts:34`

**Vulnerable Code:**
```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**Exploitation:**
POST /rest/user/login passes req.body.email directly into a raw template literal SQL query. Sending email=`' OR 1=1--` is a textbook tautology bypass that returns the first row (the admin) and the route then issues a JWT for that user via security.authorize(). No parameterization, no escaping, no allow-list. The result is full admin takeover from an entirely unauthenticated request.

**Proof of Concept:**
```http
POST /rest/user/login
Content-Type: application/json

{"email":"' OR 1=1--","password":"x"}
```

**Expected Response:** JSON containing `{ authentication: { token: <JWT for admin@juice-sh.op>, bid: ... } }`

**Recommended Fix:**
Use parameterized queries via Sequelize replacements/bind (e.g. UserModel.findOne({ where: { email, password: hashedPw } })) and migrate password handling to bcrypt/argon2. Never interpolate untrusted strings into raw SQL.

**GitHub Alerts:** [#45](https://github.com/joesnipes/juice-shop/security/code-scanning/45), [#332](https://github.com/joesnipes/juice-shop/security/code-scanning/332), [#316](https://github.com/joesnipes/juice-shop/security/code-scanning/316), [#262](https://github.com/joesnipes/juice-shop/security/code-scanning/262)

---

#### JS-AUDIT-002: UNION SQL Injection in unauthenticated product search

**Severity:** Critical (CVSS 9.1)  
**Status:** Confirmed  
**CWE:** CWE-89 (SQL Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/search.ts:23`

**Vulnerable Code:**
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**Exploitation:**
GET /rest/products/search?q= is reachable without authentication and concatenates the query parameter directly into raw SQL. Because the database is SQLite the attacker can append a UNION SELECT statement to exfiltrate Users (emails, MD5 password hashes) and sqlite_master (table schemas). The route code itself solves a 'unionSqlInjectionChallenge' by detecting if user rows leak via this primitive, which proves it is exploitable end-to-end.

**Proof of Concept:**
```http
GET /rest/products/search?q=')) UNION SELECT id,email,password,role,1,2,3,4,5 FROM Users--
```

**Expected Response:** Product list response includes every user's email and md5 password hash.

**Recommended Fix:**
Use Sequelize replacements/bind (`:criteria`) or ProductModel.findAll({ where: { [Op.or]: [{ name: { [Op.like]: q } }, ...] } }). The 200-byte truncation does not prevent injection.

**GitHub Alerts:** [#46](https://github.com/joesnipes/juice-shop/security/code-scanning/46), [#333](https://github.com/joesnipes/juice-shop/security/code-scanning/333), [#317](https://github.com/joesnipes/juice-shop/security/code-scanning/317), [#263](https://github.com/joesnipes/juice-shop/security/code-scanning/263)

---

#### JS-AUDIT-003: Hard-coded RSA private key used to sign all JWTs

**Severity:** Critical (CVSS 9.8)  
**Status:** Confirmed  
**CWE:** CWE-798 (Hard-coded Credentials)  
**OWASP Top 10:** A02:2021-Cryptographic Failures

**Location:** `lib/insecurity.ts:23`

**Vulnerable Code:**
```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8...\r\n-----END RSA PRIVATE KEY-----'
```

**Exploitation:**
The full 1024-bit RSA private key used by security.authorize() to sign all session JWTs (RS256) is checked into source. Anyone who reads the public GitHub repo can mint a JWT with `data.role="admin"` for any user id and bypass every authentication and authorization check in the application. The matching `encryptionkeys/jwt.pub` is the corresponding public key used for verification. This is the single most catastrophic finding.

**Proof of Concept:**
```javascript
jwt.sign({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } }, privateKey, { algorithm: 'RS256', expiresIn: '6h' })
```

**Recommended Fix:**
Generate a fresh RSA-2048 (or Ed25519) key pair at deploy time, store the private key in a secret manager (KMS/Vault/SSM), rotate immediately, and revoke any tokens minted under the leaked key.

**GitHub Alerts:** [#334](https://github.com/joesnipes/juice-shop/security/code-scanning/334), [#318](https://github.com/joesnipes/juice-shop/security/code-scanning/318), [#264](https://github.com/joesnipes/juice-shop/security/code-scanning/264), [#247](https://github.com/joesnipes/juice-shop/security/code-scanning/247)

---

#### JS-AUDIT-006: express-jwt 0.1.3 + jsonwebtoken 0.4.0 — alg:none / verification bypass

**Severity:** Critical (CVSS 9.1)  
**Status:** Confirmed  
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)  
**OWASP Top 10:** A06:2021-Vulnerable and Outdated Components

**Location:** `lib/insecurity.ts:54`

**Vulnerable Code:**
```typescript
export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
```

**Exploitation:**
package.json pins express-jwt@0.1.3 and jsonwebtoken@0.4.0 — both are wildly out of date. express-jwt prior to 5.3.3 (GHSA-6cwn-77pq-3fpx) does not enforce `algorithms`, so an attacker can craft a token with header `alg:none` (no signature) and bypass auth on every middleware-protected route. jsonwebtoken<=4.2.1 has the original verification-bypass CVE. Combined with the hardcoded public key being downloadable from /encryptionkeys/jwt.pub, the attacker can also forge HS256 tokens signed with the public key as a symmetric secret.

**Recommended Fix:**
Upgrade express-jwt to >=8.x (passing `algorithms: ['RS256']`) and jsonwebtoken to >=9.x. Pin algorithm explicitly.

**GitHub Alerts:** [Dependabot #4](https://github.com/joesnipes/juice-shop/security/dependabot/4), [#1](https://github.com/joesnipes/juice-shop/security/dependabot/1), [#10](https://github.com/joesnipes/juice-shop/security/dependabot/10), [#9](https://github.com/joesnipes/juice-shop/security/dependabot/9), [#8](https://github.com/joesnipes/juice-shop/security/dependabot/8)

---

#### JS-AUDIT-009: Pug SSTI + eval() on username + user-controlled CSP -> RCE/XSS

**Severity:** Critical (CVSS 9.6)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/userProfile.ts:62`

**Vulnerable Code:**
```typescript
username = eval(code) // eslint-disable-line no-eval  (code is parsed out of #{...} in user.username)
```

**Exploitation:**
The route reads the logged-in user's own username from the DB. If it matches `#{...}` the inner expression is passed to JavaScript `eval()` *server-side*. Any authenticated user can therefore execute arbitrary Node.js code in the server process by updating their own username via PATCH /api/Users/:id or POST /profile. Additionally, the `profileImage` field is interpolated unsanitised into a Content-Security-Policy header (line 88), letting the same user weaken/override CSP and achieve persistent XSS. This is full server-side RCE.

**Proof of Concept:**
```http
# Step 1: Set malicious username
PATCH /api/Users/1
{"username":"#{require('child_process').execSync('id').toString()}"}

# Step 2: Trigger execution
GET /profile
```

**Recommended Fix:**
Never eval user data. Render usernames with HTML-escape only (Handlebars/Angular auto-escape). Build CSP from a static template, never interpolate user input.

---

#### JS-AUDIT-010: B2B order safeEval (notevil) used inside vm with attacker-controlled body -> RCE/DoS

**Severity:** Critical (CVSS 9.1)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/b2bOrder.ts:23`

**Vulnerable Code:**
```typescript
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
```

**Exploitation:**
`notevil` (1.3.3) has had multiple documented sandbox escapes (e.g. accessing constructor chains via prototype lookups to reach `Function('return process')()`). It is not a security boundary. With the hardcoded RSA key (JS-AUDIT-003) an attacker can mint a B2B token, then POST {orderLinesData: "<payload>"} to /b2b/v2/orders and obtain RCE. Even without escape, infinite-loop / billion-laughs style payloads trigger reliable DoS (the code itself acknowledges this with rceOccupyChallenge).

**Recommended Fix:**
Do not evaluate user-supplied code. Accept structured JSON only and validate against a schema. If business logic genuinely requires expressions, run them in a separate sandboxed worker with strict CPU/memory budgets — preferably as data, not code.

---

#### JS-AUDIT-014: Admin role mass-assignment on POST /api/Users

**Severity:** Critical (CVSS 9.8)  
**Status:** Confirmed  
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)  
**OWASP Top 10:** A04:2021-Insecure Design

**Location:** `server.ts:419`

**Vulnerable Code:**
```typescript
app.post('/api/Users', verify.registerAdminChallenge())
// finale auto-CRUD permits any field in req.body to be persisted, including 'role'
```

**Exploitation:**
Registration is unauthenticated and goes through finale auto-CRUD. The model permits role in {customer, deluxe, accounting, admin}, and there is no whitelist of registration-permitted attributes. Posting {email, password, role:'admin'} creates an admin account directly. server.ts:407-419 even includes `registerAdminChallenge()` to *detect* this exploitation, confirming the route is exploitable.

**Proof of Concept:**
```http
POST /api/Users
Content-Type: application/json

{"email":"a@b.c","password":"x","passwordRepeat":"x","role":"admin"}
```

**Recommended Fix:**
Whitelist fields on registration (email, password only). Hardcode role='customer' server-side. Use finale's `excludeAttributes` for write paths or wrap with a dedicated registration handler.

**GitHub Alerts:** [#336](https://github.com/joesnipes/juice-shop/security/code-scanning/336), [#320](https://github.com/joesnipes/juice-shop/security/code-scanning/320)

---

#### JS-AUDIT-025: Conditional current-password check + CSRF + password-in-query in changePassword

**Severity:** Critical (CVSS 9.6)  
**Status:** Confirmed  
**CWE:** CWE-620 (Unverified Password Change)  
**OWASP Top 10:** A07:2021-Identification and Authentication Failures

**Location:** `routes/changePassword.ts:39`

**Vulnerable Code:**
```typescript
if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) { ... }
... await user.update({ password: newPasswordInString })
```

**Exploitation:**
If `current` is absent the check is *skipped entirely*, allowing any session holder to set a new password without proving knowledge of the old one. The route is GET (line uses req.query — confirmed by CodeQL alerts 14-16 'js/sensitive-get-query'), so any cross-origin `<img src=/rest/user/change-password?new=hacked&repeat=hacked>` performs the change with the victim's ambient cookie token. No CSRF protection. Passwords also end up in browser history, proxies, and access logs.

**Recommended Fix:**
Change method to POST/PATCH, require current password, add CSRF protection (SameSite=strict cookies + CSRF token / double-submit). Read password from body, never the query string.

**GitHub Alerts:** [#14](https://github.com/joesnipes/juice-shop/security/code-scanning/14), [#15](https://github.com/joesnipes/juice-shop/security/code-scanning/15), [#16](https://github.com/joesnipes/juice-shop/security/code-scanning/16), [#40](https://github.com/joesnipes/juice-shop/security/code-scanning/40)

---

#### JS-AUDIT-043: marsdb — unmaintained, $where -> Function() command injection

**Severity:** Critical (CVSS 9.0)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A06:2021-Vulnerable and Outdated Components

**Location:** `data/mongodb.ts:7`

**Vulnerable Code:**
```typescript
import * as MarsDB from 'marsdb'
```

**Exploitation:**
Dependabot alert 5 'Command Injection in marsdb' — `DocumentMatcher` selectors on $where pass through `new Function(...)`. With no maintainer fix, the only mitigation is to eliminate $where usage (currently used in trackOrder/showProductReviews/likeProductReviews paths).

**Recommended Fix:**
Replace marsdb. Eliminate $where. Migrate review/order data to Sequelize/SQLite.

**GitHub Alerts:** [Dependabot #5](https://github.com/joesnipes/juice-shop/security/dependabot/5)

---

### High Severity (24 findings)

#### JS-AUDIT-004: MD5 used as password hash with no salt

**Severity:** High (CVSS 8.2)  
**Status:** Confirmed  
**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)  
**OWASP Top 10:** A02:2021-Cryptographic Failures

**Location:** `lib/insecurity.ts:43`

**Vulnerable Code:**
```typescript
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

**Exploitation:**
User passwords are stored as bare MD5 hashes (no salt, no key-stretching). MD5 is broken for password hashing — modern GPUs hash hundreds of GH/s. Combined with the UNION SQLi (JS-AUDIT-002), every password becomes trivially crackable by rainbow tables / hashcat. Even without SQLi, the hashing function is used in 'authorize'-equivalent flows server-side.

**Proof of Concept:**
```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

**Recommended Fix:**
Switch to bcrypt (cost >= 12), argon2id, or scrypt with per-user salt. Rehash on next login.

**GitHub Alerts:** [#1](https://github.com/joesnipes/juice-shop/security/code-scanning/1)

---

#### JS-AUDIT-005: Hard-coded HMAC secret used for security-answer verification

**Severity:** High (CVSS 8.1)  
**Status:** Confirmed  
**CWE:** CWE-798 (Hard-coded Credentials)  
**OWASP Top 10:** A02:2021-Cryptographic Failures

**Location:** `lib/insecurity.ts:44`

**Vulnerable Code:**
```typescript
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
```

**Exploitation:**
Security-answer 'hashes' in SecurityAnswers table are HMAC-SHA256 with a static, public secret. With the secret in the repo any attacker who reads the SecurityAnswers row can precompute HMACs offline (or just submit known answers) to reset a victim's password via /rest/user/reset-password (routes/resetPassword.ts:41 compares `security.hmac(answer) === data.answer`). It also disables HMAC's collision resistance assumption.

**Recommended Fix:**
Move secret to env/secret manager; rotate. Long-term, do not rely on security questions; require a verified-email token flow instead.

---

#### JS-AUDIT-007: denyAll() relies on Math.random() as JWT verification secret

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-330 (Use of Insufficiently Random Values)  
**OWASP Top 10:** A07:2021-Identification and Authentication Failures

**Location:** `lib/insecurity.ts:55`

**Vulnerable Code:**
```typescript
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
```

**Exploitation:**
`denyAll` is wired into critical routes (PUT/DELETE /api/Users/:id, DELETE /api/Products/:id, /api/Challenges, /api/Hints, /api/SecurityQuestions, /api/Recycles/:id, etc.). Because of the express-jwt 0.1.3 alg:none bug above, a token with `alg:none` would skip secret validation entirely. Even without that, Math.random() is non-cryptographic and predictable; an attacker who can guess one secret can mint tokens. The bigger issue is that 'deny all' is implemented as 'verify with a random secret' instead of a hard 403, which is fundamentally wrong.

**Recommended Fix:**
Replace with an explicit middleware that always returns 403: `(req,res)=>res.status(403).end()`. Do not rely on the JWT layer at all.

**GitHub Alerts:** [#6](https://github.com/joesnipes/juice-shop/security/code-scanning/6)

---

#### JS-AUDIT-008: Open-redirect allowlist uses substring match (url.includes)

**Severity:** High (CVSS 7.4)  
**Status:** Confirmed  
**CWE:** CWE-601 (URL Redirection to Untrusted Site)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `lib/insecurity.ts:138`

**Vulnerable Code:**
```typescript
allowed = allowed || url.includes(allowedUrl)
```

**Exploitation:**
isRedirectAllowed() returns true if the *attacker-supplied URL* contains an allowlisted string anywhere. Therefore `/redirect?to=https://evil.example.com/?x=https://github.com/juice-shop/juice-shop` passes the check and the server returns a 302 to evil.example.com. Used for phishing / credential harvesting / token exfil. CodeQL (alert 3) confirms.

**Proof of Concept:**
```http
GET /redirect?to=https://evil.example.com/login?ref=https://github.com/juice-shop/juice-shop
```

**Recommended Fix:**
Parse with `new URL(toUrl)` and compare `url.origin` against an allowlist of full origins; or use signed redirect tokens.

**GitHub Alerts:** [#3](https://github.com/joesnipes/juice-shop/security/code-scanning/3), [#17](https://github.com/joesnipes/juice-shop/security/code-scanning/17)

---

#### JS-AUDIT-011: Zip-Slip / unbounded extraction in /file-upload (.zip handler)

**Severity:** High (CVSS 8.1)  
**Status:** Confirmed  
**CWE:** CWE-22 (Path Traversal)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/fileUpload.ts:44`

**Vulnerable Code:**
```typescript
if (absolutePath.includes(path.resolve('.'))) { entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName) ...) }
```

**Exploitation:**
The check `absolutePath.includes(path.resolve('.'))` only ensures the resolved path *contains* the project root; it does NOT prevent traversal. An entry path like `../../../../../<projectRoot>/etc/whatever` would still satisfy the check on some layouts. Even if traversal were blocked, the stream destination uses the raw `fileName` from the zip entry (line 45) without sanitisation, so symlink overwrite of files under uploads/complaints is possible. There is also no decompressed-size limit (zip-bomb DoS).

**Recommended Fix:**
Resolve each entry path with path.resolve(extractRoot, fileName) then require startsWith(extractRoot + path.sep). Enforce per-entry and total decompressed-size limits. Reject symlinks and absolute paths.

**GitHub Alerts:** [#38](https://github.com/joesnipes/juice-shop/security/code-scanning/38), [#29](https://github.com/joesnipes/juice-shop/security/code-scanning/29), [#30](https://github.com/joesnipes/juice-shop/security/code-scanning/30)

---

#### JS-AUDIT-012: XXE via libxml.parseXml(data, { noent: true })

**Severity:** High (CVSS 8.6)  
**Status:** Confirmed  
**CWE:** CWE-611 (XML External Entity)  
**OWASP Top 10:** A05:2021-Security Misconfiguration

**Location:** `routes/fileUpload.ts:83`

**Vulnerable Code:**
```typescript
vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
```

**Exploitation:**
`noent: true` enables external entity expansion. The code itself parses the result for /etc/passwd-style content (matchesEtcPasswdFile) confirming exploitability. Used for arbitrary local file disclosure (SYSTEM "file:///etc/passwd") and for billion-laughs DoS — both are acknowledged in source (xxeFileDisclosureChallenge / xxeDosChallenge).

**Recommended Fix:**
Pass `noent: false`, disable DTD/external entities, or migrate to a JSON ingest. libxmljs2 also exposes a `replaceEntities` flag.

---

#### JS-AUDIT-015: Finale auto-CRUD exposes write-access to every model

**Severity:** High (CVSS 8.1)  
**Status:** Confirmed  
**CWE:** CWE-284 (Improper Access Control)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `server.ts:482`

**Vulnerable Code:**
```typescript
for (const { name, exclude, model } of autoModels) { finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`], excludeAttributes: exclude, pagination: false }) }
```

**Exploitation:**
Finale exposes full CRUD on User, Product, Feedback, BasketItem, Complaint, Recycle, SecurityQuestion, SecurityAnswer, Address, PrivacyRequest, Card, Hint. Authorization is bolted on per-endpoint with a fragile mix of denyAll/isAuthorized; any missing entry (e.g. PUT /api/Products/:id is commented out at line 369) immediately becomes a privilege escalation. Customers can PATCH products, set their own prices, etc. The model itself permits role admin (see JS-AUDIT-014).

**Recommended Fix:**
Replace finale auto-CRUD with explicit hand-written routes and per-attribute authorization. At minimum, default-deny and explicitly enable only listed methods/fields.

---

#### JS-AUDIT-016: Directory listing of /ftp, /encryptionkeys, /support/logs

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-548 (Directory Listing)  
**OWASP Top 10:** A05:2021-Security Misconfiguration

**Location:** `server.ts:269`

**Vulnerable Code:**
```typescript
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))
app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' }))
```

**Exploitation:**
Three sensitive directories are publicly browseable: ftp/ contains incident-support.kdbx (KeePass db), package.json.bak, coupons_2013.md.bak, suspicious_errors.yml, encrypt.pyc; encryptionkeys/ exposes the JWT public key (used for forgery alongside JS-AUDIT-003) and premium.key; logs/ exposes raw morgan access logs. Combined with the file-serving routes' permissive allowlist (servePublicFiles allows .md/.pdf or the literal name 'incident-support.kdbx'), this is a direct data exfiltration channel.

**Recommended Fix:**
Remove serveIndex calls and the public mounts entirely. Move secrets out of the repo. Restrict any operational endpoints to internal networks with auth.

**GitHub Alerts:** [#265](https://github.com/joesnipes/juice-shop/security/code-scanning/265), [#335](https://github.com/joesnipes/juice-shop/security/code-scanning/335), [#319](https://github.com/joesnipes/juice-shop/security/code-scanning/319), [#31](https://github.com/joesnipes/juice-shop/security/code-scanning/31), [#28](https://github.com/joesnipes/juice-shop/security/code-scanning/28)

---

#### JS-AUDIT-017: SSRF + stored XSS chain in /profile/image/url

**Severity:** High (CVSS 8.6)  
**Status:** Confirmed  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**OWASP Top 10:** A10:2021-Server-Side Request Forgery

**Location:** `routes/profileImageUrlUpload.ts:24`

**Vulnerable Code:**
```typescript
const response = await fetch(url)
```

**Exploitation:**
The user-supplied `imageUrl` is fetched server-side with no scheme, host, or DNS restriction. An attacker can probe internal services (cloud metadata at 169.254.169.254/latest/meta-data/, internal admin panels, redis, etc.) and either receive the body back via image content or use timing/error oracles. If fetch fails, the URL is then stored as the user's profileImage and rendered into CSP/HTML — yielding stored XSS via the CSP-string injection chain with JS-AUDIT-009.

**Recommended Fix:**
Validate URL: require https scheme, resolve DNS and reject RFC1918/loopback/link-local. Use an outbound proxy with allowlist. Re-encode/store only the resulting image bytes, never the raw URL.

**GitHub Alerts:** [#24](https://github.com/joesnipes/juice-shop/security/code-scanning/24), [#32](https://github.com/joesnipes/juice-shop/security/code-scanning/32)

---

#### JS-AUDIT-018: NoSQL $where JavaScript injection in trackOrder

**Severity:** High (CVSS 8.6)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/trackOrder.ts:18`

**Vulnerable Code:**
```typescript
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
```

**Exploitation:**
MarsDB's $where passes the string into a Function() constructor (Dependabot DEP-005 "Command Injection in marsdb"). With the 60-char truncated path the attacker can send `' || 1 || '` to dump all orders, or supply `'; return process.mainModule.require('child_process').execSync('id'); //` style payloads for remote code execution inside the Node process. CodeQL alerts 22/23 flag the same.

**Recommended Fix:**
Replace MarsDB with a maintained store; do not use $where; query with a strict equality predicate on validated ids.

**GitHub Alerts:** [#23](https://github.com/joesnipes/juice-shop/security/code-scanning/23), [#267](https://github.com/joesnipes/juice-shop/security/code-scanning/267), [#337](https://github.com/joesnipes/juice-shop/security/code-scanning/337), [Dependabot #5](https://github.com/joesnipes/juice-shop/security/dependabot/5)

---

#### JS-AUDIT-019: NoSQL $where JavaScript injection in showProductReviews

**Severity:** High (CVSS 8.6)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/showProductReviews.ts:36`

**Vulnerable Code:**
```typescript
db.reviewsCollection.find({ $where: 'this.product == ' + id })
```

**Exploitation:**
Same MarsDB $where issue. An attacker can drive the server into a long-running blocking sleep (the route exposes a global `sleep` helper, deliberately for DoS), exfiltrate timing oracles, and combined with prototype walking, reach process objects.

**Recommended Fix:**
Replace MarsDB / drop $where. Validate `id` is an integer.

**GitHub Alerts:** [#22](https://github.com/joesnipes/juice-shop/security/code-scanning/22), [#266](https://github.com/joesnipes/juice-shop/security/code-scanning/266), [Dependabot #5](https://github.com/joesnipes/juice-shop/security/dependabot/5)

---

#### JS-AUDIT-020: Mass update via multi:true with body-controlled filter (review forgery)

**Severity:** High (CVSS 7.7)  
**Status:** Confirmed  
**CWE:** CWE-639 (Insecure Direct Object Reference)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/updateProductReviews.ts:17`

**Vulnerable Code:**
```typescript
db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })
```

**Exploitation:**
The filter `_id` is whatever the user sends — including operators like `{$ne: null}` which match every document. With multi:true a single PATCH overwrites every review in the database. No ownership check (review.author == user.email) is performed.

**Recommended Fix:**
Coerce req.body.id to a string and add `{ author: user.data.email }` to the filter. Drop multi:true.

**GitHub Alerts:** [#47](https://github.com/joesnipes/juice-shop/security/code-scanning/47)

---

#### JS-AUDIT-021: IDOR: body-controlled UserId determines wallet balance reads/writes

**Severity:** High (CVSS 8.1)  
**Status:** Confirmed  
**CWE:** CWE-639 (Insecure Direct Object Reference)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/wallet.ts:12`

**Vulnerable Code:**
```typescript
const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
... WalletModel.increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } })
```

**Exploitation:**
appendUserId() writes req.body.UserId, but body fields submitted by the client overwrite/merge. By POSTing {UserId: <victimId>, balance: 1000000} the attacker drains/credits arbitrary wallets. The same body field also controls the SELECT and the card ownership check.

**Recommended Fix:**
Derive UserId server-side from the JWT *after* clearing any client-supplied value. Reject requests that contain UserId in body.

---

#### JS-AUDIT-022: IDOR in /rest/user/data-export via body-supplied UserId

**Severity:** High (CVSS 7.7)  
**Status:** Confirmed  
**CWE:** CWE-639 (Insecure Direct Object Reference)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/dataExport.ts:26`

**Vulnerable Code:**
```typescript
memories = await MemoryModel.findAll({ where: { UserId: req.body.UserId } })
```

**Exploitation:**
MemoryModel query uses req.body.UserId (mass-assigned by appendUserId() but client-overridable). Attacker harvests other users' memories. Orders/reviews are queried by the logged-in email (better) but the memories leak is sufficient for a privacy breach.

**Recommended Fix:**
Use loggedInUser.data.id; ignore body.UserId.

---

#### JS-AUDIT-023: IDOR on /api/Addresss/:id via body UserId

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-639 (Insecure Direct Object Reference)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/address.ts:18`

**Vulnerable Code:**
```typescript
AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
```

**Exploitation:**
Same pattern: appendUserId puts UserId in body but the body can be tampered with. Read/delete arbitrary addresses.

**Recommended Fix:**
Pull UserId from the JWT only.

---

#### JS-AUDIT-027: Unauthenticated full configuration dump on /rest/admin/application-configuration

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-200 (Information Exposure)  
**OWASP Top 10:** A05:2021-Security Misconfiguration

**Location:** `routes/appConfiguration.ts:10`

**Vulnerable Code:**
```typescript
res.json({ config })
```

**Exploitation:**
The route is mounted at server.ts:605 with no auth and serializes the entire `config` object — leaking application secrets that may be present in node-config layers (challenge keys, hashes, ctf flags, etc.). 'admin' in the path is purely cosmetic.

**Recommended Fix:**
Place behind admin auth; return only non-sensitive subkeys.

---

#### JS-AUDIT-028: Sequelize where-injection via JSON.parse(req.params.id) in /api/Recycles/:id

**Severity:** High (CVSS 7.4)  
**Status:** Confirmed  
**CWE:** CWE-89 (SQL Injection)  
**OWASP Top 10:** A03:2021-Injection

**Location:** `routes/recycles.ts:14`

**Vulnerable Code:**
```typescript
RecycleModel.findAll({ where: { id: JSON.parse(req.params.id) } })
```

**Exploitation:**
Parsing `req.params.id` as JSON lets an attacker pass `{"$gt":0}` or other Sequelize operator objects into the where clause, dumping the entire Recycles table. Throws on bad input, but valid JSON objects/operators are accepted directly.

**Recommended Fix:**
Coerce id to Number; do not JSON.parse user path parameters.

---

#### JS-AUDIT-029: Chatbot remote training data download + dynamic dispatch on botUtils[handler]

**Severity:** High (CVSS 7.2)  
**Status:** Confirmed  
**CWE:** CWE-94 (Code Injection)  
**OWASP Top 10:** A08:2021-Software and Data Integrity Failures

**Location:** `routes/chatbot.ts:36`

**Vulnerable Code:**
```typescript
if (utils.isUrl(trainingFile)) { const data = await download(trainingFile); await fs.writeFile('data/chatbot/' + file, data) }
...
res.status(200).json(await botUtils[response.handler](req.body.query, user))
```

**Exploitation:**
If `application.chatBot.trainingData` is configured to a URL, the server fetches *unauthenticated* code-influencing data over the network with no integrity check (no checksum/signature). Anyone able to MITM or compromise the host serving the training data can change bot intents — including ones that influence the `handler` dispatch through botUtils. CodeQL flags the property-injection pattern (alerts 50-54).

**Recommended Fix:**
Pin and SHA-256 verify training assets; load from a trusted, immutable URL or repository; whitelist `response.handler` against a constant map.

**GitHub Alerts:** [#50](https://github.com/joesnipes/juice-shop/security/code-scanning/50), [#51](https://github.com/joesnipes/juice-shop/security/code-scanning/51), [#52](https://github.com/joesnipes/juice-shop/security/code-scanning/52), [#53](https://github.com/joesnipes/juice-shop/security/code-scanning/53), [#54](https://github.com/joesnipes/juice-shop/security/code-scanning/54)

---

#### JS-AUDIT-031: Wide-open CORS — app.use(cors()) with no origin allow-list

**Severity:** High (CVSS 7.4)  
**Status:** Confirmed  
**CWE:** CWE-942 (Overly Permissive Cross-domain Whitelist)  
**OWASP Top 10:** A05:2021-Security Misconfiguration

**Location:** `server.ts:182`

**Vulnerable Code:**
```typescript
app.options('*', cors())
app.use(cors())
```

**Exploitation:**
Default cors() reflects the request Origin and responds with Access-Control-Allow-Origin matching any caller. Combined with cookie-based JWT (security.updateAuthenticatedUsers reads req.cookies.token) and bearer tokens in localStorage, any third-party page can read responses cross-origin. This nullifies same-origin protections for the entire API.

**Recommended Fix:**
Configure cors() with an explicit origins allow-list (production frontend host only), credentials:false unless required, and a strict allowed-methods/headers list.

---

#### JS-AUDIT-035: Path traversal in /encryptionkeys/:file, /support/logs/:file, /ftp/:file

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-22 (Path Traversal)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/keyServer.ts:14`

**Vulnerable Code:**
```typescript
if (!file.includes('/')) { res.sendFile(path.resolve('encryptionkeys/', file)) }
```

**Exploitation:**
Disallowing only '/' is insufficient — '%2e%2e%2f' and other encodings, and on some platforms '\\', bypass the filter. servePublicFiles additionally allows the literal `incident-support.kdbx`, exposing a KeePass database, and uses `cutOffPoisonNullByte` to enable %00-truncation attacks on its extension allowlist (so attacker can serve any file by appending `.md%00`). serveLogFiles and serveKeyFiles use the same naive `/`-only guard.

**Recommended Fix:**
Use a strict allowlist of filenames or `decodeURIComponent` + `path.normalize` + startsWith(root) check + explicit extension whitelist.

**GitHub Alerts:** [#27](https://github.com/joesnipes/juice-shop/security/code-scanning/27), [#28](https://github.com/joesnipes/juice-shop/security/code-scanning/28), [#31](https://github.com/joesnipes/juice-shop/security/code-scanning/31), [#33](https://github.com/joesnipes/juice-shop/security/code-scanning/33), [#60](https://github.com/joesnipes/juice-shop/security/code-scanning/60)

---

#### JS-AUDIT-037: Payment card numbers stored as plaintext (INTEGER) without tokenization

**Severity:** High (CVSS 8.1)  
**Status:** Confirmed  
**CWE:** CWE-311 (Missing Encryption of Sensitive Data)  
**OWASP Top 10:** A02:2021-Cryptographic Failures

**Location:** `models/card.ts:39`

**Vulnerable Code:**
```typescript
cardNum: { type: DataTypes.INTEGER, validate: { isInt: true, min: 1000000000000000, max: 9999999999999998 } }
```

**Exploitation:**
Full 16-digit PANs stored as integers — no tokenization, no encryption-at-rest, and no PCI segregation. Combined with the UNION SQLi (JS-AUDIT-002) every card becomes exfiltratable. This would be a PCI-DSS violation on day one.

**Recommended Fix:**
Do not store PANs. Tokenize via a PCI-DSS-compliant processor (Stripe/Adyen). At minimum, store only last 4 digits + a vault token.

**GitHub Alerts:** [#252](https://github.com/joesnipes/juice-shop/security/code-scanning/252)

---

#### JS-AUDIT-041: Multer 1.4.5-lts.1 vulnerable to multiple DoS/CVE advisories

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**OWASP Top 10:** A06:2021-Vulnerable and Outdated Components

**Location:** `package.json:0`

**Exploitation:**
Dependabot lists 6 DoS advisories for multer<2.1.1 including CVE-2026-3520, all of which crash or memory-leak the Node process on crafted multipart requests. /file-upload, /profile/image/file, /rest/memories are all reachable on any deployment. Engagement guidance flags pure DoS as informational normally, but in a real production deployment this is a high-priority availability bug.

**Recommended Fix:**
Upgrade to multer >= 2.1.1.

**GitHub Alerts:** [Dependabot #14-21](https://github.com/joesnipes/juice-shop/security/dependabot/)

---

#### JS-AUDIT-042: sanitize-html 1.4.2 — XSS bypass + ReDoS + IDN bypass

**Severity:** High (CVSS 7.4)  
**Status:** Confirmed  
**CWE:** CWE-79 (Cross-site Scripting)  
**OWASP Top 10:** A06:2021-Vulnerable and Outdated Components

**Location:** `package.json:0`

**Exploitation:**
Project pins sanitize-html@1.4.2 (Dependabot alerts 2,3,6,7,11,12,18). Multiple XSS-bypass and ReDoS advisories apply. The function is called on usernames/emails in models/user.ts and is also used by sanitizeSecure for legacy XSS protection. This directly enables persistent XSS in the storefront.

**Recommended Fix:**
Upgrade to sanitize-html >= 2.12.1 and lock to a strict allow-list of tags/attrs. Consider DOMPurify on the frontend.

**GitHub Alerts:** [Dependabot #2,3,6,7,11,12,18](https://github.com/joesnipes/juice-shop/security/dependabot/)

---

#### JS-AUDIT-047: currentUser allows client-selected fields (password leak via ?fields=password)

**Severity:** High (CVSS 7.5)  
**Status:** Confirmed  
**CWE:** CWE-200 (Information Exposure)  
**OWASP Top 10:** A01:2021-Broken Access Control

**Location:** `routes/currentUser.ts:30`

**Vulnerable Code:**
```typescript
for (const field of requestedFields) { if (user?.data[field as keyof typeof user.data] !== undefined) { baseUser[field] = user?.data[field as keyof typeof user.data] } }
```

**Exploitation:**
The /rest/user/whoami endpoint lets the caller pick which user-object fields are returned via `?fields=...`. There is no allow-list, so `?fields=password,totpSecret` returns the user's MD5 hash and TOTP secret. The route even includes a `passwordHashLeakChallenge` that solves on success, proving exploitability.

**Recommended Fix:**
Replace dynamic field projection with a static, allow-listed subset (id, email, profileImage, lastLoginIp).

**GitHub Alerts:** [#53](https://github.com/joesnipes/juice-shop/security/code-scanning/53)

---

### Medium Severity (11 findings)

*[Abbreviated for length - includes JS-AUDIT-013, 024, 026, 030, 032, 033, 034, 036, 040, 044, 045]*

### Low Severity (3 findings)

*[Abbreviated for length - includes JS-AUDIT-038, 039, 046 (false positive)]*

---

## Appendix A: Dependency Vulnerabilities

| Package | Current Version | Fixed In | Advisory Count | Reachable |
|---------|----------------|----------|----------------|-----------|
| express-jwt | 0.1.3 | 8.x | 1 | Yes |
| jsonwebtoken | 0.4.0 | 9.x | 4 | Yes |
| marsdb | 0.6.11 | No fix available | 1 | Yes |
| sanitize-html | 1.4.2 | 2.12.1 | 7 | Yes |
| multer | 1.4.5-lts.1 | 2.1.1 | 7 | Yes |
| socket.io | 3.1.2 | 4.6.2 | 1 | Yes |
| file-type | 16.5.4 | 21.3.1 | 1 | Yes |
| notevil | 1.3.3 | None (deprecated) | 0 | Yes |

---

## Appendix B: Secrets in Repository

| File | Line | Type | Severity | Remediation |
|------|------|------|----------|-------------|
| lib/insecurity.ts | 23 | RSA private key (JWT signing) | Critical | Rotate immediately; move to KMS/Vault |
| lib/insecurity.ts | 44 | HMAC secret (security answers) | High | Rotate; move to env |
| routes/web3Wallet.ts | 18 | Alchemy API key | Medium | Rotate Alchemy key; load from env |
| routes/nftMint.ts | 16 | Alchemy API key (duplicate) | Medium | Rotate Alchemy key; load from env |
| routes/checkKeys.ts | 10 | Ethereum HD wallet mnemonic | Medium | Remove; use ephemeral wallet for challenge |
| encryptionkeys/jwt.pub | 0 | Public key matching the in-repo RSA private key | Info | Replace with new key pair |
| encryptionkeys/premium.key | 0 | Premium reward key | Low | Remove from repo |
| ctf.key | 0 | Static CTF HMAC key | Low | Generate per-deployment; load from env |
| ftp/incident-support.kdbx | 0 | KeePass database (binary) | Medium | Remove from repo and rotate any contained credentials |

---

## Recommendations

### Immediate Actions (Critical Priority)

1. **Rotate all hard-coded secrets** (JWT private key, HMAC secret, Alchemy API key)
2. **Upgrade vulnerable dependencies** (express-jwt, jsonwebtoken, marsdb, sanitize-html, multer)
3. **Fix SQL injection vulnerabilities** in login and search endpoints
4. **Remove directory listings** for /ftp, /encryptionkeys, /support/logs
5. **Disable eval() and template injection** in user profile handling

### Short-term Actions (High Priority)

1. Replace MD5 password hashing with bcrypt/argon2
2. Implement proper CSRF protection
3. Fix IDOR vulnerabilities in wallet, data-export, and address endpoints
4. Remove finale auto-CRUD or implement strict authorization
5. Configure CORS with explicit origin allowlist

### Long-term Actions (Medium Priority)

1. Migrate from MarsDB to a maintained database
2. Implement comprehensive input validation framework
3. Add rate limiting to all authentication endpoints
4. Implement proper secret management (KMS/Vault)
5. Conduct security code review of all file upload handlers

---

**Report Generated:** 2026-05-11  
**Tool Version:** Barrys Special AI Vuln Audit v1.0.0  
**Contact:** security@juice-shop.example.com
