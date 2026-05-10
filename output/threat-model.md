# Production Threat Model: OWASP Juice Shop

Generated: 2026-05-10  
Repository: `/Users/barrydawson/Desktop/repo/juice-shop`  
Methodology: STRIDE, abuse-case driven review, production deployment assumptions  
Scope note: This model treats the application as a real production e-commerce system even though the repository is intentionally vulnerable.

## 1. System Overview

Juice Shop is a Node.js/Express single-page e-commerce application with an Angular frontend. The backend exposes custom REST routes, generated CRUD endpoints through `finale-rest`, a B2B OpenAPI endpoint, static file serving, WebSocket challenge notifications, and upload/download features. Persistence is primarily SQLite via Sequelize (`data/juiceshop.sqlite`) plus MarsDB collections for product reviews and orders. Authentication uses JWT bearer tokens signed with an RSA private key embedded in `lib/insecurity.js`; some profile flows additionally rely on a `token` cookie and an in-memory authenticated-user map.

### Major components

| Component | Key files | Responsibilities | Primary risk themes |
|---|---|---|---|
| Express application | `server.js`, `app.js` | Routing, middleware, static assets, API exposure, rate limiting, error handling | Global CORS, weak middleware hardening, large attack surface |
| Angular frontend | `frontend/`, `frontend/package.json` | Browser SPA for shop, login, basket, checkout, profile, admin-like views | XSS, token exposure, client-side authorization assumptions |
| Authentication/session layer | `routes/login.js`, `routes/2fa.js`, `lib/insecurity.js` | Password login, JWT issuance/verification, 2FA setup/verify, authenticated user cache | SQL injection, hardcoded keys, weak hashing, token misuse, 2FA secret exposure |
| REST and generated CRUD APIs | `routes/*.js`, `server.js` Finale resources | Products, users, baskets, complaints, recycling, privacy requests, feedback | IDOR, function-level authorization gaps, mass assignment, information disclosure |
| File handling | `routes/fileUpload.js`, `routes/profileImageFileUpload.js`, `routes/profileImageUrlUpload.js`, `routes/fileServer.js`, `routes/keyServer.js`, `routes/logfileServer.js` | Complaint uploads, profile images, static/download directories | XXE, Zip Slip, path traversal, malware upload, SSRF, key/log disclosure |
| B2B API | `swagger.yml`, `routes/b2bOrder.js` | Authenticated order submission | Unsafe evaluation/RCE, DoS, schema validation gaps |
| Data stores | `models/*.js`, `data/mongodb.js`, `data/static/*.yml` | Users, baskets, products, orders, reviews, challenges | PII/credential storage, weak data segregation, DB reset on startup |
| Observability/config | `lib/logger.js`, `logs/`, `config/*.yml` | Access logs, runtime config, public security.txt | Sensitive log leakage, directory browsing, environment drift |

## 2. Actors and Security Objectives

### Actors

- Anonymous internet user: browses products, registers, searches, submits feedback, uses public uploads and static endpoints.
- Authenticated customer: manages basket, orders, profile image, password, 2FA, reviews, privacy/export/erasure flows.
- Administrator/support user: represented by `isAdmin` and seeded users; expected to access privileged application data/configuration.
- B2B customer/integrator: submits large order payloads to `/b2b/v2/orders` with bearer JWT.
- External service endpoints: profile image URLs fetched by backend; links to social/shop/crypto sites; potential future payment/shipping/email providers.
- Security/audit team: monitors logs, receives vulnerability disclosures, validates controls.
- Malicious insider or compromised account: abuses legitimate authenticated access to escalate privileges, exfiltrate data, or tamper orders.

### Security objectives

1. Protect customer PII, credentials, authentication tokens, order history, and privacy request data.
2. Enforce strong authentication, session integrity, and object/function-level authorization.
3. Prevent arbitrary code execution, server-side request forgery, filesystem writes/reads outside intended directories, and unsafe XML/archive processing.
4. Preserve integrity of products, baskets, orders, reviews, challenge/admin state, and logs.
5. Maintain availability under brute force, upload, B2B payload, search, and WebSocket traffic.
6. Support non-repudiation through security-relevant audit trails.

## 3. Critical Assets

| Asset | Location | Sensitivity | Required protections |
|---|---|---|---|
| User accounts and PII: email, username, last login IP, profile image, deleted state | `Users` SQLite model | High | Strong authN/Z, encryption at rest where appropriate, minimization, privacy access controls |
| Password hashes | `Users.password` | Critical | Adaptive salted hashing such as Argon2id/bcrypt; no MD5; no logging/export |
| TOTP secrets | `Users.totpSecret` | Critical | Encrypt with KMS/HSM-backed key, restrict export/API exposure, rotate/reset controls |
| JWT signing private key and public key | `lib/insecurity.js`, `encryptionkeys/jwt.pub` | Critical | Private key only in secret manager, rotation, no repository storage, algorithm pinning |
| Auth tokens and authenticated-user cache | Authorization header, cookie, `insecurity.authenticatedUsers` | Critical | HTTPS-only, HttpOnly/SameSite cookies, revocation/expiry, no token leakage to logs |
| Basket and order data | Sequelize Basket/BasketItem; MarsDB `orders` | High | Per-user object authorization, transaction integrity, tamper-resistant order totals |
| Product catalogue/prices | Product model/config | Medium/High | Admin-only mutation, audit changes, server-side price validation |
| Reviews/feedback/complaints | MarsDB reviews; Finale feedback/complaints | Medium | Output encoding, moderation, anti-spam, author ownership controls |
| Uploaded files and public assets | `uploads/`, `ftp/`, `frontend/dist/.../uploads` | High | Content validation, AV scanning, path confinement, separate object storage/domain |
| Logs | `logs/access.log`, `/support/logs` | High | Access restricted to admins/security, redaction, immutability, retention controls |
| Security/configuration metadata | `config/*.yml`, `security.txt`, Swagger | Medium | Controlled release, no sensitive config, accurate docs |

## 4. Trust Boundaries and Zones

### Public/untrusted zone

All browser and API traffic entering Express is untrusted. Public entry points include static SPA assets, `/rest/products/search`, `/api/Products` GET, `/api/Feedbacks` POST, `/file-upload`, `/profile/image/*`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/api-docs`, `/redirect`, `/promotion`, `/video`, `/rest/captcha`, `/rest/image-captcha`, and registration/login/reset flows. Every parameter, header, cookie, body, uploaded file, archive member name, XML entity, and URL is attacker-controlled.

### Authenticated customer zone

JWT-protected endpoints include basket operations, selected generated CRUD endpoints, B2B API, privacy requests, data export, review mutation, 2FA status/setup/disable, and profile changes. Boundary transition is intended to be `Authorization: Bearer <JWT>` verified by `express-jwt` with the public key. Some routes use `req.cookies.token` and the in-memory token map instead of only bearer-token verification, creating inconsistent trust assumptions.

### Administrative/internal zone

Admin-like resources include application configuration/version, products mutation, user listings, challenge state, key/log directories, database access, seeded config, and filesystem. In production these must be reachable only from trusted admin networks or admin RBAC, but the current code exposes several through public or weakly authenticated routes.

### Data-store boundary

Express crosses from untrusted request data into SQLite/Sequelize raw SQL, Finale generated CRUD, and MarsDB queries. Strict parameterization, schema validation, ORM ownership filters, and transaction boundaries are required at this boundary.

### Filesystem/network egress boundary

Uploads, archive extraction, static serving, profile-image URL fetching, XML parsing, and video/file serving cross into OS filesystem and outbound network trust boundaries. These require allowlists, sandboxing, path normalization, size limits, decompression limits, XML external entity disablement, and egress restrictions.

## 5. Entry Points and Data Flows

### Key entry points

- Authentication: `POST /rest/user/login`, `GET /rest/user/change-password`, `POST /rest/user/reset-password`, `GET /rest/user/security-question`, `/rest/2fa/*`.
- User/profile/privacy: `GET/POST /profile`, `POST /profile/image/file`, `POST /profile/image/url`, `POST /rest/data-export`, `GET /rest/user/erasure-request`, `/api/PrivacyRequests`.
- Shop/order: `GET /rest/products/search`, generated `/api/Products`, `/rest/basket/:id`, `/api/BasketItems`, `/rest/basket/:id/checkout`, `/rest/basket/:id/coupon/:coupon`, `/b2b/v2/orders`.
- User content: `/api/Feedbacks`, `/rest/products/:id/reviews`, `/rest/products/reviews`, complaint/recycle endpoints.
- File/static/admin-like: `/file-upload`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/api-docs`, `/redirect`, `/promotion`, `/video`.
- Realtime: Socket.IO registered in `lib/startup/registerWebsocketEvents.js`.

### Representative data flows

1. Login: Browser submits email/password -> Express parses JSON/text -> `routes/login.js` raw SQL query -> `Users` table -> JWT created with embedded private key -> token stored in in-memory map -> token returned to browser.
2. Authenticated API: Browser sends bearer JWT -> `express-jwt` verifies -> route may also consult in-memory token map -> route reads/writes Sequelize/MarsDB -> JSON returned.
3. Product search: Query string `q` -> string concatenated into SQL -> SQLite -> product JSON returned; unsafe input can read other tables.
4. Checkout/order: Authenticated basket ID and items -> basket/order routes -> database/MarsDB order state -> response; object ownership must be enforced on basket ID.
5. Profile image by URL: Browser supplies URL -> server performs outbound HTTP GET -> response stream written under frontend public uploads -> user profile image updated; this is an SSRF and untrusted content boundary.
6. Complaint upload: Multipart file -> memory upload limit -> XML parsed with entity expansion or ZIP extracted to local filesystem -> errors returned/logged; this is an XXE, archive traversal, and DoS boundary.
7. Data export: Authenticated token -> in-memory user -> MarsDB order/review lookups -> JSON export; this is a privacy/IDOR boundary.
8. B2B order: Authenticated JSON body -> `orderLinesData` evaluated in VM through `notevil` -> confirmation returned; this is an RCE/DoS boundary.

## 6. Authentication and Authorization Model

Current model:

- Passwords are stored as unsalted MD5 hashes via `insecurity.hash()`.
- Login executes a raw SQL statement built from request body values.
- JWTs are RS256 and expire after five hours, but the private key is hardcoded in source and the public key is served from the repository tree.
- `express-jwt` protects selected path prefixes; generated CRUD endpoints are selectively protected with route middleware before Finale initializes.
- An in-memory token-to-user map is used for `currentUser`, profile image flows, data export, and related logic.
- 2FA is optional; TOTP secrets are stored in the user row and returned during setup as a signed setup token.
- Authorization is path-based and object-level authorization is inconsistent. Admin status exists in the model but is not consistently enforced as RBAC.

Required production model:

- Replace MD5 with Argon2id/bcrypt and enforce password policy, breach checks, lockout/risk throttling, and password reset token expiration.
- Parameterize all SQL and centralize authentication service logic.
- Store signing keys in a secret manager/KMS; rotate keys; use `kid`; keep keys out of repo and public static routes.
- Use consistent token extraction/verification; avoid mutable in-memory session source of truth unless backed by a revocation store.
- Apply deny-by-default RBAC/ABAC on every route and every object ID (`userId`, `basketId`, `reviewId`, `orderId`).
- Require step-up authentication for sensitive changes: password, 2FA, email, erasure/export, admin operations.

## 7. Dependencies and Supply Chain

Primary backend dependencies include Express 4, Sequelize 5, sqlite3, Finale REST, jsonwebtoken, express-jwt `0.1.3`, multer, libxmljs2, unzipper, request, sanitize-html `1.4.2`, socket.io 2, helmet 3, and errorhandler. Frontend uses Angular 7, RxJS 6, Angular Material 7, ng2-file-upload, ngx-cookie, and socket.io-client 2. This stack is legacy and contains many end-of-life or historically vulnerable packages. Production must pin supported versions, run SCA in CI, generate SBOMs, review transitive vulnerabilities, and remove deprecated packages such as `request` and old Angular/Node ranges.

## 8. Deployment Assumptions

This model assumes a production deployment behind TLS-terminating reverse proxy/WAF with Node.js running as a non-root user in a container or VM, persistent database and object storage separated from the application image, centralized logging/SIEM, no public directory browsing, outbound network egress controls, and environment-specific secrets injected at runtime. Current code defaults to `PORT` or `config.server.port` 3000, trusts proxy headers, enables broad CORS, resets SQLite data on startup, and writes logs/uploads to local disk; all must be revisited for production.

## 9. STRIDE Threat Analysis

### Express/API gateway

- Spoofing: Global CORS and mixed cookie/bearer token usage can let attacker-controlled origins interact with APIs if browser token storage is weak. Severity: High. Gap: no strict origin allowlist or consistent SameSite/HttpOnly session design.
- Tampering: Body parser accepts text for all content types and later parses JSON manually; schema validation is largely absent. Severity: High. Gap: route-specific validators and content-type enforcement.
- Repudiation: Morgan access logs exist, but security events are not structured, user-bound, immutable, or protected from public log exposure. Severity: Medium.
- Information disclosure: `errorhandler()` can return stack traces; `/api-docs`, directory indexes, logs, and encryption keys are exposed. Severity: Critical.
- Denial of service: Limited rate limiting only on password reset and 2FA; search, login, uploads, XML, B2B evaluation, and WebSockets are broadly exposed. Severity: High.
- Elevation of privilege: Path-based middleware before generated resources is error-prone; missing function-level authorization comments indicate known gaps. Severity: High.

### Authentication/session/2FA

- Spoofing: SQL injection in login, hardcoded JWT private key, optional 2FA, and weak password hashes allow account impersonation. Severity: Critical.
- Tampering: JWT contents may be trusted after verification without rechecking fresh user state; in-memory token map can diverge from database. Severity: High.
- Repudiation: Login, 2FA changes, password reset, token issuance, and admin actions lack durable audit events. Severity: Medium.
- Information disclosure: Password hashes and TOTP secrets can be exposed through injection, unsafe exports, logs, or database access. Severity: Critical.
- Denial of service: Login endpoint lacks throttling; 2FA has high retry limits; token map grows in memory. Severity: High.
- Elevation of privilege: `isAdmin` is not consistently enforced and object ownership is inconsistent. Severity: Critical.

### Data access and generated CRUD

- Spoofing: User identity is inferred from token map/header/cookie in different routes. Severity: High.
- Tampering: Raw SQL in login/search and generated resource writes can modify/read unintended data if not constrained. Severity: Critical.
- Repudiation: CRUD changes do not produce actor-aware audit logs. Severity: Medium.
- Information disclosure: User listing excludes password/TOTP in generated output, but SQL injection and IDOR can reveal credentials/PII. Severity: Critical.
- Denial of service: Expensive SQL wildcard searches and unbounded generated list endpoints can exhaust DB resources. Severity: Medium.
- Elevation of privilege: Lack of centralized object-level authorization enables access to other users' baskets, reviews, complaints, privacy requests. Severity: Critical.

### File upload/download and filesystem

- Spoofing: Profile image upload trusts cookie token map instead of route-level JWT middleware. Severity: High.
- Tampering: ZIP extraction writes based on attacker-controlled entry names; profile URL/file uploads write into public assets. Severity: Critical.
- Repudiation: File writes and downloads are not audited with user ID/hash. Severity: Medium.
- Information disclosure: Directory browsing for `/ftp`, `/encryptionkeys`, and `/support/logs`; XML parser can disclose local files via XXE. Severity: Critical.
- Denial of service: XML entity expansion, archive bombs, large/parallel uploads, and disk exhaustion. Severity: High.
- Elevation of privilege: Arbitrary file write or public asset overwrite can become stored XSS or server compromise. Severity: Critical.

### B2B API

- Spoofing: Any authenticated user can access `/b2b/v2/orders`; no B2B role/client separation is visible. Severity: High.
- Tampering: `orderLinesData` is evaluated rather than strictly parsed; order confirmations are generated without robust validation. Severity: Critical.
- Repudiation: No durable B2B request signing, idempotency, or audit trail. Severity: Medium.
- Information disclosure: Evaluated payload errors can disclose internals. Severity: High.
- Denial of service: VM/eval timeout can be abused; request body size and complexity controls are weak. Severity: High.
- Elevation of privilege: Sandbox escape would lead to server-side code execution. Severity: Critical.

### Frontend/browser

- Spoofing: If tokens are stored/read by JavaScript or non-HttpOnly cookies, XSS enables account takeover. Severity: Critical.
- Tampering: Client-side basket/product/pricing controls can be modified unless server recalculates all totals. Severity: High.
- Repudiation: User-visible actions are not backed by signed/immutable audit records. Severity: Medium.
- Information disclosure: Reflected/stored XSS can leak tokens, PII, and order data. Severity: Critical.
- Denial of service: SPA can trigger repeated expensive API calls; no per-user/global throttling. Severity: Medium.
- Elevation of privilege: Client routes/admin UI must not imply authorization. Severity: High.

## 10. Primary Abuse Cases

1. Account takeover through SQL injection on `POST /rest/user/login` or password spraying weak seeded/common passwords.
2. Exfiltrate all users, password hashes, and TOTP secrets through product search SQL injection or exposed logs/keys.
3. Forge or replay JWTs after obtaining hardcoded/private signing key material.
4. Read local files or crash the service through XML upload with external entities/entity expansion.
5. Write files outside intended upload directory via ZIP traversal or abuse public profile image writes for stored XSS.
6. Use profile-image URL upload for SSRF against metadata services, internal admin panels, or localhost-only endpoints.
7. Execute code or consume CPU via B2B `orderLinesData` evaluation.
8. Access or manipulate another user's basket, order, privacy request, or review by changing IDs.
9. Harvest encryption keys and support logs through public directory browsing.
10. Tamper product prices, coupons, or order totals if server-side recalculation and authorization are incomplete.

## 11. Existing Security Controls

- Helmet `noSniff` and `frameguard` are enabled.
- Multer memory upload limit of 200 KB for configured multipart routes.
- Some route-level JWT authorization is applied with `express-jwt`.
- 2FA support exists with TOTP and basic rate limiting on setup/verify endpoints.
- Rate limiting exists for password reset and 2FA, albeit permissive.
- Finale excludes `password` and `totpSecret` from generated User responses.
- Some destructive operations are blocked with `denyAll()`.
- Access logging with Morgan and log rotation is configured.
- `security.txt` is published.

## 12. Control Gaps and Required Remediation Themes

- Injection resistance: replace all string-built SQL and unsafe eval/XML/archive processing with parameterized queries, strict parsers, schemas, and sandbox removal.
- Secrets management: remove private keys and static secrets from source; disable public key/log/key directory browsing; rotate all exposed material.
- AuthN/Z: centralize authentication, implement RBAC/ABAC, enforce object ownership, require admin roles for admin/config/product/user operations.
- Session security: consistent bearer/cookie strategy, HttpOnly/Secure/SameSite cookies if cookies are used, token revocation, short-lived access + refresh tokens.
- Input/output validation: route-level schemas, size limits, content-type allowlists, output encoding, CSP, and strong XSS prevention.
- File/network boundaries: object storage, AV scanning, path confinement, egress allowlists, SSRF metadata IP blocking, XXE disabled, decompression limits.
- Availability: global and per-route throttling, request/body/time limits, WebSocket limits, query pagination, circuit breakers.
- Auditability: structured security logs for login, 2FA, password reset, data export/erasure, admin/product/order changes; protect logs from users.
- Supply chain: upgrade legacy Node/Angular/dependencies, run SCA, produce SBOM, sign builds/images.
- Deployment hardening: TLS/HSTS, strict CORS, production error handling, non-root containers, read-only filesystem where possible, separated DB/object storage.

## 13. Vulnerability Pattern Library for This Codebase

### SQL injection

Vulnerable:

```js
models.sequelize.query('SELECT * FROM Users WHERE email = \'' + req.body.email + '\'')
```

Safe:

```js
models.sequelize.query('SELECT * FROM Users WHERE email = :email', {
  replacements: { email: req.body.email },
  type: models.Sequelize.QueryTypes.SELECT
})
```

### XSS / unsafe HTML

Vulnerable:

```js
res.send('<div>' + userControlledText + '</div>')
```

Safe:

```js
// Prefer framework auto-escaping and sanitize rich text on input/output with a current sanitizer.
res.json({ message: String(userControlledText) })
```

### Command/eval injection

Vulnerable:

```js
vm.runInContext('safeEval(orderLinesData)', sandbox)
```

Safe:

```js
const orderLines = JSON.parse(orderLinesData)
validateOrderLines(orderLines)
```

### Path traversal / Zip Slip

Vulnerable:

```js
fs.createWriteStream('uploads/complaints/' + entry.path)
```

Safe:

```js
const base = path.resolve('uploads/complaints')
const target = path.resolve(base, path.basename(entry.path))
if (!target.startsWith(base + path.sep)) throw new Error('Invalid path')
```

### SSRF

Vulnerable:

```js
request.get(req.body.imageUrl).pipe(fs.createWriteStream(target))
```

Safe:

```js
const url = new URL(req.body.imageUrl)
if (!['https:'].includes(url.protocol) || !allowedHosts.has(url.hostname)) throw new Error('Blocked')
// Resolve DNS and block private/link-local/metadata IP ranges before fetch.
```

### Authentication bypass / weak crypto

Vulnerable:

```js
crypto.createHash('md5').update(password).digest('hex')
const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'
```

Safe:

```js
const hash = await argon2.hash(password, { type: argon2.argon2id })
const privateKey = await secretsManager.getSecretValue({ SecretId: 'jwt-signing-key' })
```

### IDOR / object-level authorization

Vulnerable:

```js
app.get('/rest/basket/:id', isAuthorized(), basket())
```

Safe:

```js
app.get('/rest/basket/:id', isAuthorized(), requireBasketOwner('id'), basket())
```

## 14. Security Testing Strategy

- SAST rules: raw `sequelize.query` concatenation, `vm`/`eval`/`notevil`, `libxml.parseXml` with `noent`, filesystem writes using request data, `request.get` on user URL, `serveIndex`, `errorhandler`, hardcoded keys/secrets, weak hash algorithms, missing authorization middleware.
- DAST/API tests: login injection, search injection, IDOR for baskets/orders/reviews/privacy requests, upload XXE/Zip Slip/archive bombs, SSRF to loopback/metadata IPs, B2B RCE/timeout payloads, XSS in reviews/feedback/profile/product fields, unauthenticated access to logs/keys/docs.
- Dependency/security posture: `npm audit` or SCA equivalent, license/SBOM, container scan, secret scanning, IaC/deployment config review.
- Abuse and resilience tests: brute-force throttling, token replay/revocation, CORS preflight/origin checks, WebSocket flooding, large body and slow request handling.
- Compliance-oriented tests: GDPR data export/erasure authorization, retention, auditability, consent/cookie tracking, breach logging.

## 15. Production Risk Register

| Priority | Risk | Severity | Likelihood | Security-auditor focus |
|---|---|---:|---:|---|
| P0 | SQL injection in login/search and weak password hashing | Critical | High | Exploitability, credential exposure, remediation with parameterization/Argon2id |
| P0 | Hardcoded JWT private key/static secrets and key directory exposure | Critical | High | Secret inventory, key rotation, token forgery |
| P0 | File upload XXE/Zip Slip/SSRF/arbitrary write | Critical | High | Filesystem/network boundary tests |
| P0 | B2B unsafe evaluation/RCE/DoS | Critical | High | Remove eval, strict JSON schema, sandbox escape tests |
| P0 | IDOR/function-level authorization gaps | Critical | High | Object ownership matrix across all IDs/routes |
| P1 | Public logs/directory browsing/errorhandler info leaks | High | High | Production config and route exposure review |
| P1 | Legacy vulnerable dependencies | High | High | SCA, upgrade plan, exploitability triage |
| P1 | Missing comprehensive rate limits | High | Medium | Auth, upload, search, B2B, WebSocket throttling |
| P2 | Insufficient audit/non-repudiation | Medium | High | Security event schema, SIEM, log protection |

## 16. Assumptions and Accepted Risks

- No payment processor is visible in this repository; if payments are added, PCI DSS scoping and tokenization must be modeled separately.
- Email delivery, fraud tooling, CDN/WAF, and cloud infrastructure are not represented in code and should be added to a deployment-specific model.
- Seeded challenge/user data is treated as production-like customer/admin data for this analysis.
- No current risks are accepted for a real production launch; Critical and High gaps should block release until mitigated or formally accepted by accountable leadership.

## 17. Changelog

- 1.0.0 (2026-05-10): Initial production-grade STRIDE threat model generated from repository inspection.
