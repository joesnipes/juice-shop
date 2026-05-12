# Production Threat Model: Juice Shop Web Application

Version: 1.0.0  
Last updated: 2026-05-11T23:53:59Z  
Scope: `/Users/barrydawson/Desktop/repo/juice-shop`  
Methodology: STRIDE, treating the repository as a normal production e-commerce web application.

## 1. System Overview

The application is a Node.js/TypeScript e-commerce web application with an Express backend and Angular frontend. The backend starts from `app.ts`, initializes dependency checks, imports `server.ts`, synchronizes Sequelize models to SQLite, seeds data, starts an HTTP server, and registers Socket.IO events. The Angular SPA is built into `frontend/dist/frontend` and served statically by Express.

Primary technologies:

- Backend: Node.js, TypeScript, Express, Sequelize, SQLite, MarsDB-style document collections, Socket.IO.
- Frontend: Angular 20, Angular Material, RxJS, Socket.IO client.
- API styles: custom REST endpoints under `/rest`, generated CRUD endpoints under `/api`, B2B endpoint under `/b2b/v2`, Swagger UI under `/api-docs`, Web3 endpoints under `/rest/web3`.
- Data stores: `data/juiceshop.sqlite` for relational application data; MarsDB collections for product reviews and orders; filesystem paths for uploads, generated PDFs, logs, static assets, encryption keys, and chatbot training data.
- Authentication: local email/password login, JWT bearer/cookie token, optional TOTP 2FA, role fields (`customer`, `deluxe`, `accounting`, `admin`), and in-memory token tracking.
- Operational telemetry: Morgan access logs in `logs/`, Prometheus metrics on `/metrics`, app custom metrics, generated SBOM scripts.

The production security posture should assume all challenge/training behavior is accidental vulnerability debt. Any code path intentionally relaxing controls for training must be considered a production defect for triage.

## 2. Architecture and Major Components

### 2.1 Browser SPA

The Angular frontend handles product browsing, login, basket management, checkout, profile management, chatbot interactions, file upload flows, Web3 interactions, and Socket.IO notifications. It stores and sends JWTs via cookies and/or authorization headers and calls backend endpoints under `/api`, `/rest`, `/b2b/v2`, and `/profile`.

### 2.2 Express HTTP Server

`server.ts` is the central composition root. It configures compression, permissive CORS, selected Helmet headers, feature policy, static file serving, body parsing, file upload middleware, access logging, rate limiting for selected endpoints, authorization middleware, generated Finale REST resources, custom routes, error handling, and metrics.

Important route groups:

- Public application/static: `/`, Angular fallback, `/assets/*`, `/vendor/*`, `/.well-known/*`.
- Directory/file serving: `/ftp`, `/ftp/:file`, `/ftp/quarantine/:file`, `/encryptionkeys`, `/support/logs`, generated order PDFs.
- Auth/account: `/rest/user/login`, `/api/Users`, `/rest/user/change-password`, `/rest/user/reset-password`, `/rest/2fa/*`, `/rest/user/whoami`, `/profile`.
- Commerce: `/api/Products`, `/api/BasketItems`, `/rest/basket/:id`, `/rest/basket/:id/checkout`, `/api/Cards`, `/api/Addresss`, `/rest/order-history`, `/rest/wallet/balance`, `/rest/deluxe-membership`.
- User-generated content: product reviews, feedback, complaints, memories, profile image uploads.
- B2B and parsers: `/file-upload`, `/b2b/v2/orders`, XML/YAML/ZIP handling.
- Integrations: chatbot training and responses, Web3/NFT/wallet endpoints, external URL profile image fetching.
- Admin/accounting operations: `/rest/order-history/orders`, `/rest/order-history/:id/delivery-status`, `/api/Quantitys/:id`, app configuration/version endpoints.
- Observability and docs: `/metrics`, `/api-docs`, `/security.txt`.

### 2.3 Data Stores

- SQLite via Sequelize: Users, Baskets, BasketItems, Products, Quantities, Feedback, Complaints, Recycles, SecurityQuestions, SecurityAnswers, Addresses, PrivacyRequests, Cards, Wallets, Hints, Challenges, Delivery methods.
- MarsDB collections: `reviewsCollection` and `ordersCollection` in `data/mongodb.ts`.
- Filesystem: uploads in `frontend/dist/frontend/assets/public/images/uploads/`, complaint uploads in `uploads/complaints/`, generated order PDFs in `ftp/`, logs in `logs/`, JWT public/private key material in `encryptionkeys/` and `lib/insecurity.ts`, chatbot data in `data/chatbot/`.

### 2.4 Security Controls Observed

- Some Helmet headers (`noSniff`, frameguard) and disabled `x-powered-by`.
- JWT verification middleware using `express-jwt` and RSA public key verification.
- Role helper methods for customer, deluxe, accounting.
- Selected rate limits on reset password and 2FA endpoints.
- File upload size limit of 200 KB for memory uploads and MIME allowlist for disk image uploads.
- Payment card responses mask all but last four digits.
- Address and card access often includes `UserId` filtering.
- Prometheus metrics and access logs support operational visibility.

## 3. Trust Boundaries and Security Zones

### 3.1 Public Zone

Untrusted users and automated clients can reach the HTTP server, static assets, unauthenticated REST APIs, registration/login/reset flows, file upload endpoints where not explicitly authenticated, product search/reviews, Swagger UI, metrics, directory listings, and WebSocket connection establishment. Inputs crossing this boundary include request path/query/body, cookies, JWTs, file contents, filenames, image URLs, XML/YAML/ZIP payloads, chatbot messages, Web3 payloads, and socket events.

Required production validations at this boundary:

- Strict CORS allowlist, CSRF protection for cookie-authenticated actions, request size limits on all parsers, normalized path validation, input schema validation, authentication before protected actions, and security headers including CSP and HSTS at TLS termination.

### 3.2 Authenticated User Zone

Authenticated customers can access profile, basket, checkout, wallet, payment methods, addresses, order history, data export, reviews, memories, chatbot, profile image upload, and deluxe membership functions. This zone is only partially trusted: users may attempt IDOR, business logic abuse, injection, file upload abuse, account takeover, or privilege escalation.

Required production validations:

- Verify JWT signature, expiry, algorithm, issuer/audience; bind objects to current user server-side; avoid trusting client-supplied `UserId`, basket id, address id, payment id, role, price, discount, delivery status, or wallet values; enforce per-user and global rate limits.

### 3.3 Privileged Internal Zone

Accounting/admin-only functions, database access, filesystem writes, server-side parsers, chatbot training loading, metrics scraping, logs, secrets, and service configuration sit in the trusted zone. Transitions into this zone must require authenticated roles, network restrictions, least-privileged service accounts, immutable audit logs, and secret management.

High-risk trust-boundary crossings:

- HTTP request to SQL queries in `routes/login.ts`.
- HTTP request to filesystem writes in upload/profile/order routes.
- HTTP request to XML/YAML/ZIP parsers in `routes/fileUpload.ts`.
- HTTP request to server-side `fetch()` in `routes/profileImageUrlUpload.ts`.
- JWT/cookie to in-memory auth map in `lib/insecurity.ts`.
- Public network to generated Finale CRUD resources.
- Public WebSocket events to server event handlers.
- App startup to externally downloaded chatbot training data when configured as URL.

## 4. Critical Assets

### 4.1 PII and Customer Data

- User emails, usernames, profile images, last login IPs.
- Addresses and delivery details.
- Order history, products purchased, order PDFs, basket contents.
- Feedback, complaints, reviews, memories and image uploads.
- Privacy request and data export contents.

Protection requirements: authenticated access, object-level authorization, encryption at rest for sensitive stores, TLS in transit, retention policies, privacy request audit trail, and minimization in logs and PDFs.

### 4.2 Credentials and Secrets

- Password hashes in `Users.password`.
- TOTP secrets in `Users.totpSecret`.
- JWT public/private keys and hardcoded signing/HMAC material.
- Session/JWT cookies and bearer tokens.
- Google OAuth client id and authorized redirects.
- Web3 keys or submitted wallet/NFT verification material.

Protection requirements: modern password hashing (Argon2id/bcrypt), secret storage outside repo, key rotation, secure cookie flags, token revocation, TOTP secret encryption, and removal of exposed key-serving routes.

### 4.3 Payment and Financial Data

- Payment card full name, card number, expiry month/year.
- Wallet balances, deluxe membership token/role, discounts/coupons, delivery pricing, order totals.

Protection requirements: PCI DSS scope reduction through tokenized payment provider, never store raw PAN, authorization around wallet and coupon changes, tamper-resistant pricing calculations, audit logs for monetary changes.

### 4.4 Operational and Business-Critical Assets

- Product catalog, inventory quantities, pricing and discounts.
- Logs, metrics, API documentation, application configuration.
- Source code snippets, static files, uploaded content, generated PDFs.
- Availability of checkout, login, chatbot, file processing, and database.

Protection requirements: role-based access, change audit logs, resource limits, backup/recovery, dependency and container hardening.

## 5. Attack Surface and Entry Points

| Entry point | Trust level | Key risks for SAST/SCA triage |
|---|---:|---|
| `/rest/user/login` | Public | SQL injection, credential stuffing, weak password hashing, verbose errors, token creation flaws |
| `/api/Users` registration and user APIs | Public/authenticated | Mass assignment, role injection, duplicate account abuse, PII disclosure |
| `/rest/user/reset-password`, `/rest/user/change-password`, `/rest/2fa/*` | Public/authenticated | Brute force, weak recovery, token confusion, missing re-authentication |
| `/api/BasketItems`, `/rest/basket/:id`, `/rest/basket/:id/checkout` | Authenticated | IDOR, basket tampering, price/quantity manipulation, race conditions |
| `/api/Cards`, `/api/Addresss` | Authenticated | Stored PAN, IDOR, data leakage, insufficient validation |
| `/file-upload`, `/profile/image/file`, `/profile/image/url`, `/rest/memories` | Public/authenticated | SSRF, path traversal, ZIP slip, XXE, YAML bombs, stored XSS, malware upload |
| `/ftp`, `/support/logs`, `/encryptionkeys` | Public/static | Sensitive file disclosure, key exposure, generated order PDF leakage |
| Product search/reviews/feedback | Public/authenticated | SQL/NoSQL injection, stored XSS, spam/abuse, content moderation gaps |
| `/rest/chatbot/*` | Public/authenticated | Model/training data poisoning, prompt/command/function abuse, DoS |
| `/b2b/v2/orders` | Authenticated | XML/JSON validation gaps, B2B fraud, replay, missing partner auth |
| `/rest/web3/*` | Public | Wallet spoofing, replay, signature validation errors, blockchain dependency abuse |
| `/metrics`, `/api-docs`, `/.well-known/*` | Public/internal | Information disclosure, endpoint enumeration, operational metadata leakage |
| Socket.IO events | Public connection | Unauthenticated event abuse, XSS verification payloads, notification tampering |

## 6. STRIDE Threat Analysis

### 6.1 Authentication and Session Management

**Spoofing — CRITICAL / High likelihood.** Attackers may impersonate users if JWT signing keys or cookies are exposed, if weak algorithms are accepted, or if hardcoded private keys remain in code. SAST should prioritize `lib/insecurity.ts`, `/encryptionkeys` serving, cookie settings, and uses of `jwt.sign`, `jws.verify`, `jwt.verify`, `express-jwt`.

**Tampering — HIGH / High likelihood.** Token payload contains user role and id. Any endpoint trusting decoded role or client-supplied `UserId` can be abused. Search for `req.body.UserId`, `decodedToken?.data?.role`, and updates to role/deluxe token.

**Repudiation — MEDIUM / Medium likelihood.** Login, reset, 2FA changes, profile updates, and privilege-sensitive events lack a clear immutable audit trail. Access logs exist but are not sufficient for user-level non-repudiation.

**Information Disclosure — HIGH / Medium likelihood.** Tokens returned in JSON and set as cookies can leak via XSS or logs if not protected. Sensitive secrets and keys are filesystem-backed and some key/log paths are publicly served.

**Denial of Service — MEDIUM / Medium likelihood.** Login and many authenticated endpoints lack rate limits; in-memory token maps grow without visible eviction; JWT verification and 2FA can be brute-forced.

**Elevation of Privilege — CRITICAL / High likelihood.** Role enforcement is inconsistent and relies heavily on decoded token data. Admin/accounting route gates should be reviewed for bypasses, especially generated CRUD resources and object-level operations.

### 6.2 User, Profile, and Account Recovery

**Spoofing — HIGH.** Reset password, security question, and profile flows can enable account takeover if answers, tokens, or TOTP setup/disable operations lack re-authentication and strong rate limiting.

**Tampering — HIGH.** Profile update and username/chatbot name update may write user-controlled values that later render in the SPA or chatbot responses.

**Repudiation — MEDIUM.** Profile changes, 2FA enable/disable, password reset, data erasure/export requests need audit events with actor, subject, IP, user agent, and outcome.

**Information Disclosure — HIGH.** `/rest/user/whoami`, `/rest/user/authentication-details`, `/profile`, and data export are sensitive. SAST should verify every route maps returned data to the current authenticated user and excludes password/TOTP secrets.

**Denial of Service — MEDIUM.** Password reset and 2FA have rate limits, but values are permissive for production. Username/profile image update can call external URLs and write files.

**Elevation of Privilege — HIGH.** User registration and generated `/api/Users` resources must prevent role, id, `isActive`, `deluxeToken`, `totpSecret`, and profile image mass assignment.

### 6.3 Commerce, Basket, Checkout, Wallet, and Orders

**Spoofing — HIGH.** Attackers may use another user's basket, payment method, address, or wallet if object ids are accepted without server-side ownership checks. `/rest/basket/:id/checkout` is especially sensitive.

**Tampering — CRITICAL.** Price, quantity, coupon, delivery method, wallet balance, bonus points, and deluxe membership calculations are business-critical. The server must ignore client-supplied totals and re-read authoritative product, inventory, coupon, delivery, payment, and wallet state in a transaction.

**Repudiation — HIGH.** Monetary changes should have append-only audit logs: basket mutation, checkout, wallet debit/credit, coupon application, delivery status changes, and refunds.

**Information Disclosure — HIGH.** Generated PDFs under `ftp/` include customer email and order details. Order history and all-orders accounting APIs must prevent public file enumeration and IDOR.

**Denial of Service — MEDIUM.** Checkout generates PDFs and writes to filesystem. Attackers can exhaust disk, deplete inventory, or create expensive database operations without quota and rate limits.

**Elevation of Privilege — HIGH.** Accounting-only endpoints and quantity updates rely on role helpers and an IP filter with questionable configuration. Privileged functions require robust RBAC and network policy.

### 6.4 File Upload, Static File Serving, and Server-Side Fetch

**Spoofing — MEDIUM.** Upload endpoints should require authentication where files affect a user profile, memories, or complaints. Cookie-only checks should not be the only auth decision.

**Tampering — CRITICAL.** ZIP extraction, filename handling, and write paths can overwrite application files if path traversal controls fail. Generated files in web-served directories can become stored XSS or executable content depending on hosting.

**Repudiation — MEDIUM.** File upload, rejected file, and server-side fetch events should be logged with user id and hash of content, not raw sensitive payloads.

**Information Disclosure — CRITICAL.** Public serving of `/encryptionkeys`, `/support/logs`, `/ftp`, and generated PDFs can disclose secrets, tokens, PII, and order details. Directory listing should be disabled in production.

**Denial of Service — HIGH.** XML/YAML parsing, ZIP decompression, remote fetch streaming, and disk writes can consume CPU, memory, network, and disk. Enforce parser hardening, decompression ratio limits, timeouts, and quotas.

**Elevation of Privilege — HIGH.** SSRF via profile image URL can reach cloud metadata/internal services. Uploaded SVG/GIF/image content can execute in browsers if served with dangerous content types.

### 6.5 Product Search, Reviews, Feedback, and NoSQL Collections

**Spoofing — MEDIUM.** Review authorship and likes must be bound to authenticated identity, not client-provided identifiers.

**Tampering — HIGH.** Search and review endpoints can introduce SQL/NoSQL injection or stored XSS if user input is interpolated into queries or rendered without context-aware output encoding.

**Repudiation — LOW.** Content creation/update/delete operations need moderation and audit trails for abuse handling.

**Information Disclosure — MEDIUM.** Search errors or review APIs may disclose schema, internal ids, deleted products, or private user data.

**Denial of Service — MEDIUM.** Fuzzy search, unbounded review listing, and malformed NoSQL predicates can cause CPU/memory exhaustion.

**Elevation of Privilege — MEDIUM.** Review update/like endpoints need object-level authorization to prevent users editing or inflating others' content.

### 6.6 Generated CRUD API and Admin/Accounting Functions

**Spoofing — HIGH.** Generated resources expose many models through uniform endpoints. Auth middleware must be complete before Finale handlers register and must default deny unsafe methods.

**Tampering — CRITICAL.** Product, quantity, user, card, privacy request, and challenge-like resources can be modified through mass assignment or method gaps if middleware order is wrong.

**Repudiation — HIGH.** Admin/accounting actions need immutable logs separate from public access logs.

**Information Disclosure — HIGH.** Generated list/read APIs can leak full records unless attributes are explicitly excluded and scoped. `User` excludes password/TOTP, but other models may expose sensitive fields.

**Denial of Service — MEDIUM.** Pagination is disabled for generated resources, so list endpoints can become unbounded.

**Elevation of Privilege — CRITICAL.** Any failure in route-specific guards can expose privileged CRUD actions. SAST should check HTTP method coverage and route precedence.

### 6.7 WebSockets, Chatbot, Web3, Metrics, and Documentation

**Spoofing — MEDIUM.** Socket.IO accepts connections with permissive development CORS. Web3 endpoints must verify wallet signatures, nonces, chain id, expiry, and replay resistance.

**Tampering — HIGH.** Chatbot training data can be downloaded from URL at startup if configured, then used by a bot capable of function handlers. Treat training data as code-adjacent configuration.

**Repudiation — LOW.** Socket and Web3 events need event logging if they affect state, rewards, wallets, or user-visible notifications.

**Information Disclosure — HIGH.** `/metrics`, `/api-docs`, security metadata, and chatbot errors can reveal endpoint names, business logic, internal state, versions, and operational data.

**Denial of Service — HIGH.** Socket floods, chatbot expensive queries, metrics scraping, and Web3 verification can exhaust server resources.

**Elevation of Privilege — MEDIUM.** Chatbot function handlers and Web3 reward flows can become alternate authorization paths if not consistently checking current user and role.

## 7. Vulnerability Pattern Library for SAST/SCA Triage

### SQL Injection

Vulnerable pattern observed:

```ts
sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
```

Safe pattern:

```ts
sequelize.query('SELECT * FROM Users WHERE email = :email', {
  replacements: { email: req.body.email },
  model: UserModel,
  plain: true
})
```

Prioritize all `sequelize.query`, string concatenation in query builders, and raw SQL-like operators.

### XSS and HTML Injection

Risky patterns:

```ts
user.update({ username: req.body.query })
res.json({ body: userControlledValue })
```

Safe pattern: validate schema, sanitize only where appropriate, and perform context-aware encoding in Angular templates. Avoid serving user-uploaded SVG/HTML inline from the application origin.

### Command/Code Injection and Unsafe Evaluation

Risky patterns:

```ts
vm.runInContext(userControlledParserInput, sandbox, { timeout: 2000 })
bot.factory.run(`currentUser('${user.id}')`)
```

Safe pattern: avoid dynamic code execution for request data; use hardened parsers and strict data APIs.

### Path Traversal and ZIP Slip

Risky patterns:

```ts
const absolutePath = path.resolve('uploads/complaints/' + entry.path)
entry.pipe(fs.createWriteStream('uploads/complaints/' + entry.path))
```

Safe pattern:

```ts
const target = path.resolve(baseDir, sanitizedName)
if (!target.startsWith(baseDir + path.sep)) throw new Error('invalid path')
```

Also check `serveIndex`, `express.static`, generated PDFs, and any route reading `:file` from URL params.

### SSRF

Risky pattern:

```ts
const response = await fetch(req.body.imageUrl)
```

Safe pattern: use an allowlist of schemes/hosts, block private/link-local/cloud metadata IP ranges after DNS resolution, enforce redirects/timeouts/size limits, and store only validated images.

### XXE and Parser Abuse

Risky pattern:

```ts
libxml.parseXml(data, { noent: true })
yaml.load(data)
```

Safe pattern: disable entity expansion and external resource access; use safe schemas; enforce small input sizes, nesting limits, and parse timeouts outside the main event loop.

### Authentication Bypass and Token Weakness

Risky patterns:

```ts
const privateKey = '-----BEGIN RSA PRIVATE KEY-----...'
res.cookie('token', token)
decode(token)?.payload
```

Safe pattern: external secret manager, key rotation, explicit JWT algorithm allowlist, issuer/audience checks, secure/httpOnly/sameSite cookies, central authorization middleware, server-side token revocation.

### IDOR and Mass Assignment

Risky patterns:

```ts
BasketModel.findOne({ where: { id: req.params.id } })
app.post('/api/Users', generatedCreateHandler)
req.body.UserId = authenticatedUser.id
```

Safe pattern: derive subject from verified token, query by both object id and owner id, never trust client user ids, and use DTO allowlists for writeable fields.

### Sensitive Data Exposure

Risky patterns:

```ts
app.use('/encryptionkeys', serveIndex(...))
app.use('/support/logs', serveIndex(...))
app.use('/ftp', serveIndex(...))
```

Safe pattern: remove public directory listing, serve private files through authenticated one-time URLs, redact logs, and ensure secrets are not stored in or served from the web root.

## 8. Third-Party Dependency and Supply Chain Risk

High-value dependencies for SCA triage:

- Security/auth: `jsonwebtoken` 0.4.0, `express-jwt` 0.1.3, `jws`, `cookie-parser`, `helmet` 4.6.0.
- Parsers/file handling: `libxmljs2`, `js-yaml` 3.14.0, `unzipper` 0.9.15, `multer`, `file-type`, `download`, `sanitize-html` 1.4.2.
- Web framework: `express`, `body-parser`, `cors`, `errorhandler`, `serve-index`, `swagger-ui-express`.
- Database/ORM: `sequelize`, `sqlite3`, `marsdb`, `finale-rest`.
- Frontend: Angular packages, `codemirror`, `snarkdown`, `socket.io-client`, `jwt-decode`, `ng2-file-upload`.
- Crypto/Web3: `ethers`, `web3`, `otplib`, `z85`, `jssha`.

SCA should flag deprecated/old auth libraries, known parser CVEs, unsafe transitive native modules, frontend XSS-prone markdown/code editor packages, and libraries with unmaintained status. Production policy should generate and archive SBOMs (`npm run sbom`) and block critical vulnerable dependencies unless a documented compensating control exists.

## 9. Abuse Cases to Drive Triage

1. Attacker enumerates `/encryptionkeys` or logs, steals JWT signing material or tokens, and impersonates admin/accounting users.
2. Attacker performs SQL injection on login to bypass credentials or dump users.
3. Authenticated user changes basket id, payment id, address id, or wallet amount to purchase using another account or negative totals.
4. Attacker uploads ZIP/XML/YAML payloads to overwrite files, read local files, or exhaust CPU/memory.
5. Attacker submits a profile image URL to fetch cloud metadata or internal admin endpoints via SSRF.
6. Attacker stores JavaScript in profile, review, product, or upload content and steals tokens from browsers.
7. Attacker scrapes `/metrics`, `/api-docs`, directory listings, and PDFs to enumerate internals and PII.
8. Attacker abuses generated CRUD endpoints to mass assign role, change catalog/pricing, or access records outside their tenant/user scope.
9. Attacker floods login, reset, 2FA, chatbot, Socket.IO, or checkout/PDF generation to deny service.
10. Attacker tampers with Web3 wallet/NFT verification payloads to claim benefits without ownership.

## 10. Security Testing Strategy for Subsequent SAST/SCA

Prioritize SAST findings in this order:

1. Authentication/session flaws, hardcoded secrets, JWT misuse, exposed key/log routes.
2. Injection paths: SQL, NoSQL, XML/XXE, YAML, path traversal/ZIP slip, SSRF.
3. Authorization flaws: IDOR, mass assignment, role checks, generated CRUD endpoints, basket/checkout ownership.
4. Sensitive data storage/exposure: raw PAN, password hashing, TOTP secrets, order PDFs, logs, public directory listing.
5. Business logic abuse: wallet, coupon, delivery, inventory, deluxe membership, Web3 rewards.
6. DoS: parser bombs, unbounded listing, no pagination, socket/chatbot floods, disk exhaustion.
7. Frontend XSS and dependency vulnerabilities that can expose JWTs or PII.

Recommended dynamic/security tests:

- Authenticated IDOR tests for every route with `:id` and generated `/api/*/:id` resources.
- Fuzz file uploads with oversized files, nested ZIPs, path traversal names, SVG/HTML, XML entities, YAML aliases.
- Test CORS/CSRF with cookie token flows.
- Validate all cookies have `HttpOnly`, `Secure`, `SameSite` and tokens expire/revoke correctly.
- Confirm `/metrics`, `/api-docs`, `/support/logs`, `/encryptionkeys`, and `/ftp` are protected or disabled.
- Verify payment data is tokenized and PAN is not stored.

## 11. Assumptions, Required Production Controls, and Accepted Risks

Assumptions:

- This model treats the app as a real production e-commerce service, not a training target.
- TLS is terminated upstream or by the Node service; production must enforce HTTPS and HSTS.
- SQLite and local filesystem storage may be acceptable for development but require production-grade database, backup, encryption, and access controls before handling real customer/payment data.
- No compliance framework was explicitly provided; PCI DSS is relevant due to card data, GDPR/privacy controls are relevant due to PII and data export/erasure flows, and SOC 2 controls are relevant for operational governance.

Required production controls before launch:

- Remove hardcoded secrets and public secret/log/file-serving routes.
- Replace raw SQL login with parameterized queries and modern password hashing.
- Introduce central schema validation and DTO allowlists.
- Enforce object-level authorization on all user-owned resources.
- Disable directory listings and generated public PDFs containing PII.
- Tokenize payment cards through a PCI-compliant provider.
- Harden parser and upload processing; isolate uploads from app origin.
- Restrict CORS, add CSRF defenses, and set secure cookie attributes.
- Add immutable audit logs for auth, account, payment, wallet, admin, and privacy events.
- Add pagination, rate limits, quotas, and worker isolation for CPU/file-heavy operations.

Accepted risks: none recorded for production. Any exception should include owner, expiry date, compensating controls, and monitoring.

## 12. Version Changelog

- 1.0.0 (2026-05-11): Initial STRIDE threat model generated for production interpretation of the Juice Shop repository. Includes architecture, assets, trust boundaries, entry points, authentication/authorization, data stores, third-party dependencies, abuse cases, and SAST/SCA triage guidance.
