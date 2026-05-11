# Production-Oriented STRIDE Threat Model for Juice Shop E-Commerce Application

**Version:** 1.0.0  
**Last updated:** 2026-05-10  
**Repository:** `/Users/barrydawson/Desktop/repo/juice-shop`  
**Important modeling assumption:** This document treats the application as a real production e-commerce system. Any training/CTF intent in the repository is ignored; deliberately vulnerable code paths are modeled as production security defects requiring remediation.

## 1. System Overview

The system is a TypeScript/Node.js e-commerce web application with an Angular frontend and an Express backend. The backend initializes from `app.ts` and `server.ts`, exposes REST and generated CRUD APIs, serves static frontend assets, processes orders, manages baskets, stores user addresses and payment methods, supports file uploads, exports personal data, exposes operational metrics, and integrates Web3/NFT-related workflows.

Concrete architecture evidence:

- `app.ts:6-12` validates dependencies and starts the Express server.
- `server.ts:129-130` creates the Express app and HTTP server.
- `server.ts:67-127` imports route handlers for login, payments, orders, baskets, uploads, profiles, metrics, Web3, and product reviews.
- `server.ts:478-505` uses `finale-rest` to generate CRUD endpoints for Sequelize models.
- `models/index.ts:30-40` configures Sequelize with SQLite storage at `data/juiceshop.sqlite`.
- `data/mongodb.ts:9-10` creates MarsDB collections for reviews and orders.
- `frontend/package.json:17-64` identifies the Angular 20 frontend stack.

### Major Components

1. **Browser/Angular SPA**: public shopping UI, authentication flows, profile, basket, checkout, support functions, Web3 interactions.
2. **Express API server**: request routing, authentication middleware, authorization checks, generated REST resources, file upload handling, logging, metrics.
3. **Relational datastore**: SQLite via Sequelize for users, baskets, cards, addresses, products, quantities, complaints, privacy requests, wallets, and security questions.
4. **Document datastore**: MarsDB collections for orders and product reviews.
5. **File storage**: local directories for uploaded images, complaint files, PDFs, logs, static files, and encryption keys.
6. **Security services**: JWT signing/verification, role checks, rate limits, CAPTCHA/image CAPTCHA, 2FA with TOTP.
7. **Observability**: Prometheus metrics and rotating access logs.
8. **External/client-side dependencies**: npm packages, Angular dependencies, Web3/ethers integrations, Swagger UI, PDF generation, XML/YAML parsers.

## 2. Trust Boundaries and Security Zones

### Public Zone: Internet and unauthenticated browser traffic

Entry points include product search, registration, login, feedback, CAPTCHA, product review reads, static files, Swagger docs, redirects, metrics, file upload endpoints, and Web3 endpoints. Evidence: `server.ts:593-646` defines many REST routes; `server.ts:285-286` exposes Swagger docs; `server.ts:715-718` exposes `/metrics`; `server.ts:307-313` exposes upload endpoints.

Controls expected at this boundary:

- Strict CORS allowlist, not global permissive CORS.
- Authentication where data is non-public.
- Input validation with schemas.
- Rate limiting on login, reset password, 2FA, checkout, upload, search, and Web3 endpoints.
- Safe error handling and no stack trace disclosure.

### Authenticated Customer Zone

This zone includes basket, checkout, wallet, address, cards, memories, data export, profile, order history, privacy requests, and review mutation operations. Evidence: `server.ts:354-399`, `server.ts:423-453`, `server.ts:618-627`, and `server.ts:621-635` attach authorization or user-id binding to selected routes.

Controls expected at this boundary:

- JWT validation with strong keys and current algorithms.
- Object-level authorization for every user-owned resource.
- CSRF protection if cookies are used.
- Session revocation, token rotation, and short-lived refresh-token design.
- Sensitive field filtering for cards, passwords, TOTP secrets, and PII.

### Privileged/Internal Zone

Privileged operations include accounting/admin endpoints, inventory/quantity management, all-order visibility, delivery status changes, application configuration/version retrieval, logs, key files, and metrics. Evidence: `server.ts:622-623` uses `security.isAccounting()` for all orders and delivery status; `server.ts:430` protects quantity changes with role plus IP filter; `server.ts:276-283` serves encryption-key and log directories; `server.ts:604-605` exposes admin configuration/version routes.

Controls expected at this boundary:

- Dedicated admin authentication with MFA.
- Server-side role enforcement independent of client claims.
- Network restrictions for metrics/logs/admin operations.
- Immutable audit logging.
- No public serving of keys, logs, or internal directory listings.

### Data Store Boundary

Express crosses into SQLite/Sequelize and MarsDB. User input must be parameterized and constrained before crossing this boundary. Evidence: `models/index.ts:30-40` for SQLite and `data/mongodb.ts:9-10` for MarsDB.

### File System Boundary

Uploads, generated PDFs, logs, and static serving cross into the local filesystem. Evidence: `server.ts:307-313` upload routes; `server.ts:681-706` multer memory/disk configuration; `routes/order.ts:41-45` creates order PDFs under `ftp/`; `server.ts:267-283` serves FTP, key, and log directories.

## 3. Critical Assets

### PII and Customer Data

- User email, username, last login IP, profile image, TOTP status/secret: `models/user.ts:25-34`.
- Address data including full name, mobile number, postal code, street, city, state, country: `models/address.ts:19-28`.
- Order history and product purchases: `routes/order.ts:158-170`, `data/mongodb.ts:10`.
- Product reviews and memories: `data/mongodb.ts:9`, `routes/dataExport.ts:72-101`.

### Credentials and Authentication Secrets

- Password hashes: `models/user.ts:74-78`.
- JWT public/private keys and hardcoded HMAC materials: `lib/insecurity.ts:22-24`, `lib/insecurity.ts:43-44`, `lib/insecurity.ts:54-57`.
- TOTP secrets: `models/user.ts:113-116`.
- Cookies and bearer tokens: `lib/insecurity.ts:188-199`.

### Payment and Financial Assets

- Cardholder data: `models/card.ts:19-25`, `models/card.ts:38-62`.
- Wallet balances and bonus points: `routes/order.ts:140-152`, `server.ts:624-625`.
- Basket state, coupon discounts, quantities, and inventory: `models/basket.ts:23-39`, `routes/order.ts:72-75`, `routes/order.ts:105-127`.

### Operational and Security Assets

- Access logs and audit rotation metadata: `server.ts:329-338`.
- Metrics: `server.ts:715-718`.
- Encryption/JWT key files: `server.ts:276-278`, `lib/insecurity.ts:22-24`.
- Application configuration and Swagger definitions: `server.ts:137`, `server.ts:604-605`.

## 4. Entry Points and Data Flows

### Key HTTP Entry Points

- Authentication: `POST /rest/user/login` (`server.ts:594`), reset password (`server.ts:596`), change password (`server.ts:595`), security question (`server.ts:597`), 2FA (`server.ts:456-473`).
- Customer APIs: basket, checkout, wallet, addresses, cards, profile, memories, order history, data export (`server.ts:397-453`, `server.ts:618-628`, `server.ts:662-664`).
- Product and review APIs: product search and review operations (`server.ts:600`, `server.ts:631-635`).
- File upload and serving: generic upload, profile images, memories, FTP files, logs, key files (`server.ts:267-283`, `server.ts:307-313`).
- Admin/accounting/operations: quantity, all orders, delivery status, metrics, app config, Swagger (`server.ts:430`, `server.ts:622-623`, `server.ts:715-718`, `server.ts:604-605`, `server.ts:285-286`).
- Web3 endpoints: key submission, NFT verification/listeners, wallet exploit address listener (`server.ts:637-642`).

### Authentication and Authorization Model

The application uses JWTs signed with RS256 and verified by `express-jwt`. Login creates or retrieves a basket, signs a token, stores the authenticated user in an in-memory token map, and returns token plus basket id. Evidence: `routes/login.ts:18-27`. Authorization middleware is applied per route in `server.ts:350-453` and role helpers are in `lib/insecurity.ts:144-185`.

Production concerns:

- Password hashing uses MD5 (`lib/insecurity.ts:43`, `models/user.ts:77`) and must be replaced with Argon2id or bcrypt with per-user salts.
- JWT private key material is hardcoded (`lib/insecurity.ts:23`) and must move to secret management with rotation.
- Authenticated users are tracked in process memory (`lib/insecurity.ts:72-93`), which does not scale across instances and complicates revocation.
- Cookie assignment lacks visible secure/httpOnly/sameSite flags (`lib/insecurity.ts:195`).
- Role checks rely on decoded token role claims (`lib/insecurity.ts:156-170`); privileged actions should be checked against authoritative server-side user state.

### Representative Data Flows

1. **Login flow**: Browser submits email/password to `POST /rest/user/login`; backend queries Users, creates basket if needed, signs JWT, returns token and basket id. Sensitive flow includes credentials and JWT. Evidence: `routes/login.ts:32-55`.
2. **Checkout flow**: Authenticated user calls `/rest/basket/:id/checkout`; backend loads basket, computes totals, updates inventory/wallet, writes PDF to `ftp/`, inserts order into MarsDB. Evidence: `routes/order.ts:33-50`, `routes/order.ts:72-75`, `routes/order.ts:140-170`.
3. **Payment methods flow**: Authenticated user creates/lists/deletes cards via `/api/Cards`; backend binds UserId and masks card numbers on reads. Evidence: `server.ts:437-441`, `routes/payment.ts:18-35`, `routes/payment.ts:39-77`.
4. **Data export flow**: Authenticated user requests personal-data export; backend collects memories, orders, reviews, and returns JSON. Evidence: `server.ts:618-619`, `routes/dataExport.ts:15-108`.
5. **File upload flow**: Browser uploads ZIP/XML/YAML/profile/memory files through multer; backend parses or stores content. Evidence: `server.ts:307-313`, `routes/fileUpload.ts:27-139`, `server.ts:681-706`.
6. **Observability flow**: All requests pass metrics middleware and access logging; metrics are served over HTTP. Evidence: `server.ts:207-209`, `server.ts:329-338`, `server.ts:715-718`.

## 5. Threat Analysis Using STRIDE

Severity reflects production business impact. Likelihood reflects how reachable the pattern appears from code review.

### 5.1 Authentication and Session Management

**Spoofing — CRITICAL / High likelihood**  
Attackers may impersonate users if weak password hashing or exposed signing keys are exploited. MD5 password hashing (`lib/insecurity.ts:43`, `models/user.ts:77`) enables fast offline cracking. Hardcoded JWT private key (`lib/insecurity.ts:23`) creates universal token-forgery risk if source or image is exposed. Remediate with Argon2id/bcrypt, managed secrets, key rotation, token audience/issuer validation, and device/session revocation.

**Tampering — HIGH / Medium likelihood**  
JWT role claims are used for privileged checks (`lib/insecurity.ts:156-170`). If signing or verification fails, attackers could tamper with roles or deluxe status. Remediate by loading user roles from the database for privileged operations and applying centralized authorization policies.

**Repudiation — HIGH / Medium likelihood**  
Access logs exist (`server.ts:329-338`) but there is no clear immutable audit trail for login, 2FA, password reset, profile changes, payment changes, checkout, or admin/accounting actions. Add structured security audit events with actor id, object id, decision, IP, user agent, request id, and tamper-evident storage.

**Information Disclosure — HIGH / Medium likelihood**  
Cookies are set without visible secure flags (`lib/insecurity.ts:195`), tokens are returned to the browser (`routes/login.ts:23-26`), and auth state is cached in memory (`lib/insecurity.ts:72-93`). Enforce Secure, HttpOnly, SameSite cookies or a hardened bearer-token model with refresh rotation.

**Denial of Service — MEDIUM / Medium likelihood**  
Only some auth endpoints have rate limits (`server.ts:341-347`, `server.ts:456-471`). Login itself lacks visible rate limiting at route registration (`server.ts:594`). Add account/IP/device-aware throttling, credential stuffing detection, lockout with risk controls, and MFA enforcement for privileged accounts.

**Elevation of Privilege — CRITICAL / Medium likelihood**  
Generated user CRUD endpoints and registration flow must prevent client-controlled role assignment. Generated finale resources are created for User (`server.ts:482-505`), and user role exists in the model (`models/user.ts:80-99`). Validate allowed fields on registration and prevent mass assignment of role, deluxeToken, totpSecret, and isActive.

### 5.2 Product Search and Database Access

**Tampering / Information Disclosure — CRITICAL / High likelihood**  
Search builds SQL with raw user input (`routes/search.ts:21-23`), and login also interpolates credentials into SQL (`routes/login.ts:34`). Attackers can extract users, cards, orders, schema, or modify data depending on driver behavior. Replace raw interpolation with Sequelize parameter binding or query builders everywhere.

**Denial of Service — HIGH / Medium likelihood**  
Unbounded expensive search patterns can degrade SQLite. `routes/search.ts:22` truncates to 200 characters, which helps but is insufficient. Add indexed search, query timeouts, rate limits, and pagination.

### 5.3 Customer-Owned Resources: Basket, Address, Card, Orders, Wallet

**Spoofing / IDOR — CRITICAL / High likelihood**  
Customer-owned resources use ids in paths such as `/rest/basket/:id` and `/rest/basket/:id/checkout` (`server.ts:397-399`, `server.ts:601-603`). `placeOrder()` loads basket by path id (`routes/order.ts:35-37`) and does not visibly verify that the basket belongs to the authenticated user before processing. Enforce object ownership checks on every route and reject mismatched `UserId`/basket ownership.

**Tampering — HIGH / Medium likelihood**  
Checkout trusts request body details for delivery and payment selection (`routes/order.ts:118-126`, `routes/order.ts:140-142`). Attackers may manipulate delivery, payment id, address id, or wallet usage. Validate that paymentId/addressId belong to the authenticated user and use server-side basket totals only.

**Information Disclosure — HIGH / Medium likelihood**  
Cards are masked on read (`routes/payment.ts:31-32`, `routes/payment.ts:57-58`) but the model stores full card numbers (`models/card.ts:38-46`). For production, do not store PAN unless PCI DSS scope is intended; tokenize via a payment processor and store only token, brand, and last four digits.

**Repudiation — HIGH / Medium likelihood**  
Orders, wallet changes, card deletion, and address updates need audit events. Current order code writes business data (`routes/order.ts:158-170`) but no tamper-evident audit event is visible.

### 5.4 File Uploads, Static File Serving, and Local Filesystem

**Tampering / Path Traversal — CRITICAL / High likelihood**  
ZIP entries are written with entry-controlled paths under `uploads/complaints/` (`routes/fileUpload.ts:40-45`). The path check uses `absolutePath.includes(path.resolve('.'))`, which is not a robust containment check. Use canonical path normalization, reject absolute paths and `..`, write to isolated storage, and malware-scan uploads.

**Information Disclosure — CRITICAL / High likelihood**  
Directory browsing and file serving are enabled for `/ftp`, `/encryptionkeys`, and `/support/logs` (`server.ts:267-283`). In production, logs and keys must never be web-served; public file downloads must use authorization checks and opaque object identifiers.

**XXE / Parser Abuse — HIGH / Medium likelihood**  
XML parsing enables entity expansion in a VM context (`routes/fileUpload.ts:81-87`), and YAML parsing uses `yaml.load` (`routes/fileUpload.ts:113-119`). Disable external entity resolution, use safe YAML schema, remove deprecated parsers, and isolate parsing in a sandboxed worker with CPU/memory limits.

**Denial of Service — HIGH / Medium likelihood**  
Upload memory storage has a 200 KB limit (`server.ts:681`), which helps, but XML/YAML parsing can still burn CPU/memory (`routes/fileUpload.ts:90-127`). Apply per-route limits, content-type sniffing, queueing, timeout, and backpressure.

### 5.5 Admin, Accounting, Metrics, Logs, and Configuration

**Information Disclosure — HIGH / High likelihood**  
Metrics are publicly registered at `/metrics` (`server.ts:715-718`), Swagger docs are exposed at `/api-docs` (`server.ts:285-286`), app config is exposed at `/rest/admin/application-configuration` (`server.ts:604-605`), and logs/key directories are served (`server.ts:276-283`). Restrict operational endpoints to internal networks and admin auth; redact secrets and business-sensitive telemetry.

**Elevation of Privilege — HIGH / Medium likelihood**  
Accounting checks use JWT role claims (`lib/insecurity.ts:156-164`) and an IP filter configured with a placeholder-like address (`server.ts:430`). Use centralized RBAC/ABAC, trusted proxy handling, and database-backed role validation.

**Repudiation — HIGH / Medium likelihood**  
No immutable admin audit logs are visible for all-orders reads or delivery status changes (`server.ts:622-623`). Add audit requirements and alerting for privileged data access.

### 5.6 Frontend, Browser, and Cross-Origin Controls

**Tampering / XSS — HIGH / Medium likelihood**  
User-controlled fields include username, email, reviews, profile images, memories, captions, and product reviews. Sanitization exists for some user fields (`models/user.ts:48-54`, `models/user.ts:60-71`), but coverage should be verified across all rendered data. Enforce Angular template escaping, server-side validation, CSP, and sanitize rich text consistently.

**Spoofing / CSRF — HIGH / Medium likelihood**  
CORS is globally permissive (`server.ts:180-182`) and cookies are parsed/signed (`server.ts:289`, `lib/insecurity.ts:188-199`). If cookies authenticate requests, CSRF risk is high. Restrict CORS to trusted origins, set SameSite, and add CSRF tokens for state-changing endpoints.

### 5.7 Web3 and External Integrations

**Spoofing / Tampering — HIGH / Medium likelihood**  
Web3 endpoints accept wallet/NFT/key-related inputs (`server.ts:637-642`). Attackers may submit forged wallet claims, replay signatures, or manipulate chain/network assumptions. Require nonce-based signed messages, chain-id validation, replay protection, and server-side verification independent of frontend state.

### 5.8 Supply Chain and Runtime Dependencies

**Tampering / Information Disclosure — HIGH / Medium likelihood**  
The backend includes sensitive parsing, JWT, XML/YAML, unzip, Web3, and file-handling packages (`package.json:118-189`). Frontend includes Web3, CodeMirror, highlighting, and Solidity compilation packages (`frontend/package.json:39-63`). Maintain SBOMs (`package.json:74`, `frontend/package.json:8`), lockfile integrity, SCA gating, provenance, and dependency update SLAs.

## 6. Vulnerability Pattern Library

### SQL Injection

Vulnerable pattern:

```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
```

Evidence: `routes/login.ts:34`, `routes/search.ts:23`.

Safe pattern:

```ts
await models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email, passwordHash }, model: UserModel, plain: true }
)
```

### IDOR / Missing Object Ownership

Vulnerable pattern:

```ts
BasketModel.findOne({ where: { id: req.params.id } })
```

Evidence: `routes/order.ts:35-37`.

Safe pattern:

```ts
BasketModel.findOne({ where: { id: req.params.id, UserId: req.auth.data.id } })
```

### Weak Password Storage

Vulnerable pattern:

```ts
crypto.createHash('md5').update(password).digest('hex')
```

Evidence: `lib/insecurity.ts:43`, `models/user.ts:77`.

Safe pattern: use Argon2id or bcrypt with unique salts and adaptive cost, plus password breach checks.

### Hardcoded Secrets and JWT Keys

Vulnerable pattern: key material embedded in source code. Evidence: `lib/insecurity.ts:22-24`, `lib/insecurity.ts:44`.

Safe pattern: load keys from a managed secret store or KMS, rotate keys, and publish JWKS with `kid` support.

### Path Traversal in Upload Extraction

Vulnerable pattern:

```ts
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) { write(fileName) }
```

Evidence: `routes/fileUpload.ts:40-45`.

Safe pattern:

```ts
const root = path.resolve('uploads/complaints')
const target = path.resolve(root, fileName)
if (!target.startsWith(root + path.sep)) throw new Error('invalid path')
```

### Unsafe XML/YAML Parsing

Vulnerable pattern: XML `noent: true` and YAML `yaml.load` on user input. Evidence: `routes/fileUpload.ts:81-87`, `routes/fileUpload.ts:113-119`.

Safe pattern: disable external entities, use `FAILSAFE_SCHEMA` or JSON schema validation, and parse in an isolated process.

### Sensitive File Exposure

Vulnerable pattern: serving keys/logs/directories via Express static/index middleware. Evidence: `server.ts:267-283`.

Safe pattern: never serve secret/log directories; expose downloads through authorization-checked object storage links with explicit allowlists.

### CORS Misconfiguration

Vulnerable pattern:

```ts
app.options('*', cors())
app.use(cors())
```

Evidence: `server.ts:180-182`.

Safe pattern: configure explicit origins, methods, headers, and credentials policy per environment.

## 7. Prioritized Threat Scenarios and Remediation Areas

1. **CRITICAL: Account takeover through SQL injection and weak password hashing.** Fix all raw SQL, add login throttling, migrate password hashes to Argon2id/bcrypt, and rotate all credentials.
2. **CRITICAL: JWT forgery or mass privilege escalation from hardcoded signing keys and role claims.** Move keys to KMS/secret store, rotate, implement `kid`, verify issuer/audience, and use server-side role authorization.
3. **CRITICAL: Customer data exposure through IDOR in basket/order/address/payment flows.** Add centralized object ownership checks and authorization tests for every user-owned endpoint.
4. **CRITICAL: Secret/log leakage from web-served directories.** Remove public `/encryptionkeys` and `/support/logs`; restrict `/ftp`; move logs/secrets outside web root.
5. **CRITICAL: Unsafe file uploads enabling path traversal or parser exploitation.** Replace ZIP extraction and XML/YAML parsing with hardened libraries and strict validation.
6. **HIGH: Payment data handling creates PCI exposure.** Tokenize card data, remove PAN storage, encrypt any regulated payment metadata, and document PCI scope.
7. **HIGH: Missing or inconsistent audit logging.** Implement immutable security/business audit events for auth, checkout, card changes, data export, admin/accounting access, and role changes.
8. **HIGH: Public operational endpoints leak internals.** Restrict `/metrics`, `/api-docs`, app configuration, logs, and admin APIs to internal/admin contexts.
9. **HIGH: Permissive CORS and cookie/session hardening gaps.** Restrict CORS, add CSRF protection where needed, and enforce secure cookie attributes.
10. **MEDIUM: Supply-chain and parser-heavy dependency risk.** Keep SBOMs, SCA gates, dependency pinning/provenance, and sandbox risky parsers.

## 8. Likely Attacker Profiles

- **Unauthenticated internet attacker:** probes search, login, upload, static files, redirects, and metrics for injection and disclosure.
- **Credential-stuffing actor:** targets login, password reset, and 2FA endpoints to take over accounts.
- **Authenticated malicious customer:** attempts IDOR against baskets, orders, cards, addresses, data export, wallet, and reviews.
- **Fraudster:** manipulates coupons, wallet balance, delivery/payment ids, order quantities, and checkout totals.
- **Malicious file uploader:** uploads ZIP/XML/YAML/images to trigger traversal, parser bugs, malware hosting, or DoS.
- **Insider or compromised admin/accounting user:** abuses all-order visibility, delivery status changes, inventory access, logs, and configuration.
- **Supply-chain attacker:** targets npm dependencies, build scripts, package lockfiles, Docker images, and CI artifacts.

## 9. Security Testing Strategy

- Add SAST rules for raw `sequelize.query` template strings, `crypto.createHash('md5')`, hardcoded PEM/HMAC secrets, `yaml.load`, `noent: true`, `serveIndex`, public logs/keys, and unsafe `path.resolve` checks.
- Add API authorization tests for every `:id` route to verify cross-user access is denied.
- Add DAST tests for SQL injection, XSS, file upload traversal, XXE, CORS, CSRF, open redirect, and rate limiting.
- Add unit tests around checkout total calculation, delivery/payment/address ownership, and wallet updates.
- Add dependency scanning, SBOM attestation, npm audit/SCA gates, and container scanning.
- Add log review tests ensuring no passwords, tokens, PANs, TOTP secrets, or full PII are logged.
- Add compliance checks for PCI DSS card storage, GDPR data export/erasure, and SOC 2 auditability/change management.

## 10. Auditor Priorities

1. **Authentication controls:** password hashing migration, key management, token lifecycle, MFA, rate limiting, and session revocation.
2. **Authorization coverage:** object-level access checks on basket, order, card, address, wallet, data export, and admin/accounting APIs.
3. **Sensitive data handling:** payment tokenization, TOTP secret protection, PII minimization, encryption at rest, and log redaction.
4. **Injection remediation:** all raw SQL, NoSQL query construction, XML/YAML parsing, upload extraction, and frontend rendering paths.
5. **Operational exposure:** public metrics, Swagger, logs, keys, config endpoints, directory listing, and debug error handling.
6. **Audit evidence:** immutable records for login, password reset, 2FA, checkout, card/address changes, exports, role changes, and privileged views.
7. **Privacy/compliance:** GDPR export/erasure correctness, retention schedules, consent/cookie controls, and data subject request tracking.
8. **PCI DSS scope:** verify no full PAN/CVV storage, payment processor tokenization, network segmentation, and key management.

## 11. Assumptions and Accepted Risks

- The application is assumed to process real customer accounts, addresses, orders, wallet balances, and payment methods.
- Local SQLite/MarsDB storage is assumed to be a deployable production persistence layer unless replaced by managed databases.
- No security-team contacts were provided; `output/security-config.json` keeps contacts empty.
- Compliance requirements are inferred from e-commerce production context: PCI DSS for payment data, GDPR for personal data export/erasure, and SOC 2 for operational controls.
- No risks are accepted by default. Items listed as CRITICAL/HIGH should be tracked as remediation work before production launch.

## 12. Version Changelog

- **1.0.0 (2026-05-10):** Initial production-oriented STRIDE threat model generated from repository evidence, explicitly treating the app as a real e-commerce platform rather than a training application.
