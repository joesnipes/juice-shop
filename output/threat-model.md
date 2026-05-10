# Production Threat Model: Juice Shop E-Commerce Application

**Version:** 1.0.0  
**Date:** 2026-05-10  
**Scope:** This model treats OWASP Juice Shop as a real production e-commerce application, not as an intentionally vulnerable training app. It covers the Node.js/Express API, Angular front end, generated REST resources, SQLite/MarsDB data stores, file storage, uploads, order/PDF generation, authentication, profile, review, privacy, and B2B order flows.

## 1. System Overview

Juice Shop is a single web application with an Angular client served from `frontend/dist/frontend` and a Node.js/Express backend started by `app.js` and `server.js`. The backend exposes custom REST endpoints under `/rest`, generated resource endpoints under `/api`, B2B endpoints under `/b2b/v2`, file-serving endpoints under `/ftp`, `/encryptionkeys`, and `/support/logs`, upload endpoints, Swagger documentation, and Socket.IO events.

Primary technologies observed:

- **Runtime/frameworks:** Node.js, Express, Angular, Socket.IO.
- **Authentication:** JWT bearer tokens using `jsonwebtoken` and `express-jwt`; optional TOTP using `otplib`; cookies also used for profile image upload.
- **Datastores:** SQLite via Sequelize at `data/juiceshop.sqlite`; MarsDB collections for reviews and orders.
- **File storage:** local directories including `ftp`, `uploads/complaints`, `logs`, `encryptionkeys`, and public image upload folders.
- **Parsing/rendering:** `body-parser`, `multer`, `libxmljs2`, `unzipper`, `pdfkit`, `swagger-ui-express`.
- **Controls present:** selected Helmet headers, some route authorization middleware, captcha on feedback/data export, rate limits on password reset and TOTP endpoints, file upload size limit, Swagger/API routing, access logs.

Production assumption: the app handles real customer accounts, carts, orders, product data, support complaints, privacy requests, B2B orders, profile images, and compliance requests.

## 2. Assets

### High-value data assets

- **Customer identity data:** email, username, profile image, last login IP, account activity, privacy/export/erasure requests.
- **Authentication data:** password hashes, JWTs, JWT signing keys, TOTP secrets, security answers, reset-password answers/tokens, active session cache.
- **Commerce data:** baskets, basket items, coupons, products, prices, order confirmations, order PDFs, order history, reward/bonus points.
- **User-generated content:** product reviews, feedback, complaints, B2B order data, uploaded files, profile image URLs/files.
- **Operational data:** access logs, support logs, Swagger/API documentation, server configuration, source/package metadata.
- **Cryptographic material:** `encryptionkeys/*`, hardcoded/private JWT key material, coupon/HMAC secrets.

### Business assets

- Revenue integrity: product prices, discounts, coupons, order totals, inventory/product visibility.
- Brand trust: product catalog, reviews, customer support and privacy processes.
- Availability: storefront, checkout, order generation, account login, B2B ordering.
- Compliance posture: GDPR-like data export/erasure processes and audit evidence.

## 3. Users and Roles

- **Anonymous visitor:** browse products, search, view public assets, register, submit feedback where allowed.
- **Registered customer:** login, manage basket, checkout, use coupons, write/like reviews, update profile, export data, request erasure, configure 2FA.
- **Admin/operator:** manage products/users/application data, view operational endpoints, troubleshoot logs, handle support/privacy requests.
- **B2B customer/integrator:** submit structured orders through `/b2b/v2/orders`.
- **Support/privacy agent:** handle complaints, uploaded files, privacy requests, erasure requests, exports.
- **External service:** profile image URL sources and product image download sources.
- **Attacker personas:** unauthenticated internet attacker, malicious customer, compromised customer, malicious B2B partner, insider/operator, automated bot, supply-chain attacker.

## 4. Trust Boundaries and Security Zones

1. **Public internet to Express app:** all browser/API traffic crosses an untrusted boundary. Required controls: HTTPS termination, strict input validation, authentication, rate limiting, CSRF/CORS policy, request size limits, WAF/bot controls.
2. **Anonymous to authenticated zone:** `/rest/user/login`, `/api/Users`, TOTP verification, and JWT issuance transition users into authenticated state. Required controls: strong credential storage, MFA, lockout, secure JWT signing/validation, session revocation.
3. **Authenticated customer to customer-owned resources:** basket, order, profile, review, privacy export, and erasure endpoints must enforce object ownership on every resource ID.
4. **Customer to admin/operator functionality:** admin application endpoints, generated `/api/*` resources, support logs, product mutation, and user records require role-based access control, not just authentication.
5. **Application to databases:** SQL and MarsDB queries cross into trusted persistence. Required controls: parameterized queries, ORM constraints, least-privileged DB access, encryption at rest, migrations.
6. **Application to filesystem:** uploads, zip extraction, profile images, order PDFs, logs, FTP files, encryption key files, and static assets cross a high-risk boundary. Required controls: canonical path validation, allowlisted extensions/MIME, malware scanning, no directory listing, private object storage.
7. **Application to external URLs:** profile image URL fetch and product image download are SSRF-sensitive egress boundaries. Required controls: URL allowlists, DNS/IP blocklists, no internal address access, content limits/timeouts.
8. **Application to parsing/evaluation engines:** XML parsing, zip extraction, PDF generation, and B2B order evaluation are unsafe-code/data boundaries. Required controls: disable XML entities, sandbox isolation, no dynamic evaluation, CPU/memory limits.

## 5. Entry Points and Attack Surface

- **Authentication/account:** `POST /rest/user/login`, `POST /api/Users`, `GET /rest/user/change-password`, `POST /rest/user/reset-password`, `GET /rest/user/security-question`, `/rest/2fa/*`.
- **Commerce:** `/api/BasketItems`, `/rest/basket/:id`, `/rest/basket/:id/checkout`, `/rest/basket/:id/coupon/:coupon`, `/rest/track-order/:id`.
- **Catalog/reviews:** `/rest/products/search`, generated `/api/Products`, `/rest/products/:id/reviews`, `/rest/products/reviews`.
- **Privacy/profile:** `/profile`, `/profile/image/file`, `/profile/image/url`, `/rest/data-export`, `/rest/user/erasure-request`, `/api/PrivacyRequests`.
- **Uploads/B2B:** `POST /file-upload`, `POST /b2b/v2/orders`.
- **Files/admin/ops:** `/ftp`, `/ftp/:file`, `/encryptionkeys`, `/support/logs`, `/api-docs`, `/rest/admin/application-version`, `/rest/admin/application-configuration`.
- **Redirects/static:** `/redirect`, static frontend assets, image/language assets, hidden file routes.

## 6. Key Data Flows

1. **Login and session:** credentials enter `/rest/user/login`; server queries `Users`, checks optional TOTP, signs JWT, stores token-to-user mapping in memory, returns token and basket ID.
2. **Registration:** anonymous user submits account data to `/api/Users`; Sequelize persists email, password hash, profile fields, and optional security data.
3. **Shopping/checkout:** authenticated user modifies basket; checkout reads basket/products, applies coupon, generates PDF in `ftp`, inserts masked order into MarsDB, returns `/ftp/order_*.pdf` link.
4. **Product search:** query string `q` enters `/rest/products/search`, queries SQLite products, returns matching catalog data.
5. **Reviews:** product review endpoints read/write MarsDB reviews and expose author, message, likes, and liked-by lists.
6. **Complaint upload:** multipart file enters memory via multer, XML or zip is parsed/extracted, and files may be written to `uploads/complaints`.
7. **Profile image URL:** authenticated user supplies URL; server fetches remote content and writes it as a public image.
8. **Data export:** authenticated request plus captcha returns profile, order, and review data from MarsDB.
9. **B2B order:** authenticated B2B client sends order line data that is parsed/evaluated and returns customer/order metadata.

## 7. Key Abuse Cases

- Attacker logs in as another user via SQL injection, weak passwords, reset-question guessing, stolen JWT, or JWT key compromise.
- Customer changes basket/order IDs to view or checkout another user's basket.
- Customer forges coupons, manipulates product price/quantity, or creates negative-price orders.
- Attacker extracts password hashes, TOTP secrets, encryption keys, logs, or order PDFs through exposed file routes or injection.
- Attacker uploads XML/ZIP content to read local files, write outside upload directory, trigger parser DoS, or plant web-accessible files.
- Attacker uses profile image URL upload for SSRF to metadata services or internal admin routes.
- Attacker injects XSS in profile/review/product fields to steal JWTs or perform unauthorized actions.
- Malicious B2B partner abuses dynamic evaluation to execute code or exhaust CPU.
- Bot performs password spraying, reset-password abuse, cart/checkout DoS, or captcha bypass.
- Insider accesses logs/exports/admin endpoints without auditable authorization.

## 8. STRIDE Threat Analysis

### Authentication and Session Management

- **Spoofing (CRITICAL, High likelihood):** login builds raw SQL from email/password, password hashes use MD5, and private JWT key material is hardcoded. Attackers can impersonate customers/admins through SQL injection, password cracking, or key theft. **Controls/gaps:** JWT exists and TOTP is supported, but password hashing, query construction, key management, lockout, and MFA enforcement are insufficient.
- **Tampering (HIGH):** signed setup tokens and in-memory token maps can be abused if key material is compromised. **Gap:** no centralized revocation or rotation.
- **Repudiation (MEDIUM):** login and account changes are not tied to durable audit records. **Gap:** insufficient immutable audit logging.
- **Information Disclosure (HIGH):** TOTP secrets and password hashes are stored directly in user records; application responses and logs may reveal details. **Gap:** secrets not encrypted with KMS/HSM.
- **Denial of Service (MEDIUM):** limited rate limiting only on reset/TOTP, not login/registration broadly. **Gap:** no account lockout or bot detection.
- **Elevation of Privilege (CRITICAL):** `isAdmin` exists, but many endpoints use only `isAuthorized()`; generated APIs risk function-level authorization bypass. **Gap:** no centralized RBAC/ABAC policy.

### User, Admin, and Generated API Resources

- **Spoofing (HIGH):** generated `/api/Users/:id`, `/api/Products`, `/api/PrivacyRequests` rely on route middleware and may expose resources to any authenticated user. **Gap:** role and ownership checks are inconsistent.
- **Tampering (HIGH):** product creation, basket items, complaints, recycles, privacy requests, and review records can be modified through generated APIs if method/role checks are incomplete. **Control:** some `denyAll()` handlers exist; **gap:** allow/deny policy is scattered.
- **Repudiation (HIGH):** administrative mutations and privacy actions lack formal audit trails. **Gap:** no actor/action/result logging with integrity protection.
- **Information Disclosure (HIGH):** generated APIs expose broad model fields, support logs and configuration endpoints are routable. **Gap:** least-privilege response shaping and admin-only enforcement needed.
- **Denial of Service (MEDIUM):** list endpoints and generated resources may be enumerable without pagination/quotas. **Gap:** no global rate limits.
- **Elevation of Privilege (CRITICAL):** authenticated customers may reach admin-like functionality because authentication is not equivalent to authorization. **Gap:** implement explicit roles and policy tests.

### Commerce, Basket, Coupon, and Order Flow

- **Spoofing (HIGH):** basket ID returned to client and accepted in paths can be reused by other users if ownership is not checked. **Gap:** every basket/order endpoint must compare resource owner to authenticated subject.
- **Tampering (HIGH):** coupons are reversible/weakly encoded and basket item quantities/prices can lead to invalid totals. **Gap:** server-side price lookup, quantity bounds, coupon signing with expiration and campaign constraints.
- **Repudiation (MEDIUM):** order creation lacks non-repudiation, payment authorization trace, and durable audit fields. **Gap:** auditable order ledger.
- **Information Disclosure (HIGH):** order PDFs are written to public `/ftp` and identifiers include a short email-derived hash. **Gap:** private per-user storage and authorization before download.
- **Denial of Service (MEDIUM):** PDF generation and checkout can be abused to create files and consume disk. **Gap:** checkout throttling, async job quotas, cleanup.
- **Elevation of Privilege (HIGH):** manipulating basket IDs/coupons can grant discounts or access other orders. **Gap:** object authorization and business-rule validation.

### Search, Reviews, and User Content

- **Spoofing (MEDIUM):** review authorship can be forged if review routes trust request body rather than authenticated identity. **Gap:** bind author to JWT subject server-side.
- **Tampering (CRITICAL):** product search uses string-concatenated SQL; reviews/profile fields may carry stored XSS. **Gap:** parameterized queries and output encoding.
- **Repudiation (MEDIUM):** review edits/likes are not strongly audited. **Gap:** signed audit events for moderation.
- **Information Disclosure (CRITICAL):** SQL injection can disclose users/password hashes; XSS can disclose JWTs and personal data. **Control:** some legacy sanitization; **gap:** inconsistent and not context-aware.
- **Denial of Service (MEDIUM):** search is partially length-limited but still DB-expensive; review spam can grow unbounded. **Gap:** query budgets and anti-spam.
- **Elevation of Privilege (HIGH):** stored XSS can perform authenticated actions as victims/admins. **Gap:** CSP, HttpOnly/SameSite cookies, token isolation.

### File Upload, File Serving, and Filesystem Storage

- **Spoofing (LOW):** uploaded files may impersonate trusted documents/images. **Gap:** provenance and content signing not present.
- **Tampering (CRITICAL):** ZIP extraction writes paths derived from entries; XML parsing enables entity expansion/file disclosure; public file directories may be overwritten. **Gap:** safe archive extraction, disabled external entities, isolated storage.
- **Repudiation (MEDIUM):** uploads and downloads are not audit-linked to users and file hashes. **Gap:** immutable file activity log.
- **Information Disclosure (CRITICAL):** directory listing exposes `/ftp`, `/encryptionkeys`, `/support/logs`; order PDFs and keys/logs can leak. **Gap:** disable listing, remove key/log public routes, authorize downloads.
- **Denial of Service (HIGH):** XML entity expansion, zip bombs, large file generation, and parser timeouts can exhaust CPU/memory/disk. **Control:** multer file size limit; **gap:** no decompressed size/file count limits or malware scanning.
- **Elevation of Privilege (HIGH):** arbitrary file write can become code/static content execution or config tampering. **Gap:** write outside web root, canonicalize paths, use object storage.

### Profile Image URL Fetch and External Calls

- **Spoofing (MEDIUM):** remote image sources can pose as trusted assets. **Gap:** no image validation/proxy policy.
- **Tampering (HIGH):** attacker controls content written into public image path. **Gap:** content-type verification and re-encoding.
- **Repudiation (LOW):** no trace of fetched URL or image hash. **Gap:** audit URL fetches.
- **Information Disclosure (CRITICAL):** server-side request forgery can reach internal services, cloud metadata, localhost routes, or sensitive files via protocols if not constrained. **Gap:** strict URL allowlist and egress firewall.
- **Denial of Service (HIGH):** remote fetch can hang or stream excessive data. **Gap:** timeouts, byte limits, async workers.
- **Elevation of Privilege (HIGH):** SSRF can access admin/internal endpoints and pivot. **Gap:** network segmentation.

### B2B Order API and Dynamic Evaluation

- **Spoofing (MEDIUM):** B2B endpoint requires authentication but lacks partner-specific scopes. **Gap:** API client identity, mTLS/API scopes.
- **Tampering (CRITICAL):** `orderLinesData` is dynamically evaluated, creating code-injection/RCE risk. **Gap:** replace evaluation with JSON schema validation.
- **Repudiation (HIGH):** B2B submissions lack signed request IDs/idempotency/audit. **Gap:** non-repudiable partner logs.
- **Information Disclosure (HIGH):** evaluation errors can leak internals. **Gap:** generic errors and safe logging.
- **Denial of Service (HIGH):** loops/timeouts can consume CPU. **Control:** VM timeout; **gap:** sandbox is not a security boundary.
- **Elevation of Privilege (CRITICAL):** RCE can become full app/server compromise. **Gap:** remove dynamic evaluation and run workers with least privilege.

### Privacy, Data Export, and Erasure

- **Spoofing (HIGH):** export trusts bearer token and captcha; compromised tokens expose all personal export data. **Gap:** step-up auth for export/erasure.
- **Tampering (MEDIUM):** erasure/privacy request status could be changed via generated APIs if authorization is broad. **Gap:** workflow roles.
- **Repudiation (HIGH):** compliance actions require audit trails, retention decisions, and operator sign-off. **Gap:** formal compliance ledger.
- **Information Disclosure (HIGH):** export may include orders/reviews for other users if order ID/email matching is weak. **Gap:** strict joins by immutable user ID.
- **Denial of Service (MEDIUM):** repeated exports can be expensive. **Gap:** per-user quotas and async generation.
- **Elevation of Privilege (HIGH):** customers may access privacy records not theirs. **Gap:** object-level authorization.

## 9. Recommended Security Controls

### Immediate priority controls

1. Replace all string-built SQL with parameterized Sequelize queries.
2. Replace MD5 password hashing with Argon2id/bcrypt/scrypt with unique salts and migration handling.
3. Move JWT private keys, HMAC/coupon secrets, and TOTP encryption keys to managed secrets/KMS; rotate exposed keys.
4. Implement centralized RBAC/ABAC and object ownership checks for every `/api`, `/rest`, `/b2b`, file, admin, and privacy route.
5. Remove directory listing and public serving for `encryptionkeys`, logs, and order PDFs; use authenticated object download URLs.
6. Disable XML external entities; use safe XML parsers; safely extract ZIPs with canonical paths, decompression limits, file count limits, and AV scanning.
7. Remove dynamic evaluation from B2B order parsing; use JSON schema validation.
8. Add login/registration/reset rate limits, account lockout, bot protection, MFA step-up for export/erasure/admin actions.
9. Lock down CORS to trusted origins; add CSRF protection for browser-authenticated actions.
10. Apply output encoding, modern CSP, HttpOnly/Secure/SameSite cookies where cookies are used, and consistent input validation.

### Monitoring and governance controls

- Immutable audit logs for login, failed login, password reset, 2FA changes, admin changes, checkout, data export, erasure, file upload/download, and B2B orders.
- Security alerts for SQL errors, XSS payloads, SSRF attempts, archive traversal, anomalous discounts/negative totals, brute force, and mass enumeration.
- Dependency scanning and patching: current dependencies include old Express-era packages and vulnerable parser/evaluation libraries.
- Secrets scanning in CI and repository history.
- Threat-informed tests for IDOR, authz bypass, SQL injection, XSS, SSRF, upload traversal, XXE, RCE, and DoS.

## 10. Production Security Gaps Summary

- Authentication is present but weakened by SQL injection, weak hashing, hardcoded keys, limited lockout, and session revocation gaps.
- Authorization is route-scattered and often checks only authentication, not role or ownership.
- Sensitive files, logs, keys, and order documents are exposed through browsable local directories.
- User-controlled input reaches SQL, HTML contexts, XML parsers, archive extraction, SSRF fetches, and dynamic evaluation.
- Audit, monitoring, compliance workflows, and admin controls are insufficient for a real e-commerce production environment.
- Availability controls are incomplete for parsers, file generation, search, checkout, login, and B2B paths.

## 11. Security Testing Strategy

- **Automated SAST:** flag raw SQL concatenation, `vm.runInContext`, `notevil`, `request.get(userUrl)`, `libxml` with entity expansion, path joins with user input, public directory listing, hardcoded secrets.
- **DAST/API tests:** verify authentication, RBAC, object ownership, SQLi/XSS payload handling, upload restrictions, CORS, CSRF, rate limits, and error handling.
- **Business logic tests:** verify basket ownership, coupon integrity, price source-of-truth, quantity bounds, order PDF authorization, refund/negative-total prevention.
- **Abuse testing:** password spraying, account enumeration, zip bombs, XXE, SSRF to localhost/metadata IPs, B2B CPU exhaustion, search enumeration.
- **Compliance tests:** export returns only requester data; erasure creates auditable workflow; logs avoid sensitive data; retention is enforced.

## 12. Assumptions and Limitations

- This artifact is based on static repository inspection and does not include runtime penetration testing, infrastructure review, cloud configuration, payment-provider details, or production deployment topology.
- Because Juice Shop is intentionally vulnerable, this model reclassifies its deliberate challenge behaviors as production security gaps.
- No security team contacts or compliance framework requirements were provided; GDPR-like controls were considered because the app includes data export and erasure features.

## 13. Changelog

- **1.0.0 (2026-05-10):** Initial production-style STRIDE threat model for the Juice Shop repository.
