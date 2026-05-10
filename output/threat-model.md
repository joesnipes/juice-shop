# Production Threat Model: OWASP Juice Shop

Version: 1.0.0  
Updated: 2026-05-10  
Methodology: STRIDE  
Scope: Treat OWASP Juice Shop as a real production e-commerce, wallet, profile, B2B, and training-content application despite intentional weaknesses in the repository.

## 1. System Overview

Juice Shop is a Node.js/Express application with an Angular frontend and REST/API endpoints backed by SQLite through Sequelize plus MarsDB collections for reviews and orders. The application exposes public product browsing, authentication, profile management, file uploads, payment methods, wallet balance, checkout, order history, data export/erasure, metrics, Swagger documentation, WebSocket notifications, Web3 challenge endpoints, and static file directories.

Repository evidence:

- Entry points: `app.ts` imports `server.ts` and starts the HTTP server.
- Main router and middleware: `server.ts` registers CORS, Helmet, static assets, file uploads, generated Finale REST resources, custom REST endpoints, WebSocket startup, and `/metrics`.
- SQL data store: `models/index.ts` configures SQLite at `data/juiceshop.sqlite` and initializes user, card, basket, order-related, privacy, and challenge models.
- NoSQL-like stores: `data/mongodb.ts` creates MarsDB `posts` and `orders` collections.
- Authentication/session logic: `lib/insecurity.ts`, `routes/login.ts`, `routes/2fa.ts`, `routes/currentUser.ts`.
- High-risk entry points: `routes/fileUpload.ts`, `routes/profileImageUrlUpload.ts`, `routes/b2bOrder.ts`, `routes/search.ts`, `routes/basket.ts`, `routes/order.ts`, `routes/payment.ts`, `routes/dataExport.ts`, `routes/redirect.ts`.

## 2. Assets

### Critical assets

- User identities: emails, usernames, roles, activation state, TOTP secrets (`models/user.ts`).
- Password hashes: stored in `Users.password`; currently produced by `security.hash()` in `lib/insecurity.ts`.
- JWTs and signing material: hardcoded private key and public key handling in `lib/insecurity.ts`, key files served under `/encryptionkeys` in `server.ts`.
- Payment cards: full card number, cardholder name, expiry, user ID (`models/card.ts`).
- Wallet balances and bonus points: `models/wallet.ts`, `routes/wallet.ts`, checkout logic in `routes/order.ts`.
- Orders: `ordersCollection` records order ID, products, totals, payment ID, address ID, masked email (`routes/order.ts`, `data/mongodb.ts`).
- Addresses, baskets, product quantities, complaints, recycle requests, privacy requests.
- Uploaded content and generated PDFs: `ftp/`, `uploads/complaints/`, `frontend/dist/frontend/assets/public/images/uploads/`.
- Logs and observability data: `logs/access.log.*`, `/support/logs`, `/metrics`.

### Sensitive compliance scope

- PCI DSS-like scope: card storage in `models/card.ts` and `/api/Cards` routes.
- GDPR-like scope: data export and erasure (`routes/dataExport.ts`, `routes/dataErasure.ts`, privacy requests).
- Security operations data: logs, metrics, challenge activity, IP addresses.

## 3. Threat Actors

- Anonymous internet users browsing products, static files, Swagger docs, metrics, redirects, uploads, and authentication endpoints.
- Registered customers attempting to access other customers' baskets, cards, addresses, orders, profile data, wallet funds, or exports.
- Privileged users: admin/accounting/deluxe roles whose tokens or role checks may be abused.
- Automated bots performing credential stuffing, password reset attacks, upload bombs, SQLi, XSS, SSRF, scraping, and DoS.
- Malicious B2B integrators submitting XML/YAML/order-line payloads.
- Insider/developer/operator with repository or filesystem access to keys, logs, SQLite DB, generated PDFs, or uploads.
- Supply-chain adversaries targeting old/high-risk dependencies such as `jsonwebtoken`, `express-jwt`, `sanitize-html`, `libxmljs2`, `unzipper`, `notevil`, and frontend packages.

## 4. Trust Boundaries, Entry Points, and Data Flows

### Trust boundaries

1. Internet/Public zone -> Express app: all HTTP routes in `server.ts`, static files, uploads, WebSocket handshake, and Swagger UI.
2. Anonymous -> Authenticated zone: `/rest/user/login`, `/api/Users`, `/rest/2fa/*`, JWT issuance in `routes/login.ts` and verification in `lib/insecurity.ts`.
3. Authenticated user -> user-owned resources: baskets, cards, addresses, profile, memories, data export, orders, wallet.
4. Authenticated user -> privileged/admin/accounting operations: `/rest/order-history/orders`, `/rest/order-history/:id/delivery-status`, `/api/Quantitys/:id`, admin configuration/version endpoints.
5. Application -> filesystem: uploads, generated order PDFs, logs, encryption keys, static frontend files.
6. Application -> databases: Sequelize SQLite and MarsDB collections.
7. Application -> external network: profile image URL fetch in `routes/profileImageUrlUpload.ts`; Web3-related endpoints; browser redirects.
8. Browser -> Angular client -> API: local storage/cookies/tokens, XSS-sensitive rendering and client-side challenge handling.

### Primary entry points

- Public: `/rest/products/search`, `/api/Products`, `/api/Users` registration, `/rest/user/login`, `/rest/user/reset-password`, `/file-upload`, `/profile/image/url`, `/redirect`, `/api-docs`, `/metrics`, `/ftp`, `/support/logs`, `/encryptionkeys`, `/rest/captcha`, `/rest/image-captcha`, `/rest/chatbot/respond`, WebSocket events.
- Authenticated: `/rest/basket/:id`, `/api/BasketItems`, `/api/Cards`, `/api/Addresss`, `/rest/basket/:id/checkout`, `/rest/order-history`, `/rest/wallet/balance`, `/rest/deluxe-membership`, `/rest/user/data-export`, `/rest/memories`, `/profile`.
- Privileged: `/rest/order-history/orders`, `/rest/order-history/:id/delivery-status`, `/api/Quantitys/:id`, admin app config/version routes.
- B2B/Web3: `/b2b/v2/orders`, `/rest/web3/*`.

### Data flows

- Login: email/password body -> raw SQL query in `routes/login.ts` -> `Users` table -> JWT signed by `lib/insecurity.ts` -> token stored in in-memory `authenticatedUsers` and returned to browser.
- Product search: query string `q` -> raw SQL in `routes/search.ts` -> `Products` SQLite table -> JSON to browser.
- Checkout: basket ID and order details -> basket/product/quantity/card/wallet lookups -> generated PDF in `ftp/` -> order in MarsDB -> basket cleared and wallet adjusted.
- Payment method: API body -> Sequelize `Cards` table -> masked data returned, full PAN remains stored.
- Data export: Authorization header and CAPTCHA -> user-owned memories from SQLite, orders/reviews from MarsDB -> JSON export.
- File upload: multipart body -> memory/disk multer -> ZIP/XML/YAML parsers or profile image storage -> filesystem/static serving.
- Profile image URL: user-supplied URL -> server-side `fetch()` -> file write under frontend uploads or URL stored directly.
- Observability: every request -> morgan access logs and Prometheus metrics -> exposed via `/support/logs` and `/metrics`.

## 5. STRIDE Threat Analysis

### Spoofing identity

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| SQL injection login bypass lets attacker authenticate as any user | CRITICAL | HIGH | `routes/login.ts:34` interpolates `req.body.email` and hashed password into SQL | Account takeover, admin/accounting access, data theft | No parameterized query; passwords are MD5; rate limits are narrow |
| JWT signing key compromise/forgery | CRITICAL | HIGH | `lib/insecurity.ts:22-57` hardcoded private key, public key file; `/encryptionkeys` served in `server.ts:276-278` | Token forgery, role spoofing, wallet/order access | Uses RS256 but private key is in source; no rotation; no key isolation |
| Weak password hashing enables offline cracking | HIGH | HIGH | `security.hash()` uses MD5 at `lib/insecurity.ts:43`, user setter at `models/user.ts:74-78` | Account takeover after DB/log leak | No salt/adaptive KDF |
| 2FA brute force/session weaknesses | HIGH | MEDIUM | `/rest/2fa/verify` rate limit allows 100/5min in `server.ts:456-459`; tmp token signed by same JWT key in `routes/login.ts` | 2FA bypass or token abuse | Limited rate limit; audit tmp-token handling |
| WebSocket client spoofing | MEDIUM | MEDIUM | Socket.IO CORS only allows localhost in `registerWebsocketEvents.ts:20`, but auth is not required for challenge events | Notification tampering, challenge state abuse | No token binding or per-user namespace |

### Tampering with data

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| SQL injection modifies or extracts DB data | CRITICAL | HIGH | Raw SQL in `routes/search.ts:23`, `routes/login.ts:34` | Product/user/card/password disclosure or modification depending SQLite capabilities | No parameterized statements; only length limit in search |
| IDOR/missing ownership check for basket checkout | CRITICAL | HIGH | Middleware only `security.isAuthorized()` and `appendUserId()` for `/rest/basket/:id/order`; `placeOrder()` loads `BasketModel.findOne({ where: { id }})` without `UserId` | Check out/alter another user's basket, wallet side effects | Must bind basket ID to authenticated user/bid |
| Wallet balance manipulation | HIGH | HIGH | `routes/wallet.ts:27` increments by client-supplied `req.body.balance` after only card ownership check | Free funds, negative/large increments | No payment gateway confirmation, amount validation, idempotency |
| Product quantity/accounting API authorization bypass risk | HIGH | MEDIUM | `server.ts:430` combines `security.isAccounting()` with `IpFilter(['123.456.789'])`; role from token | Inventory tampering | Depends entirely on forge-resistant tokens and proxy/IP correctness |
| ZIP Slip/file overwrite | HIGH | MEDIUM | `routes/fileUpload.ts:41-46` writes `uploads/complaints/` + entry path; containment check uses `absolutePath.includes(path.resolve('.'))` | Arbitrary file write under process permissions | Weak path containment; no extraction allowlist |
| Profile/image upload overwrites predictable filenames | MEDIUM | MEDIUM | `server.ts:687-704`, `profileImageUrlUpload.ts:29` write user ID/name based files | Defacement, stored XSS via SVG/GIF, overwrite user asset | MIME extension checks are weak; SVG allowed from URL |

### Repudiation

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| Users can deny wallet/card/order changes | HIGH | MEDIUM | Wallet/card/order routes do not create immutable audit events; morgan logs only request metadata in `server.ts:329-338` | Fraud investigation failure | Need structured audit with actor, resource, before/after, correlation ID |
| Logs are publicly browsable | HIGH | HIGH | `/support/logs` directory and files registered in `server.ts:280-283` | Attackers can read/alter narratives, harvest tokens/PII if logged | Logs should be private, redacted, immutable, access-controlled |
| In-memory authenticated user map is not authoritative | MEDIUM | MEDIUM | `authenticatedUsers` object in `lib/insecurity.ts:72-93` | Session events lost on restart; weak forensic trail | Use server-side session/audit store or stateless claims with revocation logs |

### Information disclosure

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| SQLi leaks users/password hashes/schema | CRITICAL | HIGH | `routes/search.ts:23` and challenge code checks for leaked users/schema | Credentials and DB structure exposed | Parameterization and least-priv DB permissions absent |
| Key/log/static directory disclosure | CRITICAL | HIGH | `/encryptionkeys`, `/support/logs`, `/ftp` directory listings in `server.ts:267-283` | JWT key, order PDFs, logs, public files leaked | Do not expose operational directories |
| Full PAN stored in DB | HIGH | HIGH | `models/card.ts` stores `cardNum` integer; `routes/payment.ts` masks only response | PCI breach risk | Tokenize; do not store PAN; encryption at rest if unavoidable |
| Data export cross-user leakage | HIGH | MEDIUM | `routes/dataExport.ts:18-26` combines token lookup and `req.body.UserId` set by middleware, then searches orders by masked email | GDPR data disclosure if token/UserId binding fails | Strong ownership checks and auditable export flow needed |
| SSRF via profile image URL | HIGH | HIGH | `routes/profileImageUrlUpload.ts:24` fetches arbitrary URL | Internal metadata/service disclosure, file fetch pivot | No URL allowlist, IP range blocking, scheme validation, size limit |
| Verbose errors and deprecated parsers leak file contents | HIGH | MEDIUM | XML parser returns truncated parsed content/errors in `routes/fileUpload.ts:83-99` | Local file disclosure, stack/info leak | Disable XXE; generic errors |
| Metrics exposed | MEDIUM | HIGH | `/metrics` public in `server.ts:714-718` | Operational intelligence, endpoint discovery | Require auth/network allowlist |

### Denial of Service

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| Parser bombs and VM execution exhaustion | CRITICAL | MEDIUM | XML/YAML parsing in `routes/fileUpload.ts:75-139`; `b2bOrder.ts:21-24` runs eval in VM | CPU/memory exhaustion, process crash | Timeouts exist but parsing may allocate before timeout; use hardened parsers/queues |
| Unauthenticated expensive endpoints | HIGH | HIGH | Product search raw LIKE, `/metrics`, `/api-docs`, upload endpoints, CAPTCHA/image generation | Resource exhaustion | Minimal global rate limiting; request size limits inconsistent |
| SSRF downloads unbounded bodies | HIGH | MEDIUM | `profileImageUrlUpload.ts` streams arbitrary response to disk | Disk/network exhaustion | No content-length, timeout, max bytes, DNS/IP controls |
| Checkout race conditions | MEDIUM | MEDIUM | `routes/order.ts:72-75` decrements quantity without transaction around basket/order/wallet | Overselling, inconsistent balances | Need DB transactions and idempotency keys |

### Elevation of privilege

| Threat | Severity | Likelihood | Evidence | Impact | Existing mitigation/gaps |
|---|---:|---:|---|---|---|
| Role escalation through registration/generated REST resources | CRITICAL | HIGH | Finale resources for `/api/Users`; user role is a model field; registration hooks in `server.ts:478-516`; role validation allows admin/accounting | Admin/accounting access | Explicit server-side allowlist for registrable fields required |
| Forged JWT with hardcoded key changes role | CRITICAL | HIGH | `lib/insecurity.ts` hardcoded private key; `isAccounting()` trusts decoded `data.role` | Privileged routes, inventory/order manipulation | Key management and authorization service needed |
| B2B RCE/eval escape | CRITICAL | MEDIUM | `routes/b2bOrder.ts:21-24` evaluates `orderLinesData` using `notevil` inside VM | Server-side code execution | Remove eval; parse declarative schema only |
| IDOR from user-owned resources to other users | HIGH | HIGH | Basket retrieval explicitly detects cross-basket access in `routes/basket.ts:21-24` but still returns basket | Horizontal privilege escalation | Enforce ownership at query layer |
| Open redirect/phishing and token theft chain | MEDIUM | HIGH | `isRedirectAllowed()` uses `url.includes(allowedUrl)` in `lib/insecurity.ts:135-139` | Phishing, OAuth/token leakage if added later | Strict URL parsing and exact origin/path allowlist |

## 6. Top Prioritized Threats

1. CRITICAL: SQL injection in login/search (`routes/login.ts`, `routes/search.ts`) causing auth bypass and database disclosure.
2. CRITICAL: JWT key exposure/hardcoding plus weak token/session model (`lib/insecurity.ts`, `server.ts` `/encryptionkeys`) enabling role spoofing.
3. CRITICAL: RCE/eval and unsafe parser paths (`routes/b2bOrder.ts`, `routes/fileUpload.ts`) enabling code execution or DoS.
4. CRITICAL: Broken object-level authorization for baskets/checkout/cards/addresses/data export (`routes/basket.ts`, `routes/order.ts`, `routes/payment.ts`, `routes/address.ts`, `routes/dataExport.ts`).
5. HIGH: SSRF and stored content risk via profile image URL/upload (`routes/profileImageUrlUpload.ts`, `server.ts` multer config).
6. HIGH: Sensitive directories and observability exposed (`server.ts` `/ftp`, `/support/logs`, `/encryptionkeys`, `/metrics`).
7. HIGH: Payment and wallet business logic abuse (`models/card.ts`, `routes/wallet.ts`, `routes/order.ts`).
8. HIGH: XSS/stored active content in profiles, product reviews, memories, and uploaded SVG/GIF (`models/user.ts`, review routes, memory/profile upload routes).

## 7. Vulnerability Pattern Library for Downstream Analysis

### SQL injection

Vulnerable pattern:

```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
```

Safe pattern:

```ts
models.sequelize.query('SELECT * FROM Users WHERE email = ? AND deletedAt IS NULL', {
  replacements: [req.body.email],
  model: UserModel,
  plain: true
})
```

Audit files: `routes/login.ts`, `routes/search.ts`, any `sequelize.query()` use.

### IDOR/BOLA

Vulnerable pattern:

```ts
BasketModel.findOne({ where: { id: req.params.id } })
```

Safe pattern:

```ts
BasketModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
```

Audit files: `routes/basket.ts`, `routes/order.ts`, `routes/payment.ts`, `routes/address.ts`, `routes/orderHistory.ts`, `routes/dataExport.ts`, `routes/memory.ts`.

### SSRF

Vulnerable pattern:

```ts
const response = await fetch(req.body.imageUrl)
```

Safe pattern: parse URL, require `https`, allowlist hosts or route through a media proxy, block private/link-local/metadata IPs after DNS resolution, set timeouts and byte limits.

Audit file: `routes/profileImageUrlUpload.ts`.

### Unsafe archive extraction/path traversal

Vulnerable pattern:

```ts
fs.createWriteStream('uploads/complaints/' + entry.path)
```

Safe pattern: resolve the destination and require `dest.startsWith(base + path.sep)`; reject absolute paths and `..`; generate server-side names.

Audit files: `routes/fileUpload.ts`, `routes/fileServer.ts`, `routes/keyServer.ts`, `routes/logfileServer.ts`, `routes/quarantineServer.ts`.

### XXE/YAML bombs/RCE

Vulnerable pattern:

```ts
libxml.parseXml(data, { noent: true })
vm.runInContext('safeEval(orderLinesData)', sandbox)
```

Safe pattern: disable external entity resolution, parse with hardened size/depth limits, avoid eval entirely, and use declarative schemas.

Audit files: `routes/fileUpload.ts`, `routes/b2bOrder.ts`, dependencies `libxmljs2`, `js-yaml`, `notevil`.

### XSS/stored active content

Vulnerable pattern: storing user-controlled HTML/URLs/SVGs or rendering review/profile/memory fields without contextual encoding.

Safe pattern: output encode by context, sanitize with a maintained policy, reject active image types, and set CSP.

Audit files: `models/user.ts`, `routes/createProductReviews.ts`, `routes/updateProductReviews.ts`, `routes/memory.ts`, `routes/profileImageFileUpload.ts`, `routes/profileImageUrlUpload.ts`, Angular components rendering review/profile/memory data.

### Secrets exposure

Vulnerable pattern: source-controlled keys and static serving of operational directories.

Safe pattern: secrets from KMS/env, mounted outside web root, never served by Express, rotated on deploy.

Audit files: `lib/insecurity.ts`, `encryptionkeys/`, `server.ts`, Docker/deployment configs.

## 8. Security Testing Strategy

- Add automated SAST rules for template-string SQL, `sequelize.query`, `fetch(req.body|req.query)`, `vm.runInContext`, `safeEval`, `parseXml(...noent: true)`, `yaml.load`, archive extraction, and `express.static`/`serveIndex` of sensitive directories.
- Add DAST/API tests for every route listed in Section 4 with anonymous, customer A, customer B, accounting, admin, and expired/forged JWT contexts.
- Add BOLA regression tests: all `:id` parameters must be checked against the authenticated user or privileged role.
- Add upload tests: size limits, MIME sniffing, SVG/script payloads, ZIP traversal, XML external entities, YAML alias bombs.
- Add business logic tests: negative wallet top-up, replayed checkout, coupon manipulation, concurrent order inventory decrement.
- Add observability tests: `/metrics`, `/support/logs`, `/encryptionkeys`, `/ftp` require appropriate production access controls.

## 9. Assumptions and Accepted Risks

- This model intentionally treats training vulnerabilities as production defects.
- The app is assumed internet-facing behind a reverse proxy because `server.ts` enables `trust proxy`.
- Compliance requirements were inferred from card handling and privacy export/erasure functionality; confirm actual PCI DSS/GDPR scope with stakeholders.
- Challenge verification code, anti-cheat logic, and snippets are considered in-scope because they share the production process, database, filesystem, and routing stack.

## 10. Downstream Analysis Focus

Security review should prioritize files and route groups with direct evidence of critical impact:

- Auth/session/roles: `lib/insecurity.ts`, `routes/login.ts`, `routes/2fa.ts`, `routes/currentUser.ts`, `server.ts` auth middleware section.
- Raw database queries and generated REST: `routes/search.ts`, `routes/login.ts`, `server.ts` Finale resource setup, `models/*` setters/validation.
- Authorization/IDOR: `routes/basket.ts`, `routes/basketItems.ts`, `routes/order.ts`, `routes/payment.ts`, `routes/address.ts`, `routes/orderHistory.ts`, `routes/dataExport.ts`, `routes/memory.ts`.
- Upload/parsing/filesystem: `routes/fileUpload.ts`, `routes/profileImageFileUpload.ts`, `routes/profileImageUrlUpload.ts`, `routes/fileServer.ts`, `routes/keyServer.ts`, `routes/logfileServer.ts`, `routes/quarantineServer.ts`, multer config in `server.ts`.
- Business logic: `routes/wallet.ts`, `routes/order.ts`, `routes/coupon.ts`, `routes/deluxe.ts`, `models/card.ts`, `models/wallet.ts`.
- Exposure/ops: `server.ts` static `serveIndex` routes, `/metrics`, `/api-docs`, morgan logs.
- RCE/SSRF/eval: `routes/b2bOrder.ts`, `routes/fileUpload.ts`, `routes/profileImageUrlUpload.ts`, `routes/chatbot.ts`.
- Frontend XSS/token handling: Angular profile/review/memory/search/order components under `frontend/src/`.

## 11. Version Changelog

- 1.0.0: Initial production-style STRIDE model generated from repository evidence.
