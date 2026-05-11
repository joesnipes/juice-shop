# STRIDE Threat Model: Juice Shop Production Application

Version: 1.0.0  
Last updated: 2026-05-11T22:12:27Z  
Repository: `/Users/barrydawson/Desktop/repo/juice-shop`  
Scope: Treat this repository as a normal production e-commerce/customer self-service application, not as an intentionally vulnerable training app.

## 1. System Overview

Juice Shop is a TypeScript/Node.js web application with an Angular frontend, Express backend, REST-style APIs, generated CRUD APIs, file upload/download endpoints, WebSocket notifications, a chatbot, and lightweight local persistence.

### Primary technology stack

- **Frontend:** Angular application under `frontend/`, built into `frontend/dist/frontend` and served statically by Express.
- **Backend:** Express 4 in `server.ts`, route handlers in `routes/*.ts`.
- **Authentication/session:** JWT bearer tokens and a `token` cookie. Tokens are signed with RS256 using key material in `lib/insecurity.ts`/`encryptionkeys/` and tracked in an in-memory `authenticatedUsers` map.
- **Relational storage:** Sequelize with SQLite database at `data/juiceshop.sqlite`; models include users, baskets, basket items, products, quantities, cards, addresses, feedback, complaints, privacy requests, security answers/questions, wallets, and memories.
- **Document/local collections:** MarsDB collections for orders and reviews in `data/mongodb.ts`.
- **File storage:** Static frontend assets, uploads under `frontend/dist/frontend/assets/public/images/uploads/`, order PDFs and public files under `ftp/`, complaint uploads under `uploads/complaints/`, logs under `logs/`, and key files under `encryptionkeys/`.
- **Operational endpoints:** `/metrics`, `/api-docs`, `/.well-known/security.txt`, `/support/logs`, and directory/file-serving routes.
- **Realtime:** Socket.IO server registered in `lib/startup/registerWebsocketEvents.ts`.
- **External integrations:** Google OAuth configuration, Web3/NFT/wallet endpoints, URL-based profile image fetches, downloadable chatbot training data, outbound redirect allowlist, and potential Prometheus scraping.

### Major components

1. **Public web frontend** serves Angular assets and browser routes.
2. **Authentication and identity** handles login, password reset/change, TOTP setup/verification, current-user lookup, security questions, and in-memory session state.
3. **Customer account APIs** manage profile, profile images, addresses, payment cards, data export/erasure, memories, and wallet/deluxe status.
4. **Commerce APIs** manage products, basket items, coupons, checkout, order PDFs, order history, delivery methods, and inventory quantities.
5. **Generated CRUD APIs** are created by `finale-rest` for core Sequelize models under `/api/<Model>s`.
6. **Content and file services** expose public files, logs, encryption keys, uploads, promotion videos, privacy proof, and code snippets/fixes.
7. **B2B and upload interfaces** accept JSON order data, PDFs/XML/YAML/ZIP uploads, complaint files, and profile image files/URLs.
8. **Reviews and chatbot** use MarsDB and chatbot training data to process user-generated text.
9. **Monitoring/admin-like surfaces** expose `/metrics`, `/api-docs`, app version/configuration, order administration, and delivery status changes.

## 2. Trust Boundaries and Security Zones

### Public Zone: untrusted internet/browser clients

Includes all unauthenticated HTTP traffic, static assets, public product/search/review endpoints, file downloads, Swagger docs, metrics if internet-exposed, redirects, captcha endpoints, WebSocket connection establishment, and upload endpoints without explicit authorization middleware.

Boundary controls observed:

- Helmet `noSniff` and `frameguard`; `x-powered-by` disabled.
- CORS is globally permissive (`app.use(cors())`).
- Limited request size for memory uploads via multer file size limit.
- Some route-level rate limits for reset-password and 2FA.

Primary gaps:

- Broad CORS allows cross-origin browser interaction.
- Many public endpoints perform database queries, file reads, redirects, or filesystem writes.
- Public directory listings and operational endpoints may disclose sensitive internals.
- Error handler may expose verbose errors in production.

### Authenticated Zone: partially trusted users

Includes JWT/cookie-authenticated customer actions: basket, checkout, cards, addresses, privacy requests, data export, profile update, wallet, deluxe membership, reviews, 2FA, order history, memories, and B2B APIs.

Boundary controls observed:

- `security.isAuthorized()` validates JWTs on selected routes.
- `security.appendUserId()` overwrites `req.body.UserId` for several resources.
- Some object-level queries constrain by `UserId` for cards/addresses.
- Role checks exist for accounting endpoints.

Primary gaps:

- Authorization is inconsistent across generated CRUD and custom routes.
- Some protected routes rely on in-memory token state rather than only cryptographic token validation.
- Role authorization trusts token claims and lacks centralized policy enforcement.
- Cookies are set without visible `httpOnly`, `secure`, or `sameSite` options.

### Internal Zone: server process, database, local filesystem, keys, logs

Includes SQLite database, MarsDB files/collections, JWT private/public keys, uploaded files, logs, server-side fetch/file parsing, chatbot training data, config, and metrics.

Boundary controls observed:

- SQLite access is local to the server process.
- Some uploaded filenames are sanitized; image upload limits exist.
- Card display masks PAN values on read.

Primary gaps:

- Key material and hardcoded HMAC/JWT secrets exist in source/runtime paths.
- File-serving routes expose directories that should normally be internal.
- Upload parsing includes ZIP extraction, XML entity expansion, YAML parsing, and URL fetches.
- Logs and generated PDFs can contain PII and order details.

## 3. Data Flows

1. **Login:** Browser posts credentials to `/rest/user/login`; server queries `Users`, hashes submitted password, creates/fetches basket, signs JWT, stores token in memory, and returns token/basket id/email.
2. **Authenticated API use:** Browser sends JWT in `Authorization` or cookie; middleware verifies token and may inject `UserId`; routes read/write SQLite or MarsDB and return JSON.
3. **Checkout:** User basket is loaded from SQLite; inventory and wallet are updated; order details are inserted into MarsDB; a PDF invoice is written to `ftp/`; basket items are cleared.
4. **Cards/addresses:** User submits payment/address data to generated APIs; custom GET/DELETE routes scope reads/deletes by `UserId`; card output is masked.
5. **Data export:** Authenticated user passes image captcha; server reads memories from SQLite, orders/reviews from MarsDB, assembles JSON, and sends it to the browser.
6. **File uploads:** Browser uploads complaint/profile/memory files; server stores in memory or disk, validates limited MIME/extension, may parse ZIP/XML/YAML, and writes files to upload directories.
7. **URL profile images:** Authenticated user submits an image URL; server performs outbound `fetch()`, writes response body to public uploads, or stores the URL directly on failure.
8. **Search and reviews:** Public product search and review endpoints query SQLite/MarsDB and return product/review content that may be rendered by Angular.
9. **WebSocket:** Browser connects to Socket.IO; server emits challenge/notification state and receives client events.
10. **Ops/observability:** Prometheus or users call `/metrics`; users can access `/api-docs`, directory listings, security.txt, and support logs depending on deployment exposure.

## 4. Critical Assets

### PII and customer data

- User email, username, last login IP, addresses, memories/images, product reviews, order history, PDF invoices, privacy requests, security answers, and chatbot-derived username data.
- Protection required: strict object-level authorization, encryption at rest where feasible, minimization in logs/PDFs, deletion workflows, and GDPR-style export/erasure controls.

### Credentials, secrets, and authenticators

- Password hashes, TOTP secrets, JWT private/public keys, HMAC secret, OAuth client ID, deluxe token derivation secret, captcha tokens, and in-memory JWT session maps.
- Protection required: strong password hashing, secret storage outside source, key rotation, secure cookie flags, token revocation/expiry controls, MFA hardening, and no directory/file exposure.

### Payment and commerce data

- Payment cards, wallet balances, coupons, order totals, inventory quantities, delivery status, product prices, and discounts.
- Protection required: PCI-aware handling/tokenization, masking, audit logs, price/inventory server-side validation, object-level authorization, and accounting/admin role controls.

### Operational and proprietary data

- Logs, metrics, Swagger docs, application configuration, source snippets/fixes, chatbot training data, uploaded files, and generated PDFs.
- Protection required: internal-only exposure, log redaction, authenticated docs/metrics, integrity controls, and malware/content validation for uploads.

## 5. Threat Analysis (STRIDE)

### Authentication and session management

- **S - Spoofing (CRITICAL / likely):** Static/hardcoded JWT private key and public key files make token forgery possible if source or key directory leaks. In-memory `authenticatedUsers` creates inconsistent trust if tokens are valid but not registered or if sessions persist unexpectedly. Look for `jwt.sign(... privateKey ...)`, public key file serving, and direct token-map access.
- **T - Tampering (HIGH / likely):** JWT claims include role, user data, deluxe token, and basket id; any signing-key compromise enables role and identity tampering.
- **R - Repudiation (HIGH / likely):** Login, password reset, 2FA changes, profile changes, and role-sensitive actions lack durable audit trails tied to user id, IP, and event id.
- **I - Information Disclosure (HIGH / likely):** Passwords use MD5 hashing; credential database disclosure is highly damaging. TOTP secrets are stored in the user record and excluded from generated output but not protected at rest.
- **D - Denial of Service (MEDIUM / possible):** Rate limits exist only on selected flows; login, registration, password-change, chatbot, and public search appear under-protected.
- **E - Elevation of Privilege (CRITICAL / likely):** Role checks trust token content; generated user creation/update patterns and mass-assignable fields must be reviewed to prevent customer-to-admin/accounting escalation.

Existing mitigations: JWT expiry, RS256 signing, some route-level authorization, 2FA support.  
Control gaps: externalized secrets, strong password hashing, secure cookies, central authz policy, login rate limits, session revocation, audit logging.

### Public REST and generated CRUD APIs

- **S (HIGH / possible):** Public endpoints with permissive CORS may be invoked cross-origin; if cookies are used, CSRF-like flows become plausible unless SameSite prevents it.
- **T (CRITICAL / likely):** Raw SQL string interpolation appears in login and product search. Generated CRUD endpoints expose many models and must be assumed mass-assignment-sensitive unless every route/method is locked down.
- **R (MEDIUM / likely):** Finale-generated create/update/delete actions lack business-level audit context.
- **I (CRITICAL / likely):** User, card, address, order, log, key, and schema data may leak through SQL injection, IDOR, verbose errors, generated APIs, directory listing, and operational endpoints.
- **D (HIGH / possible):** Public search and generated list endpoints have no pagination and may perform expensive queries.
- **E (CRITICAL / possible):** Authorization middleware is applied selectively; any missed generated endpoint can expose admin, accounting, or ownership bypass.

Existing mitigations: several method-specific `denyAll` routes, some `appendUserId` scoping, excluded password/TOTP fields in User resource.  
Control gaps: parameterized queries, deny-by-default API routing, schema validation, pagination, object-level authorization tests.

### File upload, parsing, and static file serving

- **S (MEDIUM / possible):** Upload endpoints trust authenticated identity from cookies/token maps; public upload endpoints may not require authentication.
- **T (CRITICAL / likely):** ZIP extraction can write files based on archive entry paths; XML/YAML parsing and profile-image URL fetches accept attacker-controlled content; uploaded files are served from public static directories.
- **R (MEDIUM / possible):** Upload/write actions lack tamper-evident audit records.
- **I (CRITICAL / likely):** Directory listing of `/ftp`, `/encryptionkeys`, and `/support/logs` can expose order PDFs, keys, logs, and internal files if deployed publicly.
- **D (HIGH / likely):** ZIP bombs, XML entity expansion, YAML bombs, large remote responses, and many upload attempts can exhaust CPU, memory, disk, or outbound sockets.
- **E (HIGH / possible):** Stored files under webroot can become stored XSS, content-type confusion, or server-side file overwrite if path controls fail.

Existing mitigations: 200 KB memory upload limit, limited image MIME map for one upload path, filename sanitization on profile memory image files.  
Control gaps: authenticated uploads, malware scanning, strict content sniffing, safe archive extraction, disable XML entities, SSRF denylist/allowlist, private storage + signed downloads.

### Commerce, payments, wallet, and orders

- **S (HIGH / possible):** Basket id and order ids are user-influenced/readable; token/basket association must be verified for every checkout.
- **T (HIGH / likely):** Coupon data, delivery method id, quantities, wallet balance, price calculations, and payment id are submitted by clients and require server-side validation.
- **R (HIGH / likely):** Checkout, wallet debit/credit, delivery status toggles, card create/delete, and inventory updates need immutable audit logs; current implementation writes orders but not a full audit ledger.
- **I (HIGH / possible):** Order PDFs in `ftp/`, masked card metadata, addresses, and order history are sensitive; predictable or listable locations increase exposure.
- **D (MEDIUM / possible):** Checkout updates inventory/wallet without obvious transaction wrapping; concurrent orders can cause race conditions or negative inventory.
- **E (HIGH / possible):** Accounting-only endpoints rely on token role and an IP filter with an invalid-looking allowlist value; misconfiguration can block legitimate use or create false assurance.

Existing mitigations: card reads/deletes scoped by `UserId`; cards are masked on read; wallet payment checks balance; inventory decremented server-side.  
Control gaps: payment tokenization, transactional integrity, authorization on basket ownership, anti-fraud checks, audit ledger, PCI controls.

### User-generated content, XSS, redirects, and frontend

- **S (MEDIUM / possible):** Cross-origin access plus token cookies can enable browser-origin confusion.
- **T (HIGH / likely):** Product reviews, usernames, profile image URLs, chatbot names, and feedback are user-controlled and rendered by the client/server templates.
- **R (LOW / possible):** User content moderation actions and edits are weakly attributable without audit logs.
- **I (HIGH / possible):** Open redirect patterns can leak tokens if tokens appear in URLs; profile-image SSRF can access internal metadata/services.
- **D (MEDIUM / possible):** Chatbot and search endpoints can be abused for computational load.
- **E (HIGH / possible):** Stored XSS can steal tokens, perform same-origin requests, or escalate to account takeover if cookies/local storage are accessible.

Existing mitigations: some `sanitize-html` usage and helmet frame/nosniff.  
Control gaps: CSP, output encoding guarantees, URL redirect exact-match validation, cookie flags, SSRF controls, frontend route guards as defense-in-depth only.

### WebSocket and realtime events

- **S (MEDIUM / possible):** Socket.IO allows a localhost Angular origin; deployment origin handling should be explicit for production domains.
- **T (MEDIUM / possible):** Client-supplied event data affects notification/challenge state.
- **R (LOW / possible):** WebSocket events lack auditability.
- **I (MEDIUM / possible):** Notifications may disclose application state to unauthenticated sockets if not gated.
- **D (MEDIUM / possible):** Unauthenticated socket floods can exhaust connections/memory.
- **E (LOW / possible):** No direct privilege escalation observed, but any privileged event added later must require token auth.

Control gaps: authenticate sockets, rate-limit events, configure production CORS origins, and validate event schemas.

### Operational interfaces and deployment

- **S (MEDIUM / possible):** `trust proxy` is enabled and rate-limit keys use `X-Forwarded-For`; spoofed headers are possible if the reverse proxy is not correctly constrained.
- **T (MEDIUM / possible):** Public app configuration endpoints and code-fix/snippet routes may reveal internal implementation and enable targeted tampering.
- **R (MEDIUM / likely):** Operational actions and admin/order changes lack central logging.
- **I (HIGH / likely):** `/metrics`, `/api-docs`, support logs, encryption keys, and directory listings disclose implementation, secrets, or personal data.
- **D (MEDIUM / possible):** Metrics, docs, static directory listings, and logs can be scraped repeatedly.
- **E (MEDIUM / possible):** Operational data makes exploitation of other weaknesses easier.

Control gaps: move ops endpoints behind auth/network ACLs, disable directory listing, redact metrics/logs, use production error handler, and set strict proxy trust.

## 6. Vulnerability Pattern Library

These patterns are optimized for subsequent vulnerability analysis in this TypeScript/Express/Angular/Sequelize codebase.

### SQL injection

Vulnerable:

```ts
sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`)
```

Safe:

```ts
sequelize.query('SELECT * FROM Users WHERE email = ? AND password = ?', {
  replacements: [email, passwordHash],
  model: UserModel,
  plain: true
})
ProductModel.findAll({ where: { name: { [Op.like]: `%${criteria}%` } } })
```

### XSS / unsafe rendering

Vulnerable:

```ts
user.update({ username: req.body.query })
res.render('profile', { username: req.body.username })
// Angular: [innerHTML]="review.message" without sanitizer/encoding review content
```

Safe:

```ts
const clean = sanitizeHtml(req.body.query, { allowedTags: [], allowedAttributes: {} })
// Prefer interpolation/textContent in templates and a strict CSP.
```

### Command/code injection

Vulnerable:

```ts
vm.runInContext('safeEval(orderLinesData)', sandbox)
safeEval(req.body.orderLinesData)
```

Safe:

```ts
const orderLines = orderLineSchema.parse(req.body.orderLines)
// Process structured JSON only; do not evaluate user-provided expressions.
```

### Path traversal and unsafe archive extraction

Vulnerable:

```ts
const absolutePath = path.resolve('uploads/complaints/' + entry.path)
entry.pipe(fs.createWriteStream('uploads/complaints/' + entry.path))
```

Safe:

```ts
const base = path.resolve('uploads/complaints')
const target = path.resolve(base, sanitizeFilename(entry.path))
if (!target.startsWith(base + path.sep)) throw new Error('Invalid archive path')
```

### SSRF and unsafe URL fetch

Vulnerable:

```ts
const response = await fetch(req.body.imageUrl)
```

Safe:

```ts
const url = new URL(req.body.imageUrl)
if (!['https:'].includes(url.protocol) || !allowedImageHosts.has(url.hostname)) throw new Error('Blocked URL')
// Resolve DNS and block private/link-local/metadata IP ranges before fetching.
```

### Authentication bypass / weak session controls

Vulnerable:

```ts
res.cookie('token', token)
const decoded = verify(jwtFrom(req)) && decode(jwtFrom(req))
if (decoded.data.role === 'accounting') next()
```

Safe:

```ts
res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })
const subject = await authService.verifyTokenAndLoadUser(req)
await policy.enforce(subject, 'order:updateDeliveryStatus', resource)
```

### IDOR / missing object-level authorization

Vulnerable:

```ts
BasketModel.findOne({ where: { id: req.params.id } })
AddressModel.findByPk(req.params.id)
```

Safe:

```ts
BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } })
AddressModel.findOne({ where: { id: req.params.id, UserId: req.user.id } })
```

### Sensitive file exposure

Vulnerable:

```ts
app.use('/encryptionkeys', serveIndex('encryptionkeys'))
app.use('/support/logs', serveIndex('logs'))
app.use('/ftp', serveIndex('ftp'))
```

Safe:

```ts
app.use('/support/logs', requireAdmin, internalNetworkOnly)
// Store keys outside webroot and never serve them over HTTP.
```

## 7. Security Testing Strategy

Prioritize subsequent vulnerability analysis in this order:

1. **Auth/session:** Attempt JWT forgery, insecure cookie checks, token replay, 2FA bypass, password reset abuse, missing login rate limits, and role-claim tampering.
2. **Injection:** Test login/search and any `sequelize.query`, MarsDB query construction, chatbot/b2b eval paths, YAML/XML parser behavior, and template rendering.
3. **Authorization/IDOR:** Enumerate generated `/api/*` resources and custom `/rest/*` endpoints for missing ownership checks, role bypass, and mass assignment.
4. **File/SSRF:** Test upload extension/MIME mismatch, archive traversal, XML external entities, YAML bombs, stored XSS via uploads/SVG, public access to uploaded/PDF/log/key files, and profile-image SSRF to private IPs.
5. **Commerce integrity:** Validate basket ownership, price/coupon manipulation, wallet race conditions, inventory consistency, payment card ownership, and order-history access.
6. **Operational exposure:** Confirm `/metrics`, `/api-docs`, `/support/logs`, `/encryptionkeys`, `/ftp`, app config, and verbose error pages are not publicly exposed in production.
7. **Frontend/browser:** Review token storage, Angular sanitization bypasses, CSP, CORS, CSRF, redirect handling, and WebSocket authentication.

## 8. Assumptions and Accepted Risks

- The application is assessed as a production e-commerce app despite repository metadata indicating a security training purpose.
- No external identity provider, payment gateway, WAF, reverse proxy, or deployment hardening was assumed unless visible in the repository.
- SQLite/MarsDB are assumed production data stores for this model; if replaced in deployment, equivalent data classifications and controls still apply.
- `/metrics`, directory listings, logs, keys, Swagger, and static files are assumed internet-reachable unless deployment network controls prove otherwise.
- Compliance drivers likely include GDPR/privacy obligations due to data export/erasure flows and PCI-adjacent requirements due to payment card storage, but no formal compliance requirement was provided.

## 9. Highest-Priority Control Gaps

1. Remove hardcoded key material/secrets from source; store JWT/private keys in a secrets manager; rotate all exposed keys; never serve key directories.
2. Replace MD5 password hashing with Argon2id/bcrypt plus per-user salts and migration strategy.
3. Convert all raw SQL to parameterized queries or ORM query builders.
4. Implement centralized authentication/authorization middleware with object-level policy checks and deny-by-default generated API exposure.
5. Disable public directory listing and protect `/metrics`, `/api-docs`, logs, key files, order PDFs, and app configuration.
6. Harden file upload and URL fetch flows against SSRF, archive traversal, parser attacks, malware, and public executable/active content.
7. Set secure cookie attributes and CORS allowlists; add CSRF protection for cookie-authenticated state-changing requests.
8. Add durable audit logging for login, account changes, payment/card events, checkout, wallet updates, data export/erasure, and admin/accounting actions.
9. Add rate limits and abuse controls to login, registration, search, chatbot, uploads, checkout, and WebSockets.
10. Add transaction handling and integrity checks for checkout, wallet, inventory, coupons, and delivery state.

## 10. Version Changelog

- **1.0.0 (2026-05-11):** Initial STRIDE threat model generated from repository inspection for downstream vulnerability analysis.
