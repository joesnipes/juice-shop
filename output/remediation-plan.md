# Remediation Plan

SARIF/GitHub upload link status: unavailable. The validated findings report says no GitHub ingest artifacts were found, and no per-finding code-scanning URLs were present.

## Branches

- SCA: `security-fixes/sca-20260510-000000`
- SAST: `security-fixes/sast-20260510-000000`

## Fixed

- DEP-003 (MEDIUM, CWE-79, A03): upgraded `sanitize-html` from `1.4.2` to `^2.17.0`. Validation: `npm ls sanitize-html --depth=0` passed after install; full `npm test` failed because `ng` was not found.
- VULN-001 (CRITICAL, CWE-89, A03): changed login SQL concatenation to Sequelize replacements. Syntax validation passed.
- VULN-002 (CRITICAL, CWE-89, A03): changed product search SQL concatenation to replacements with LIKE escaping. Syntax validation passed.
- VULN-003 (HIGH, CWE-943, A03): replaced `$where` order lookup with `{ orderId: req.params.id }`. Syntax validation passed.
- VULN-004 (HIGH, CWE-943, A03): replaced `$where` review lookup with typed numeric equality. Syntax validation passed.
- VULN-006 (CRITICAL, CWE-611, A05): disabled XML entity substitution/network loading and removed XML/parser-detail echoes. Syntax validation passed.
- VULN-007 (CRITICAL, CWE-22, A01): canonicalized ZIP extraction paths under `uploads/complaints`. Syntax validation passed.
- VULN-013 (CRITICAL, CWE-95, A03): removed username `eval`; profile data remains escaped. Syntax validation passed.
- VULN-014 (HIGH, CWE-79, A03): removed Angular sanitizer bypass and uses `sanitize(SecurityContext.HTML, ...)`. Full frontend tests could not run because `ng` was not found.

## Deferred: developer_decision_required

- VULN-005 / DEP-001: B2B eval/notevil removal requires accepted order-line input contract.
- DEP-002 / VULN-010: JWT dependency/key and password hash migration requires rotation and credential migration plan.
- VULN-008: SSRF fix requires approved image-source allowlist and redirect/download policy.
- VULN-009: sensitive file exposure fix requires file access and support workflow decisions.
- VULN-011: product API authorization requires admin/RBAC policy for generated resources.
- VULN-012: basket/order IDOR requires checkout/basket ownership semantics and compatibility review.

See `output/remediation-plan.json` for snippets, rationale, validation, and residual risk per finding.
