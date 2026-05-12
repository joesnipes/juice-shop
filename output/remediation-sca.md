# SCA Remediation Manifest — `remediation/sca-20260512-022728`

**Generated**: 2026-05-12T02:27:28Z
**Repository**: joesnipes/juice-shop
**Base branch**: `main`
**Source findings**: `output/findings.json`
**Threat-model PR**: https://github.com/joesnipes/juice-shop/pull/21
**Companion SAST branch**: `remediation/sast-20260512-022728`

## Summary

| Metric | Count |
|---|---|
| Attempted | 7 |
| Fixed | 5 |
| Developer decision required | 2 |

> ⚠️ **Sequencing note:** the `express-jwt`/`jsonwebtoken` major bumps require the lib/insecurity.ts rewrites that ship on the companion SAST branch. Merge both PRs together (or merge the SAST PR first).

## Fixed

| Finding | Package | From | To | Notes |
|---|---|---|---|---|
| JS-AUDIT-006 | `express-jwt` | `0.1.3` | `^8.4.1` | Closes alg:none bypass (GHSA-6cwn-77pq-3fpx). Needs paired insecurity.ts update on SAST branch. |
| JS-AUDIT-006 | `jsonwebtoken` | `0.4.0` | `^9.0.2` | Closes signature-bypass family. |
| JS-AUDIT-006 (types) | `@types/jsonwebtoken` | `^8.5.9` | `^9.0.6` | Type alignment for v9. |
| JS-AUDIT-041 | `multer` | `^1.4.5-lts.1` | `^2.0.2` | Closes 6 DoS CVEs (incl. CVE-2026-3520). |
| JS-AUDIT-042 | `sanitize-html` | `1.4.2` | `^2.13.1` | Closes 7 XSS/ReDoS advisories. |
| JS-AUDIT-044 | `socket.io` | `^3.1.2` | `^4.7.5` | Closes unhandled-error crash (GHSA-cqmj-92xf-r6r9). |
| JS-AUDIT-044 | `socket.io-client` | `^3.1.3` | `^4.7.5` | Matching client major. |

## Developer decision required

| Finding | Package | Reason |
|---|---|---|
| JS-AUDIT-043 | `marsdb` | Unmaintained, no patched version. Practical exploit closed by SAST branch (removal of `$where`), but the lib remains loaded. Recommend full migration to Sequelize for review/order data. |
| JS-AUDIT-045 | `file-type` | v17+ became ESM. Project is CommonJS — upgrade requires call-site refactor to async dynamic imports. |

## Validations not run (recommended for reviewers)

- `npm install` (postinstall triggers full frontend build; intentionally skipped here)
- `npm test`
- `npm run frisby`
- `npm run rsn` (only relevant after SAST branch merges as it touches challenge-relevant files)

## How to validate locally

```bash
git fetch origin
git checkout remediation/sca-20260512-022728
npm install              # postinstall will build frontend too
npm run lint
npm run test:server
npm run frisby           # API integration
```

## Follow-ups

1. Plan migration off `marsdb` for review/order persistence (JS-AUDIT-043).
2. Plan ESM-compatible upgrade of `file-type` to `>=21.3.1` (JS-AUDIT-045).
3. Rotate any production JWT/HMAC secrets and invalidate tokens minted with the previously-leaked RSA key (handled by SAST branch code-side; secrets must be rotated operationally).
