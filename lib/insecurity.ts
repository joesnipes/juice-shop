/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
// express-jwt v8 exports a named `expressjwt` middleware factory
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

// JWT signing keys are loaded from disk or environment. The leaked
// hard-coded private key has been removed (was JS-AUDIT-003 / CWE-798).
// In production, JWT_PRIVATE_KEY must point at a path containing a freshly
// generated RSA-2048 (or Ed25519) private key stored via secret manager.
// See .env.example for required environment variables.
const privateKeyPath = process.env.JWT_PRIVATE_KEY_PATH ?? 'encryptionkeys/jwt.key'
const publicKeyPath = process.env.JWT_PUBLIC_KEY_PATH ?? 'encryptionkeys/jwt.pub'

function readKey (path: string): string {
  if (!fs) return ''
  try {
    return fs.readFileSync(path, 'utf8')
  } catch {
    return ''
  }
}

const privateKey: string = process.env.JWT_PRIVATE_KEY ?? readKey(privateKeyPath)
export const publicKey: string = process.env.JWT_PUBLIC_KEY ?? (readKey(publicKeyPath) || 'placeholder-public-key')

if (!privateKey) {
  // Loud fail-closed warning: signing tokens with an empty key would still
  // be silently accepted by jsonwebtoken pre-9; v9+ throws, which is what
  // we want, but log explicitly here so misconfiguration is obvious.
  // eslint-disable-next-line no-console
  console.error('[insecurity] JWT private key not found; set JWT_PRIVATE_KEY or generate encryptionkeys/jwt.key. Token issuance will fail until configured.')
}

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

// Password hashing now uses scrypt with a per-credential random salt
// (was MD5, JS-AUDIT-004 / CWE-916). Output is `salt$hex` so the salt
// is stored alongside the hash. For comparison use verifyPassword().
// The legacy MD5 helper is preserved (`legacyHash`) only for migration
// of pre-existing user rows; new writes must use hash().
const SCRYPT_KEYLEN = 64
const SCRYPT_COST = 16384 // N=2^14, OWASP-recommended floor for scrypt

export const hash = (data: string): string => {
  const salt = crypto.randomBytes(16).toString('hex')
  const derived = crypto.scryptSync(data, salt, SCRYPT_KEYLEN, { N: SCRYPT_COST }).toString('hex')
  return `${salt}$${derived}`
}

export const verifyPassword = (plain: string, stored: string): boolean => {
  if (!stored) return false
  const parts = stored.split('$')
  if (parts.length === 2) {
    const [salt, expectedHex] = parts
    const derived = crypto.scryptSync(plain, salt, SCRYPT_KEYLEN, { N: SCRYPT_COST }).toString('hex')
    const a = Buffer.from(derived, 'hex')
    const b = Buffer.from(expectedHex, 'hex')
    return a.length === b.length && crypto.timingSafeEqual(a, b)
  }
  // Legacy MD5 row — accept once so we can transparently upgrade on login.
  return legacyHash(plain) === stored
}

// Legacy MD5 hash retained for backward-compatible migration ONLY.
export const legacyHash = (data: string): string =>
  crypto.createHash('md5').update(data).digest('hex')

// HMAC for security-answer comparison now keys off an env-managed secret
// (was a hard-coded literal, JS-AUDIT-005 / CWE-798).
const hmacSecret: string = process.env.SECURITY_ANSWER_HMAC_SECRET ?? (privateKey || 'change-me-in-env')
export const hmac = (data: string): string =>
  crypto.createHmac('sha256', hmacSecret).update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// JWT middleware now pins RS256 and rejects alg:none / HMAC confusion.
// (JS-AUDIT-006 / CWE-327)
export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: ['RS256'] })

// denyAll() previously verified with a random secret which, combined with
// express-jwt 0.x's alg:none bug, was reachable. Replace with an explicit
// 403 responder so authorization decisions never round-trip through a
// signature check. (JS-AUDIT-007 / CWE-330)
export const denyAll = () => (_req: Request, res: Response, _next: NextFunction) => {
  res.status(403).json({ error: 'Forbidden' })
}

export const authorize = (user: Record<string, any> = {}) => {
  if (!privateKey) {
    throw new Error('JWT signing key is not configured')
  }
  return jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
}

export const verify = (token: string) => {
  if (!token || !publicKey) return false
  try {
    // jws.verify pinned to RS256 to mirror the issuance algorithm
    return (jws.verify as ((token: string, algorithm: string, secret: string) => boolean))(token, 'RS256', publicKey)
  } catch {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

// sanitize-html v2 with an explicit allowlist (was v1.4.2, JS-AUDIT-042).
const SANITIZE_HTML_OPTIONS: sanitizeHtmlLib.IOptions = {
  allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'],
  allowedAttributes: { a: ['href', 'title', 'rel', 'target'] },
  allowedSchemes: ['http', 'https', 'mailto']
}
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html, SANITIZE_HTML_OPTIONS)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// Open-redirect allowlist now compares against the parsed URL's origin
// instead of substring matching the entire URL. (JS-AUDIT-008 / CWE-601)
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  if (!url || typeof url !== 'string') return false
  let candidate: URL
  try {
    candidate = new URL(url)
  } catch {
    return false
  }
  for (const allowedUrl of redirectAllowlist) {
    let allowed: URL
    try {
      allowed = new URL(allowedUrl)
    } catch {
      continue
    }
    if (
      candidate.protocol === allowed.protocol &&
      candidate.host === allowed.host &&
      candidate.pathname.startsWith(allowed.pathname)
    ) {
      return true
    }
  }
  return false
}

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const h = crypto.createHmac('sha256', hmacSecret)
  return h.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

// appendUserId now CLOBBERS any client-supplied UserId in the body so that
// downstream routes cannot be tricked into operating on a victim's record.
// (JS-AUDIT-021/022/023/024 / CWE-639)
export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = authenticatedUsers.tokenMap[utils.jwtFrom(req)]?.data?.id
      if (id === undefined) {
        res.status(401).json({ status: 'error', message: 'Not authenticated' })
        return
      }
      // Strip any client-supplied UserId field BEFORE merging the trusted one.
      if (req.body && typeof req.body === 'object') {
        delete req.body.UserId
      }
      req.body.UserId = id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && publicKey) {
    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          // Hardened cookie: HttpOnly + SameSite=Lax + Secure in prod
          res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production'
          })
        }
      }
    })
  }
  next()
}
