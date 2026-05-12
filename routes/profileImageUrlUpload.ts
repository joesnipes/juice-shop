/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import logger from '../lib/logger'
import * as utils from '../lib/utils'

// SECURITY (JS-AUDIT-017 / CWE-918): full SSRF guard.
//   * Require an https:// (or explicit http allowed by env) URL.
//   * Resolve all DNS records and reject any that point to a private,
//     link-local, loopback, multicast, broadcast or reserved range.
//   * Cap the response size and time-out the fetch.
//   * Store ONLY the resulting local image path, never the raw URL.

const ALLOWED_SCHEMES = (process.env.PROFILE_IMAGE_ALLOWED_SCHEMES ?? 'https').split(',').map((s) => s.trim())
const MAX_BYTES = 5 * 1024 * 1024 // 5 MiB
const FETCH_TIMEOUT_MS = 5000

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    if (a === 10 || a === 127 || a === 0) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a >= 224) return true // multicast / reserved
    return false
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase()
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('ff')) return true
    if (lower.startsWith('::ffff:')) return isPrivateIp(lower.slice('::ffff:'.length))
  }
  return true // anything we cannot classify is treated as private
}

async function isSsrfSafe (parsed: URL): Promise<boolean> {
  if (!ALLOWED_SCHEMES.includes(parsed.protocol.replace(':', ''))) return false
  try {
    const records = await dns.lookup(parsed.hostname, { all: true })
    if (!records.length) return false
    for (const r of records) {
      if (isPrivateIp(r.address)) return false
    }
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = String(req.body.imageUrl)
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }

      let parsed: URL
      try {
        parsed = new URL(url)
      } catch {
        res.status(400).json({ error: 'imageUrl must be a valid URL' })
        return
      }
      if (!(await isSsrfSafe(parsed))) {
        res.status(400).json({ error: 'imageUrl host is not permitted' })
        return
      }

      const controller = new AbortController()
      const timer = setTimeout(() => { controller.abort() }, FETCH_TIMEOUT_MS)
      try {
        const response = await fetch(parsed.toString(), { signal: controller.signal, redirect: 'manual' })
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }
        const contentLength = Number(response.headers.get('content-length') ?? '0')
        if (contentLength > MAX_BYTES) {
          throw new Error('response too large')
        }
        const contentType = response.headers.get('content-type') ?? ''
        if (!contentType.startsWith('image/')) {
          throw new Error('response is not an image')
        }
        const extFromUrl = parsed.pathname.split('.').pop()?.toLowerCase() ?? ''
        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(extFromUrl) ? extFromUrl : 'jpg'
        const localPath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        const fileStream = fs.createWriteStream(localPath, { flags: 'w' })
        let written = 0
        const reader = Readable.fromWeb(response.body as any)
        reader.on('data', (chunk: Buffer) => {
          written += chunk.length
          if (written > MAX_BYTES) {
            reader.destroy(new Error('response exceeded size limit'))
            fileStream.destroy()
          }
        })
        await finished(reader.pipe(fileStream))
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        logger.warn(`profileImageUrlUpload rejected: ${utils.getErrorMessage(error)}`)
        // Defence-in-depth: NEVER store the raw remote URL as the
        // profileImage when fetching fails — the previous fallback
        // enabled stored XSS via CSP injection (JS-AUDIT-009).
        res.status(400).json({ error: 'Could not retrieve image from URL' })
        return
      } finally {
        clearTimeout(timer)
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
