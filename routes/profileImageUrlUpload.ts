/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const MAX_REMOTE_IMAGE_BYTES = 1024 * 1024
const ALLOWED_IMAGE_TYPES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/svg+xml': 'svg'
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const imageUrl = await validateRemoteImageUrl(url)
          const controller = new AbortController()
          const timeout = setTimeout(() => controller.abort(), 5000)
          const response = await fetch(imageUrl, { redirect: 'error', signal: controller.signal })
          clearTimeout(timeout)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const contentType = response.headers.get('content-type')?.split(';')[0].toLowerCase() ?? ''
          const ext = ALLOWED_IMAGE_TYPES[contentType]
          if (ext === undefined) {
            throw new Error('url did not return a supported image content type')
          }
          const contentLength = Number(response.headers.get('content-length') ?? '0')
          if (contentLength > MAX_REMOTE_IMAGE_BYTES) {
            throw new Error('remote image is too large')
          }
          const image = Buffer.from(await response.arrayBuffer())
          if (image.length > MAX_REMOTE_IMAGE_BYTES) {
            throw new Error('remote image is too large')
          }
          fs.writeFileSync(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, image, { flag: 'w' })
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

async function validateRemoteImageUrl (rawUrl: string): Promise<string> {
  const parsedUrl = new URL(rawUrl)
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('only HTTPS image URLs are allowed')
  }
  if (parsedUrl.username !== '' || parsedUrl.password !== '') {
    throw new Error('image URL must not contain credentials')
  }

  const addresses = await dns.lookup(parsedUrl.hostname, { all: true })
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error('image URL resolves to a disallowed network address')
  }

  return parsedUrl.toString()
}

function isPrivateAddress (address: string): boolean {
  if (net.isIPv4(address)) {
    const [first, second] = address.split('.').map(Number)
    return first === 10 || first === 127 || first === 0 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 169 && second === 254)
  }

  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase()
    return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:')
  }

  return true
}
