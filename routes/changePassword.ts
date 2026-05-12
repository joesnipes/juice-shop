/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

// SECURITY (JS-AUDIT-025 / CWE-620 + CWE-352):
//   * Read fields from the request body (POST), not the query string,
//     so credentials are not logged in browser history / access logs.
//   * ALWAYS require the current password and verify it via the
//     constant-time scrypt comparison in security.verifyPassword.
//   * Reject any request that does not present an Authorization bearer
//     token (defence-in-depth against CSRF — cookie-only auth must not
//     be accepted on this endpoint).
//   * Persist the new password via security.hash (scrypt+salt), not the
//     old MD5 helper.
export function changePassword () {
  return async ({ body, headers, socket }: Request, res: Response, next: NextFunction) => {
    const currentPassword = typeof body.current === 'string' ? body.current : ''
    const newPassword = typeof body.new === 'string' ? body.new : ''
    const repeatPassword = typeof body.repeat === 'string' ? body.repeat : ''

    if (!currentPassword) {
      res.status(401).send(res.__('Current password is required.'))
      return
    }
    if (!newPassword) {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    }
    if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }
    if (newPassword.length < 10) {
      res.status(400).send(res.__('Password must be at least 10 characters.'))
      return
    }

    // Require a bearer token in the Authorization header (NOT a cookie)
    // so that this endpoint cannot be triggered via ambient credentials
    // from a cross-origin context.
    const authHeader = typeof headers.authorization === 'string' ? headers.authorization : ''
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : authHeader.startsWith('Bearer=') ? authHeader.slice('Bearer='.length) : ''
    if (!bearer) {
      next(new Error('Blocked illegal activity by ' + socket.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(bearer)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      if (!security.verifyPassword(currentPassword, user.password)) {
        res.status(401).send(res.__('Current password is not correct.'))
        return
      }

      await user.update({ password: security.hash(newPassword) })
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
