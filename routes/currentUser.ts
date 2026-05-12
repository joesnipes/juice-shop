/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'

// SECURITY (JS-AUDIT-047 / CWE-200): /rest/user/whoami previously
// allowed callers to pick which user-object fields were returned via
// `?fields=...`, which let them request `password`, `totpSecret`, etc.
// The endpoint now returns a fixed, public-safe projection regardless
// of any client-supplied query parameter.
const PUBLIC_FIELDS = ['id', 'email', 'lastLoginIp', 'profileImage'] as const

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    let response: any = { user: emptyUser }
    try {
      if (security.verify(req.cookies.token)) {
        const user = security.authenticatedUsers.get(req.cookies.token)
        const baseUser: any = {}
        for (const field of PUBLIC_FIELDS) {
          baseUser[field] = user?.data?.[field as keyof typeof user.data]
        }
        response = { user: baseUser }
      }
    } catch {
      response = { user: emptyUser }
    }

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      res.jsonp(response)
    }
  }
}
