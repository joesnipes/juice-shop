/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

// SECURITY (JS-AUDIT-035 / CWE-22): replace the naive forward-slash
// check with an explicit allow-list of filenames. URL-encoded traversal
// (`%2e%2e%2f`), backslashes on Windows, and null-byte truncation are
// all rejected by definition because nothing outside the allow-list
// will resolve to the configured root.
const KEY_ROOT = path.resolve('encryptionkeys')
const ALLOWED_FILES = new Set<string>([
  'jwt.pub'
  // NOTE: premium.key was removed from the repository (see SAST manifest
  // JS-AUDIT-016 / JS-AUDIT-035). Add new public assets here if they are
  // genuinely intended to be downloadable.
])

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = String(params.file ?? '')
    if (!ALLOWED_FILES.has(file)) {
      res.status(403)
      next(new Error('File access not allowed'))
      return
    }
    const target = path.resolve(KEY_ROOT, file)
    if (!target.startsWith(KEY_ROOT + path.sep)) {
      res.status(403)
      next(new Error('File access not allowed'))
      return
    }
    res.sendFile(target)
  }
}
