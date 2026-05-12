/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

// SECURITY (JS-AUDIT-027 / CWE-200): never serialise the entire config
// object. Return only the small whitelist of public branding/UX values
// that the SPA needs. The route is also gated by isAuthorized() at the
// server.ts mount point.
const PUBLIC_CONFIG_KEYS: readonly string[] = [
  'application.domain',
  'application.name',
  'application.logo',
  'application.favicon',
  'application.theme',
  'application.showVersionNumber',
  'application.showGitHubLinks',
  'application.localBackupEnabled',
  'application.numberOfRandomFakeUsers',
  'application.altcoinName',
  'application.privacyContact',
  'application.welcomeBanner',
  'application.cookieConsent',
  'application.securityTxt',
  'application.promotion',
  'application.easterEggPlanet',
  'application.googleOauth',
  'application.googleAnalyticsId',
  'application.recyclePage',
  'application.chatBot.name',
  'application.chatBot.avatar',
  'application.social',
  'challenges.showSolvedNotifications',
  'challenges.showHints',
  'challenges.showMitigations',
  'hackingInstructor.isEnabled'
]

function safeGet (key: string): unknown {
  try { return config.get(key) } catch { return undefined }
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const result: Record<string, unknown> = {}
    for (const key of PUBLIC_CONFIG_KEYS) {
      const v = safeGet(key)
      if (v !== undefined) {
        // restore the nested-object shape the SPA expects
        const path = key.split('.')
        let cursor: any = result
        for (let i = 0; i < path.length - 1; i++) {
          cursor[path[i]] = cursor[path[i]] ?? {}
          cursor = cursor[path[i]]
        }
        cursor[path[path.length - 1]] = v
      }
    }
    res.json({ config: result })
  }
}
