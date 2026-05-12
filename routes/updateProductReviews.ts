/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return (req: Request, res: Response, _next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'Not authenticated' })
      return
    }
    // SECURITY (JS-AUDIT-020 / CWE-639): the previous handler took the
    // `_id` filter from the request body untyped (allowing operator
    // injection such as { $ne: null }) and used `multi:true`, which let
    // an attacker overwrite every review in the database. We now coerce
    // the id to a string, restrict the update to documents authored by
    // the caller, and drop `multi`.
    const reviewId = typeof req.body.id === 'string' ? req.body.id : ''
    const newMessage = typeof req.body.message === 'string' ? req.body.message.slice(0, 2000) : ''
    if (!reviewId || !newMessage) {
      res.status(400).json({ error: 'Both id and message are required.' })
      return
    }

    db.reviewsCollection.update(
      { _id: reviewId, author: user.data.email },
      { $set: { message: newMessage } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
