/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Note: the previous module exposed a global `sleep()` helper specifically
// to amplify the NoSQL DoS challenge. Removed — global state for DoS
// amplification is not appropriate in production.

export function showProductReviews () {
  return (req: Request, res: Response, _next: NextFunction) => {
    // SECURITY (JS-AUDIT-019 / CWE-94): replace `$where` (which executes
    // a JavaScript Function constructor with attacker-influenced source)
    // with a typed equality predicate. Strictly coerce the path parameter
    // to a positive integer.
    const id = Number(req.params.id)
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: 'Invalid product id' })
      return
    }

    db.reviewsCollection.find({ product: id }).then((reviews: Review[]) => {
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
