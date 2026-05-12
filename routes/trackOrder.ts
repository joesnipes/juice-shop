/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // SECURITY (JS-AUDIT-018 / CWE-94): the previous handler injected the
    // path parameter into a MarsDB `$where` selector, which is implemented
    // via `new Function(...)` (NoSQL/code injection). We now validate the
    // id to a strict alphanumeric/hyphen pattern and pass it as an
    // equality match — `$where` is never invoked.
    const rawId = String(req.params.id ?? '')
    if (!/^[\w-]{1,60}$/.test(rawId)) {
      res.status(400).json({ error: 'Invalid order id format' })
      return
    }

    db.ordersCollection.find({ orderId: rawId }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: rawId }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
