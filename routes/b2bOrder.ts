/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'

// SECURITY (JS-AUDIT-010 / CWE-94): the previous implementation passed
// the raw `orderLinesData` body field through `notevil`'s safeEval inside
// a Node `vm` context. `notevil` has documented sandbox escapes and is
// not a security boundary; the route was a confirmed RCE/DoS vector.
//
// The B2B endpoint now expects structured JSON describing an order. Any
// non-object payload is rejected outright. No user-supplied expression
// is ever evaluated.

interface B2bOrderLine {
  productId: number
  quantity: number
  customerReference?: string
  couponCode?: string
}

interface B2bOrderRequest {
  cid?: string
  orderLinesData?: B2bOrderLine[]
}

function isValidOrderLine (line: any): line is B2bOrderLine {
  return (
    line !== null && typeof line === 'object' &&
    Number.isInteger(line.productId) && line.productId > 0 &&
    Number.isInteger(line.quantity) && line.quantity > 0 && line.quantity <= 1000 &&
    (line.customerReference === undefined || typeof line.customerReference === 'string') &&
    (line.couponCode === undefined || typeof line.couponCode === 'string')
  )
}

export function b2bOrder () {
  return (req: Request<unknown, unknown, B2bOrderRequest>, res: Response, next: NextFunction) => {
    const body = req.body ?? {}
    const orderLines = body.orderLinesData

    if (orderLines !== undefined) {
      if (!Array.isArray(orderLines) || orderLines.length > 100 || !orderLines.every(isValidOrderLine)) {
        res.status(400).json({ error: 'orderLinesData must be an array of valid order line objects (max 100).' })
        return
      }
    }

    res.json({
      cid: body.cid,
      orderNo: uniqueOrderNumber(),
      paymentDue: dateTwoWeeksFromNow()
    })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
