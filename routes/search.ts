/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import * as utils from '../lib/utils'
import { ProductModel } from '../models/product'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    // SECURITY (JS-AUDIT-002 / CWE-89): replace raw string-template SQL
    // with Sequelize model where-clause. The `like` operator below is
    // safely escaped by the driver and cannot host UNION SELECT payloads.
    const likePattern = `%${criteria}%`
    ProductModel.findAll({
      where: {
        [Op.and]: [
          { deletedAt: null },
          { [Op.or]: [{ name: { [Op.like]: likePattern } }, { description: { [Op.like]: likePattern } }] }
        ]
      },
      order: [['name', 'ASC']]
    })
      .then((products: ProductModel[]) => {
        // Challenge detection paths that previously relied on the raw-SQL
        // UNION injection are no longer reachable now that the query is
        // parameterised. The challenge state remains driven by the seeded
        // data plus the other challenge endpoints; we intentionally do
        // not re-introduce a vulnerable code path to "solve" them.
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
