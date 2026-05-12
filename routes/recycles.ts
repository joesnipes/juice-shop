/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

// SECURITY (JS-AUDIT-028 / CWE-89): the previous handler called
// `JSON.parse(req.params.id)` and dropped the result into a Sequelize
// `where` clause, letting an attacker inject operator objects such as
// `{"$gt":0}` to dump the entire table. Coerce id to a positive integer.
export const getRecycleItem = () => (req: Request, res: Response) => {
  const id = Number(req.params.id)
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'Invalid recycle id' })
    return
  }
  RecycleModel.findAll({ where: { id } }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
