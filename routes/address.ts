/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// SECURITY (JS-AUDIT-023 / CWE-639): the previous implementations took
// the user id from `req.body.UserId`, which could be overridden by the
// client even after `appendUserId` ran. We now derive the user id from
// the verified JWT inside each handler and ignore any client-supplied
// `UserId` field.
function userIdFromRequest (req: Request): number | null {
  const tokenUser = security.authenticatedUsers.from(req)
  if (tokenUser?.data?.id) return Number(tokenUser.data.id)
  return null
}

export function getAddress () {
  return async (req: Request, res: Response) => {
    const userId = userIdFromRequest(req)
    if (userId == null) {
      res.status(401).json({ status: 'error' })
      return
    }
    const addresses = await AddressModel.findAll({ where: { UserId: userId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const userId = userIdFromRequest(req)
    if (userId == null) {
      res.status(401).json({ status: 'error' })
      return
    }
    const addressId = Number(req.params.id)
    if (!Number.isInteger(addressId)) {
      res.status(400).json({ status: 'error', data: 'Invalid address id' })
      return
    }
    const address = await AddressModel.findOne({ where: { id: addressId, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const userId = userIdFromRequest(req)
    if (userId == null) {
      res.status(401).json({ status: 'error' })
      return
    }
    const addressId = Number(req.params.id)
    if (!Number.isInteger(addressId)) {
      res.status(400).json({ status: 'error', data: 'Invalid address id' })
      return
    }
    const address = await AddressModel.destroy({ where: { id: addressId, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(404).json({ status: 'error', data: 'Address not found.' })
    }
  }
}

// re-export utils to silence unused-import lint if optimisation removes it
void utils
