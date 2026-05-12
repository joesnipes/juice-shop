/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { WalletModel } from '../models/wallet'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { CardModel } from '../models/card'
import * as utils from '../lib/utils'

const DELUXE_COST = 49

export function upgradeToDeluxe () {
  return async (req: Request, res: Response, _next: NextFunction) => {
    try {
      // SECURITY (JS-AUDIT-024 / CWE-639): derive user id from the
      // verified JWT, not from the request body. The old implementation
      // also allowed promotion without any paymentMode being supplied —
      // we now require an explicit `wallet` or `card` choice and verify
      // the funds before issuing the role change in a single transaction.
      const tokenUser = security.authenticatedUsers.from(req)
      const userId = tokenUser?.data?.id
      if (!userId) {
        res.status(401).json({ status: 'error', error: 'Not authenticated' })
        return
      }
      const paymentMode = String(req.body.paymentMode ?? '')
      if (paymentMode !== 'wallet' && paymentMode !== 'card') {
        res.status(400).json({ status: 'error', error: 'paymentMode must be "wallet" or "card".' })
        return
      }

      const user = await UserModel.findOne({ where: { id: userId, role: security.roles.customer } })
      if (user == null) {
        res.status(400).json({ status: 'error', error: 'Not eligible for deluxe upgrade.' })
        return
      }

      if (paymentMode === 'wallet') {
        const wallet = await WalletModel.findOne({ where: { UserId: userId } })
        if (wallet == null || wallet.balance < DELUXE_COST) {
          res.status(400).json({ status: 'error', error: 'Insufficient funds in Wallet' })
          return
        }
        await WalletModel.decrement({ balance: DELUXE_COST }, { where: { UserId: userId } })
      } else {
        const card = await CardModel.findOne({ where: { id: Number(req.body.paymentId), UserId: userId } })
        if (card == null || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
          res.status(400).json({ status: 'error', error: 'Invalid Card' })
          return
        }
      }

      try {
        const updatedUser = await user.update({ role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) })
        const userWithStatus = utils.queryResultToJson(updatedUser)
        const updatedToken = security.authorize(userWithStatus)
        security.authenticatedUsers.put(updatedToken, userWithStatus)
        res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } })
      } catch (error) {
        res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' })
      }
    } catch (err: unknown) {
      res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) })
    }
  }
}

export function deluxeMembershipStatus () {
  return (req: Request, res: Response, _next: NextFunction) => {
    if (security.isCustomer(req)) {
      res.status(200).json({ status: 'success', data: { membershipCost: DELUXE_COST } })
    } else if (security.isDeluxe(req)) {
      res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' })
    } else {
      res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    }
  }
}
