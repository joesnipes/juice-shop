import { type Request, type Response } from 'express'
import { WebSocketProvider, Contract } from 'ethers'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set()
let isEventListenerCreated = false

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body.walletAddress
    walletsConnected.add(metamaskAddress)
    try {
      // SECURITY (JS-AUDIT-030 / CWE-798): never hard-code third-party
      // API keys. The previously committed Alchemy key must be rotated.
      const alchemyUrl = process.env.ALCHEMY_WSS_URL
      if (!alchemyUrl) {
        res.status(503).json({ success: false, message: 'Web3 provider not configured' })
        return
      }
      const provider = new WebSocketProvider(alchemyUrl)
      const contract = new Contract(web3WalletAddress, web3WalletABI, provider)
      if (!isEventListenerCreated) {
        void contract.on('ContractExploited', (exploiter: string) => {
          if (walletsConnected.has(exploiter)) {
            walletsConnected.delete(exploiter)
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
