import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import { HDNodeWallet } from 'ethers'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

// SECURITY (JS-AUDIT-040 / CWE-798): the HD-wallet mnemonic is loaded
// from env, not committed. The old hard-coded mnemonic must be rotated.
// Comparisons against the private key use crypto.timingSafeEqual.

function safeEqual (a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ab.length !== bb.length) return false
  return crypto.timingSafeEqual(ab, bb)
}

export function checkKeys () {
  return (req: Request, res: Response) => {
    try {
      const mnemonic = process.env.NFT_CHALLENGE_MNEMONIC
      if (!mnemonic) {
        res.status(503).json({ success: false, message: 'NFT challenge not configured' })
        return
      }
      const mnemonicWallet = HDNodeWallet.fromPhrase(mnemonic)
      const privateKey = mnemonicWallet.privateKey
      const publicKey = mnemonicWallet.publicKey
      const address = mnemonicWallet.address
      const submitted = typeof req.body.privateKey === 'string' ? req.body.privateKey : ''
      const isMatch = safeEqual(submitted, privateKey)
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => isMatch)
      if (isMatch) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else if (safeEqual(submitted, address)) {
        res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
      } else if (safeEqual(submitted, publicKey)) {
        res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
      } else {
        res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
