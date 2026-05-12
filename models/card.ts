/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

// SECURITY (JS-AUDIT-037 / CWE-311 + PCI-DSS): NEVER persist full PANs.
// The previous schema stored a 16-digit integer with no tokenisation.
// The hook below truncates any submitted card number down to the last
// four digits BEFORE the row is written, so even if a caller sends a
// full PAN the database never sees more than the last four. A
// `paymentToken` column is added so the application can store a
// reference to a PCI-compliant processor (e.g. Stripe) for actual
// charging.
class Card extends Model<
InferAttributes<Card>,
InferCreationAttributes<Card>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare fullName: string
  declare cardNum: number
  declare paymentToken: CreationOptional<string | null>
  declare expMonth: number
  declare expYear: number
}

function lastFourOf (value: number | string | null | undefined): number {
  if (value == null) return 0
  const digits = String(value).replace(/\D/g, '')
  if (!digits) return 0
  return Number(digits.slice(-4))
}

const CardModelInit = (sequelize: Sequelize) => {
  Card.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      fullName: DataTypes.STRING,
      cardNum: {
        type: DataTypes.INTEGER,
        // Validation relaxed because we deliberately truncate to last 4
        // digits in the beforeValidate hook below.
        validate: {
          isInt: true,
          min: 0,
          max: 9999999999999998 // tolerate inbound full PAN that will be truncated
        }
      },
      paymentToken: {
        type: DataTypes.STRING,
        allowNull: true
      },
      expMonth: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 1,
          max: 12
        }
      },
      expYear: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 2080,
          max: 2099
        }
      }
    },
    {
      hooks: {
        beforeValidate (card: Card) {
          if (card.cardNum != null) {
            card.cardNum = lastFourOf(card.cardNum)
          }
        }
      },
      tableName: 'Cards',
      sequelize
    }
  )
}

export { Card as CardModel, CardModelInit }
