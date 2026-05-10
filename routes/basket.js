const utils = require('../lib/utils')
const insecurity = require('../lib/insecurity')
const models = require('../models/index')
const challenges = require('../data/datacache').challenges

module.exports = function retrieveBasket () {
  return (req, res, next) => {
    const id = req.params.id
    const user = insecurity.authenticatedUsers.from(req)
    if (!user || !id || id === 'undefined' || id === 'null' || user.bid != id) { // eslint-disable-line eqeqeq
      return res.status(403).json({ error: 'Basket access denied' })
    }
    models.Basket.findOne({ where: { id, userId: user.data.id }, include: [ { model: models.Product, paranoid: false } ] })
      .then(basket => {
        /* jshint eqeqeq:false */
        if (utils.notSolved(challenges.basketAccessChallenge)) {
          if (user && id && id !== 'undefined' && id !== 'null' && user.bid != id) { // eslint-disable-line eqeqeq
            utils.solve(challenges.basketAccessChallenge)
          }
        }
        res.json(utils.queryResultToJson(basket))
      }).catch(error => {
        next(error)
      })
  }
}
