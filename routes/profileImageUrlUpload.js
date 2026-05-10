const fs = require('fs')
const dns = require('dns')
const net = require('net')
const models = require('../models/index')
const insecurity = require('../lib/insecurity')
const request = require('request')
const logger = require('../lib/logger')

module.exports = function profileImageUrlUpload () {
  return (req, res, next) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
        req.app.locals.abused_ssrf_bug = true
      }
      const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        isAllowedImageUrl(url, function (err, allowed) {
          if (err || !allowed) {
            logger.warn('Blocked profile image URL: ' + (err ? err.message : 'URL is not allowed'))
            return
          }
          request
            .get({ url, followRedirect: false })
            .on('error', function (err) {
              logger.warn('Error retrieving authenticated user: ' + err.message)
            })
            .pipe(fs.createWriteStream('frontend/dist/frontend/assets/public/images/uploads/' + loggedInUser.data.id + '.jpg'))
          models.User.findByPk(loggedInUser.data.id).then(user => {
            return user.update({ profileImage: loggedInUser.data.id + '.jpg' })
          }).catch(error => {
            next(error)
          })
        })
      } else {
        next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
      }
    }
    res.location('/profile')
    res.redirect('/profile')
  }
}

function isAllowedImageUrl (imageUrl, callback) {
  let parsedUrl
  try {
    parsedUrl = new URL(imageUrl)
  } catch (err) {
    return callback(err)
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return callback(null, false)
  }
  if (parsedUrl.username || parsedUrl.password) {
    return callback(null, false)
  }
  dns.lookup(parsedUrl.hostname, { all: true }, function (err, addresses) {
    if (err) {
      return callback(err)
    }
    callback(null, addresses.length > 0 && addresses.every(address => isPublicAddress(address.address)))
  })
}

function isPublicAddress (address) {
  if (net.isIP(address) === 4) {
    const parts = address.split('.').map(part => parseInt(part, 10))
    return !(parts[0] === 10 || parts[0] === 127 || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 0)
  }
  if (net.isIP(address) === 6) {
    return !(address === '::1' || address.indexOf('fc') === 0 || address.indexOf('fd') === 0 || address.indexOf('fe80') === 0)
  }
  return false
}
