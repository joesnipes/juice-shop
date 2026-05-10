const utils = require('../lib/utils')
const challenges = require('../data/datacache').challenges
const libxml = require('libxmljs2')
const os = require('os')
const fs = require('fs')
const unzipper = require('unzipper')
const path = require('path')

module.exports = function fileUpload () {
  return (req, res, next) => {
    if (req.file) {
      const file = req.file
      if (utils.endsWith(file.originalname.toLowerCase(), '.zip')) {
        const buffer = file.buffer
        const filename = file.originalname.toLowerCase()
        const tempFile = path.join(os.tmpdir(), filename)
        fs.open(tempFile, 'w', function (err, fd) {
          if (err) { next(err) }
          fs.write(fd, buffer, 0, buffer.length, null, function (err) {
            if (err) { next(err) }
            fs.close(fd, function () {
              fs.createReadStream(tempFile)
                .pipe(unzipper.Parse())
                .on('entry', function (entry) {
                  const fileName = entry.path
                  const targetDir = path.resolve('uploads/complaints')
                  const absolutePath = path.resolve(targetDir, fileName)
                  if (absolutePath === path.resolve('ftp/legal.md') && utils.notSolved(challenges.fileWriteChallenge)) {
                    utils.solve(challenges.fileWriteChallenge)
                  }
                  if (absolutePath === targetDir || absolutePath.indexOf(targetDir + path.sep) !== 0) {
                    entry.autodrain()
                  } else {
                    entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
                  }
                }).on('error', function (err) { next(err) })
            })
          })
        })
      }
      if (utils.notSolved(challenges.uploadSizeChallenge) && file.size > 100000) {
        utils.solve(challenges.uploadSizeChallenge)
      }
      if (utils.notSolved(challenges.uploadTypeChallenge) && !(utils.endsWith(file.originalname.toLowerCase(), '.pdf') ||
        utils.endsWith(file.originalname.toLowerCase(), '.xml') || utils.endsWith(file.originalname.toLowerCase(), '.zip'))) {
        utils.solve(challenges.uploadTypeChallenge)
      }
      if (utils.endsWith(file.originalname.toLowerCase(), '.xml')) {
        if (utils.notSolved(challenges.deprecatedInterfaceChallenge)) {
          utils.solve(challenges.deprecatedInterfaceChallenge)
        }
        if (file.buffer && !utils.disableOnContainerEnv()) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
          const data = file.buffer.toString()
          try {
            const xmlDoc = libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })
            const xmlString = xmlDoc.toString(false)
            if (utils.notSolved(challenges.xxeFileDisclosureChallenge) && (matchesSystemIniFile(xmlString) || matchesEtcPasswdFile(xmlString))) {
              utils.solve(challenges.xxeFileDisclosureChallenge)
            }
            res.status(410)
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file.originalname + ')'))
          } catch (err) {
            if (utils.contains(err.message, 'Script execution timed out')) {
              if (utils.notSolved(challenges.xxeDosChallenge)) {
                utils.solve(challenges.xxeDosChallenge)
              }
              res.status(503)
              next(new Error('Sorry, we are temporarily not available! Please try again later.'))
            } else {
              res.status(410)
              next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
            }
          }
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file.originalname + ')'))
        }
      }
      res.status(204).end()
    }

    function matchesSystemIniFile (text) {
      const match = text.match(/(; for 16-bit app support|drivers|mci|driver32|386enh|keyboard|boot|display)/gi)
      return match && match.length >= 2
    }

    function matchesEtcPasswdFile (text) {
      const match = text.match(/\w*:\w*:\d*:\d*:\w*:.*/gi)
      return match && match.length >= 2
    }
  }
}
