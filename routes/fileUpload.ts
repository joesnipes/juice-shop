/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

const EXTRACT_ROOT = path.resolve('uploads/complaints')
const MAX_TOTAL_EXTRACTED_BYTES = 5 * 1024 * 1024 // 5 MiB hard cap to prevent zip-bombs
const MAX_PER_ENTRY_BYTES = 1 * 1024 * 1024 // 1 MiB per file

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (!utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    next()
    return
  }

  if ((file?.buffer) == null) {
    res.status(204).end()
    return
  }

  const buffer = file.buffer
  const filename = file.originalname.toLowerCase()
  const tempFile = path.join(os.tmpdir(), filename)
  fs.open(tempFile, 'w', function (err, fd) {
    if (err != null) { next(err); return }
    fs.write(fd, buffer, 0, buffer.length, null, function (err) {
      if (err != null) { next(err); return }
      fs.close(fd, function () {
        let totalExtracted = 0
        fs.createReadStream(tempFile)
          .pipe(unzipper.Parse())
          .on('entry', function (entry: any) {
            const rawName = String(entry.path)
            // SECURITY (JS-AUDIT-011 / CWE-22): full hardened zip-slip
            // protection — sanitise filename, resolve against the fixed
            // extract root, reject symlinks/absolute paths/traversal,
            // enforce per-entry and total decompressed-size limits.
            if (entry.type !== 'File' || path.isAbsolute(rawName) || rawName.includes('\x00')) {
              entry.autodrain()
              return
            }
            const safeName = path.basename(rawName) // strip any traversal segments
            if (!safeName || safeName === '.' || safeName === '..') {
              entry.autodrain()
              return
            }
            const target = path.resolve(EXTRACT_ROOT, safeName)
            if (!target.startsWith(EXTRACT_ROOT + path.sep) && target !== EXTRACT_ROOT) {
              entry.autodrain()
              return
            }

            let entrySize = 0
            const out = fs.createWriteStream(target)
              .on('error', function (err) { next(err) })
            entry.on('data', (chunk: Buffer) => {
              entrySize += chunk.length
              totalExtracted += chunk.length
              if (entrySize > MAX_PER_ENTRY_BYTES || totalExtracted > MAX_TOTAL_EXTRACTED_BYTES) {
                entry.destroy(new Error('Decompressed size limit exceeded'))
                out.destroy()
              }
            })
            entry.pipe(out)
          })
          .on('error', function (err: unknown) { next(err) })
      })
    })
  })
  res.status(204).end()
}

function checkUploadSize (_req: Request, _res: Response, next: NextFunction) {
  next()
}

function checkFileType (_req: Request, _res: Response, next: NextFunction) {
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    if ((file?.buffer) != null) {
      const data = file.buffer.toString()
      try {
        // SECURITY (JS-AUDIT-012 / CWE-611): disable DOCTYPE / external
        // entity expansion. `noent:false` plus `dtdload:false` and
        // `noblanks:true` prevents XXE file-disclosure and billion-laughs
        // amplification without dropping the parser entirely.
        const xmlDoc = libxml.parseXml(data, {
          noblanks: true,
          noent: false,
          nocdata: true,
          dtdload: false,
          dtdvalid: false,
          nonet: true
        })
        const xmlString = xmlDoc.toString(false)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
        return
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        return
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
      return
    }
  }
  next()
}

const MAX_YAML_INPUT_BYTES = 50 * 1024 // 50 KiB cap

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    if ((file?.buffer) != null) {
      const data = file.buffer.toString()
      if (data.length > MAX_YAML_INPUT_BYTES) {
        res.status(413)
        next(new Error('YAML upload exceeds size cap'))
        return
      }
      try {
        // SECURITY (JS-AUDIT-013 / CWE-502): use FAILSAFE_SCHEMA which
        // only resolves strings/maps/sequences — disallowing custom tags
        // that could instantiate JS objects, and limiting the impact of
        // YAML anchors. We additionally pass `json:false` to fail on
        // duplicate keys.
        const parsed = yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA, json: false })
        const yamlString = JSON.stringify(parsed)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
        return
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        return
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
      return
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
