'use strict';
/**
 * zip-util.js — Dependency-free ZIP/VSIX extractor
 * ================================================
 * WHY THIS EXISTS
 * ---------------
 * Every stage of the pipeline used to unpack a .vsix by shelling out:
 *     spawnSync('unzip', …)      → not present on Windows at all
 *     spawnSync('python3', …)    → on Windows resolves to the Microsoft Store
 *                                  App-Execution-Alias stub, which does not
 *                                  extract anything and can block on a Store
 *                                  prompt.
 * On the analysis host (Windows 11) that meant EVERY .vsix silently failed to
 * unpack — the batch scanner could only ever see the handful of samples that
 * happened to be pre-extracted. A malware scanner that cannot open its own
 * samples reports 100% BENIGN, which is the worst possible failure mode.
 *
 * This module reads the ZIP container directly with `zlib.inflateRawSync`, so
 * the engine has zero external dependencies and behaves identically on
 * Windows / macOS / Linux.
 *
 * Supported: STORE (method 0) and DEFLATE (method 8) — the only two methods the
 * VSIX packer (`vsce`) ever emits. ZIP64 end-of-central-directory is handled so
 * archives with >65535 entries or >4 GiB still resolve.
 *
 * SECURITY: path traversal (`../`, absolute paths, drive letters) is neutralised
 * before anything touches the filesystem — we are unpacking hostile archives.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIG_EOCD    = 0x06054b50;   // End of central directory
const SIG_EOCD64  = 0x06064b50;   // ZIP64 end of central directory record
const SIG_LOC64   = 0x07064b50;   // ZIP64 end of central directory locator
const SIG_CEN     = 0x02014b50;   // Central directory file header
const SIG_LOC     = 0x04034b50;   // Local file header

/** Locate the End-Of-Central-Directory record (scans the last 64 KiB + comment). */
function findEocd(buf) {
  const min = Math.max(0, buf.length - 0x10000 - 22);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

/**
 * Parse the central directory into entry descriptors.
 * @param {Buffer} buf whole archive
 * @returns {Array<{name:string, method:number, compressedSize:number, size:number, localOffset:number, isDir:boolean}>}
 */
function readCentralDirectory(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error('not a ZIP archive (no end-of-central-directory record)');

  let entryCount = buf.readUInt16LE(eocd + 10);
  let cdOffset   = buf.readUInt32LE(eocd + 16);

  // ZIP64: the 32-bit fields saturate; the real values live in the ZIP64 EOCD.
  if (entryCount === 0xffff || cdOffset === 0xffffffff) {
    const locOff = eocd - 20;
    if (locOff >= 0 && buf.readUInt32LE(locOff) === SIG_LOC64) {
      const z64 = Number(buf.readBigUInt64LE(locOff + 8));
      if (z64 >= 0 && z64 + 56 <= buf.length && buf.readUInt32LE(z64) === SIG_EOCD64) {
        entryCount = Number(buf.readBigUInt64LE(z64 + 32));
        cdOffset   = Number(buf.readBigUInt64LE(z64 + 48));
      }
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== SIG_CEN) break;
    const method    = buf.readUInt16LE(p + 10);
    let   compSize  = buf.readUInt32LE(p + 20);
    let   size      = buf.readUInt32LE(p + 24);
    const nameLen   = buf.readUInt16LE(p + 28);
    const extraLen  = buf.readUInt16LE(p + 30);
    const commentLen= buf.readUInt16LE(p + 32);
    let   localOff  = buf.readUInt32LE(p + 42);
    const name      = buf.toString('utf8', p + 46, p + 46 + nameLen);

    // ZIP64 extended-information extra field (0x0001) overrides saturated sizes.
    if (size === 0xffffffff || compSize === 0xffffffff || localOff === 0xffffffff) {
      let e = p + 46 + nameLen;
      const extraEnd = e + extraLen;
      while (e + 4 <= extraEnd) {
        const hid = buf.readUInt16LE(e), hlen = buf.readUInt16LE(e + 2);
        if (hid === 0x0001) {
          let q = e + 4;
          if (size     === 0xffffffff && q + 8 <= extraEnd) { size     = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (compSize === 0xffffffff && q + 8 <= extraEnd) { compSize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (localOff === 0xffffffff && q + 8 <= extraEnd) { localOff = Number(buf.readBigUInt64LE(q)); q += 8; }
          break;
        }
        e += 4 + hlen;
      }
    }

    entries.push({
      name, method, compressedSize: compSize, size, localOffset: localOff,
      isDir: /[/\\]$/.test(name) || (size === 0 && /[/\\]$/.test(name)),
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Decompress one entry to a Buffer. */
function readEntry(buf, ent) {
  const lo = ent.localOffset;
  if (lo + 30 > buf.length || buf.readUInt32LE(lo) !== SIG_LOC) {
    throw new Error(`corrupt local header for ${ent.name}`);
  }
  // The local header's name/extra lengths are authoritative for the data offset
  // (they legitimately differ from the central directory's).
  const nameLen  = buf.readUInt16LE(lo + 26);
  const extraLen = buf.readUInt16LE(lo + 28);
  const start    = lo + 30 + nameLen + extraLen;
  const raw      = buf.subarray(start, start + ent.compressedSize);

  if (ent.method === 0) return raw;
  if (ent.method === 8) return zlib.inflateRawSync(raw);
  throw new Error(`unsupported compression method ${ent.method} for ${ent.name}`);
}

/**
 * Neutralise path traversal: strip drive letters, leading separators and any
 * `..` segment. Returns null when nothing safe remains.
 */
function safeJoin(destDir, entryName) {
  const cleaned = String(entryName)
    .replace(/\\/g, '/')
    .replace(/^[a-zA-Z]:/, '')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join(path.sep);
  if (!cleaned) return null;
  const full = path.join(destDir, cleaned);
  // Belt-and-braces: the resolved path must still live under destDir.
  const rel = path.relative(path.resolve(destDir), path.resolve(full));
  if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return full;
}

/**
 * Extract an archive to `destDir`.
 *
 * @param {string} archivePath  .vsix / .zip
 * @param {string} destDir      created if missing
 * @param {Object} [opts]
 * @param {number} [opts.maxEntries=20000]        guard against zip bombs
 * @param {number} [opts.maxTotalBytes=400MiB]    guard against zip bombs
 * @param {RegExp} [opts.skip]                    entry names to ignore
 * @returns {{extracted:number, skipped:number, bytes:number, errors:string[]}}
 */
function extractZip(archivePath, destDir, opts = {}) {
  const maxEntries    = opts.maxEntries    != null ? opts.maxEntries    : 20000;
  const maxTotalBytes = opts.maxTotalBytes != null ? opts.maxTotalBytes : 400 * 1024 * 1024;
  const skip          = opts.skip || null;

  const buf     = fs.readFileSync(archivePath);
  const entries = readCentralDirectory(buf);

  fs.mkdirSync(destDir, { recursive: true });

  let extracted = 0, skipped = 0, bytes = 0;
  const errors = [];

  for (const ent of entries) {
    if (extracted >= maxEntries || bytes >= maxTotalBytes) { skipped++; continue; }
    if (skip && skip.test(ent.name))                       { skipped++; continue; }

    const target = safeJoin(destDir, ent.name);
    if (!target) { skipped++; continue; }

    if (ent.isDir) { try { fs.mkdirSync(target, { recursive: true }); } catch (_) {} continue; }

    try {
      const data = readEntry(buf, ent);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, data);
      extracted++;
      bytes += data.length;
    } catch (e) {
      errors.push(`${ent.name}: ${e.message}`);
    }
  }
  return { extracted, skipped, bytes, errors };
}

/**
 * Read a single file out of an archive WITHOUT extracting it (used for cheap
 * metadata probes such as `extension/package.json`).
 * @returns {Buffer|null}
 */
function readFileFromZip(archivePath, entryName) {
  try {
    const buf  = fs.readFileSync(archivePath);
    const want = String(entryName).replace(/\\/g, '/').toLowerCase();
    for (const ent of readCentralDirectory(buf)) {
      if (ent.name.replace(/\\/g, '/').toLowerCase() === want) return readEntry(buf, ent);
    }
  } catch (_) {}
  return null;
}

/** List entry names without extracting. */
function listZip(archivePath) {
  try { return readCentralDirectory(fs.readFileSync(archivePath)).map((e) => e.name); }
  catch (_) { return []; }
}

/**
 * Extract, then descend to the directory that actually holds package.json.
 * A .vsix always unpacks to `<dest>/extension/`, but hand-made zips vary.
 * @returns {string} the extension root
 */
function extractVsix(archivePath, destDir, opts = {}) {
  extractZip(archivePath, destDir, opts);
  const ext = path.join(destDir, 'extension');
  if (fs.existsSync(path.join(ext, 'package.json'))) return ext;
  if (fs.existsSync(path.join(destDir, 'package.json'))) return destDir;
  // One more level for oddly-nested archives.
  let ents; try { ents = fs.readdirSync(destDir, { withFileTypes: true }); } catch (_) { return destDir; }
  for (const e of ents) {
    if (!e.isDirectory()) continue;
    const d = path.join(destDir, e.name);
    if (fs.existsSync(path.join(d, 'extension', 'package.json'))) return path.join(d, 'extension');
    if (fs.existsSync(path.join(d, 'package.json')))              return d;
  }
  return ext;
}

module.exports = { extractZip, extractVsix, readFileFromZip, listZip, readCentralDirectory };
