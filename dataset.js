'use strict';
/**
 * dataset.js — Dataset Ingestion & Ground-Truth Resolution
 * ========================================================
 * One module that understands EVERY corpus layout this project touches, so the
 * orchestrator never has to care which dataset it is pointed at.
 *
 * SUPPORTED LAYOUTS
 * -----------------
 * (A) DataDog  ("Dataset_Malicious/" · "Dataset_Benign/")
 *       <root>/<publisher>.<name>/<version>.vsix
 *       <root>/<publisher>.<name>/<version>/extension/package.json   (pre-unpacked)
 *       <root>/Sample/Sample/<publisher>.<name>-<version>.vsix       (loose extras)
 *     Ground truth comes from the corpus itself: everything under a
 *     *_Malicious tree is label 1, everything under a *_Benign tree is label 0.
 *
 * (B) VsMex  (Alachkar et al., CODASPY '26)
 *       <root>/extensions/<publisher>.<name>/<version>/<publisher>.<name>-<version>.vsix
 *       <root>/metadata/vsmex_metadata.csv               ← per (extension, version)
 *       <root>/metadata/msft_vscode_flagged_extensions.csv ← per extension
 *     Ground truth comes from Microsoft's own removal reason
 *     (`msft_classification_type`), which is NOT uniformly "malware" — see
 *     CLASSIFICATION_TIERS below. This distinction is the single most important
 *     thing to get right when reporting recall on VsMex.
 *
 * (C) Generic — any tree containing .vsix files and/or extension directories.
 *
 * INVARIANTS
 * ----------
 *   • node_modules is NEVER descended when discovering samples (a single
 *     extension can ship 2 000 nested package.json files; scanning them as
 *     separate samples was the reason earlier batch runs produced junk rows
 *     named "node-fetch" and "fetch-blob").
 *   • When a sample exists BOTH as a .vsix and as a pre-unpacked directory the
 *     .vsix wins: it is the pristine artefact, whereas unpacked trees are
 *     polluted with execution-log.json / static-analysis.json from prior runs.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
//  Microsoft removal-reason → evidence tier
//
//  VsMex is a dataset of extensions REMOVED BY MICROSOFT, not a dataset of
//  malware. Roughly half the corpus was pulled for brand impersonation,
//  copyright or spam — policy violations whose code is frequently a verbatim
//  clone of the legitimate extension and therefore contains NO malicious
//  behaviour to detect. Scoring a behavioural engine against those samples
//  measures nothing, so we tier them:
//
//    code    — the removal reason asserts hostile CODE. A behavioural/static
//              engine is expected to catch these. This is the primary metric.
//    suspect — "Untrustworthy": Microsoft's catch-all for risky-but-unproven.
//              Reported separately; counted in the permissive matrix only.
//    policy  — impersonation / copyright / spam / owner request. Detectable
//              only by publisher reputation and marketplace metadata, never by
//              analysing the bundle. Excluded from the primary matrix and
//              reported as a coverage note.
// ─────────────────────────────────────────────────────────────────────────────
const CLASSIFICATION_TIERS = {
  'malware':               'code',
  'malicious':             'code',
  'potentially malicious': 'code',
  'spam / malware':        'code',
  'trojan':                'code',
  'untrustworthy':         'suspect',
  'impersonation':         'policy',
  'typo-squatting':        'policy',
  'copyright violation':   'policy',
  'spam':                  'policy',
  'owner request':         'policy',
  'publisher requested':   'policy',
  'publisher request':     'policy',
  'deprecated':            'policy',
  'expired domain':        'policy',
};

const TIER_RANK = { unknown: 0, policy: 1, suspect: 2, code: 3 };

/**
 * Normalise a raw classification cell → evidence tier.
 * Cells may carry several reasons ("Impersonation;Malware", "Spam / Malware");
 * the STRONGEST tier wins, so a sample flagged for both impersonation and
 * malware is still scored as code-level malware.
 */
function tierOf(rawClassification) {
  const raw = String(rawClassification || '').replace(/^"+|"+$/g, '').trim().toLowerCase();
  if (!raw) return 'unknown';
  if (CLASSIFICATION_TIERS[raw]) return CLASSIFICATION_TIERS[raw];      // exact match first
  let best = 'unknown';
  for (const part of raw.split(/[;,|]/)) {
    const t = CLASSIFICATION_TIERS[part.trim()] || 'policy';
    if (TIER_RANK[t] > TIER_RANK[best]) best = t;
  }
  return best;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Minimal RFC-4180 CSV reader (quoted fields, embedded commas + newlines)
// ─────────────────────────────────────────────────────────────────────────────
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim());
  return rows.slice(1)
    .filter((r) => r.length > 1)
    .map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] !== undefined ? r[i] : ''])));
}

const readCsv = (p) => { try { return parseCsv(fs.readFileSync(p, 'utf8')); } catch (_) { return []; } };

// ─────────────────────────────────────────────────────────────────────────────
//  Filesystem walking
// ─────────────────────────────────────────────────────────────────────────────
const SKIP_DIRS = new Set(['node_modules', '.git', '.vscode-test', 'out-test', '__pycache__']);

function safeReaddir(d) { try { return fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return []; } }

/** Recursively collect .vsix paths, never descending into node_modules. */
function findVsix(root, out = [], depth = 0) {
  if (depth > 8) return out;
  for (const e of safeReaddir(root)) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) findVsix(full, out, depth + 1); }
    else if (/\.vsix$/i.test(e.name)) out.push(full);
  }
  return out;
}

/**
 * Collect unpacked extension roots (dirs holding package.json), never
 * descending INTO an extension once found and never into node_modules.
 */
function findExtensionDirs(root, out = [], depth = 0) {
  if (depth > 6) return out;
  if (fs.existsSync(path.join(root, 'package.json'))) { out.push(root); return out; }
  for (const e of safeReaddir(root)) {
    if (!e.isDirectory() || SKIP_DIRS.has(e.name)) continue;
    findExtensionDirs(path.join(root, e.name), out, depth + 1);
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Identity parsing
// ─────────────────────────────────────────────────────────────────────────────
const SEMVERISH = /^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/;

/**
 * Derive { id, publisher, name, version } from a sample path.
 * Handles all three naming conventions in play:
 *   .../<pub.name>/<version>.vsix                       (DataDog)
 *   .../<pub.name>/<version>/<pub.name>-<version>.vsix  (VsMex)
 *   .../<pub.name>-<version>.vsix                       (loose)
 */
function identify(samplePath, isDir) {
  const base   = path.basename(samplePath, isDir ? '' : path.extname(samplePath));
  const parent = path.basename(path.dirname(samplePath));
  const gp     = path.basename(path.dirname(path.dirname(samplePath)));

  let id = '', version = '';

  // `<pub.name>-<ver>/extension` — the identity lives in the grandparent name.
  const nameSource = (isDir && base === 'extension') ? parent : base;

  // <pub.name>-<version> in the name itself (VsMex + loose files).
  const m = nameSource.match(/^(.+?)-(v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?)$/);
  if (m && m[1].includes('.')) { id = m[1]; version = m[2]; }

  if (!id) {
    if (SEMVERISH.test(base)) { version = base; id = parent; }          // <pub.name>/<ver>.vsix
    else if (SEMVERISH.test(parent)) { version = parent; id = gp; }     // <pub.name>/<ver>/extension
    else if (base === 'extension' && SEMVERISH.test(parent)) { version = parent; id = gp; }
    else id = base;
  }
  // `<pub.name>/<ver>/extension` — climb one more level for the real id.
  if (id === 'extension' && SEMVERISH.test(parent)) id = gp;

  const dot = id.indexOf('.');
  return {
    id,
    publisher: dot > 0 ? id.slice(0, dot) : '',
    name:      dot > 0 ? id.slice(dot + 1) : id,
    version:   version.replace(/^v/, ''),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Layout detection
// ─────────────────────────────────────────────────────────────────────────────

/** Descend through single-child wrapper dirs (Dataset_Malicious/Dataset_Malicious/…). */
function unwrapRoot(root) {
  let cur = path.resolve(root);
  for (let i = 0; i < 4; i++) {
    if (fs.existsSync(path.join(cur, 'extensions')) && fs.existsSync(path.join(cur, 'metadata'))) return cur;
    const kids = safeReaddir(cur).filter((e) => e.isDirectory() && !e.name.startsWith('.'));
    const files = safeReaddir(cur).filter((e) => e.isFile() && /\.vsix$/i.test(e.name));
    if (files.length) return cur;
    if (kids.length === 1 && kids[0].name.toLowerCase() === path.basename(cur).toLowerCase()) {
      cur = path.join(cur, kids[0].name);                     // Dataset_X/Dataset_X
      continue;
    }
    if (kids.length === 1 && ['vsmex-dataset', 'vsmex-main', 'extensions'].includes(kids[0].name)) {
      cur = path.join(cur, kids[0].name);
      continue;
    }
    return cur;
  }
  return cur;
}

function detectKind(root) {
  if (fs.existsSync(path.join(root, 'extensions')) && fs.existsSync(path.join(root, 'metadata'))) return 'vsmex';
  const b = path.basename(root).toLowerCase();
  if (b.includes('malicious')) return 'datadog-malicious';
  if (b.includes('benign'))    return 'datadog-benign';
  return 'generic';
}

// ─────────────────────────────────────────────────────────────────────────────
//  VsMex label index
// ─────────────────────────────────────────────────────────────────────────────
function loadVsmexLabels(root) {
  const metaDir  = path.join(root, 'metadata');
  const perVer   = readCsv(path.join(metaDir, 'vsmex_metadata.csv'));
  const perExt   = readCsv(path.join(metaDir, 'msft_vscode_flagged_extensions.csv'));

  const byVersion = new Map();   // "id@version" → { classification, tier, … }
  const byId      = new Map();   // "id"         → { classification, tier, … }

  for (const r of perExt) {
    const id = (r.extension_identifier || '').trim();
    if (!id) continue;
    const cls = r.msft_classification_type || '';
    byId.set(id.toLowerCase(), {
      classification: cls, tier: tierOf(cls),
      removed_date: r.msft_removed_date || '', source: r.source || '',
    });
  }
  for (const r of perVer) {
    const id  = (r.extension_identifier || '').trim();
    const ver = (r.version || '').trim();
    if (!id) continue;
    const cls = r.msft_classification_type || '';
    const rec = {
      classification: cls, tier: tierOf(cls),
      publisher: r.publisher_name || '', sha256: r.sha256 || '',
      size_mb: r.size_mb || '', installs: r.installation_count || '',
      categories: r.categories || '', repository: r.repository_url || '',
      verified_publisher: r.verified_publisher || '', source: r.source || '',
    };
    byVersion.set(`${id.toLowerCase()}@${ver}`, rec);
    if (!byId.has(id.toLowerCase())) byId.set(id.toLowerCase(), rec);
  }
  return { byVersion, byId, versionRows: perVer.length, extRows: perExt.length };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Discovery
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enumerate every analysable sample under `inputRoot`.
 *
 * @param {string} inputRoot
 * @param {Object} [opts]
 * @param {number} [opts.label]            force the ground-truth label (0/1)
 * @param {boolean}[opts.latestOnly=false] keep only the newest version per extension
 * @param {number} [opts.limit]            cap the sample count (after sorting)
 * @param {string} [opts.datasetName]      label used in reports
 * @param {string[]}[opts.includeTiers]    keep ONLY these evidence tiers
 * @param {string[]}[opts.excludeTiers]    drop these evidence tiers
 * @returns {{root:string, kind:string, datasetName:string, samples:Array, stats:Object}}
 */
function discover(inputRoot, opts = {}) {
  const root = unwrapRoot(inputRoot);
  const kind = detectKind(root);
  const datasetName = opts.datasetName || path.basename(root);

  const scanRoot = kind === 'vsmex' ? path.join(root, 'extensions') : root;
  const labels   = kind === 'vsmex' ? loadVsmexLabels(root) : null;

  // 1. Every .vsix in the tree (node_modules excluded by findVsix).
  const vsixList = findVsix(scanRoot);

  // 2. Pre-unpacked extension dirs, minus any whose sibling .vsix we already have.
  const vsixKeys = new Set(vsixList.map((v) => {
    const i = identify(v, false);
    return `${i.id.toLowerCase()}@${i.version}`;
  }));
  const dirList = findExtensionDirs(scanRoot).filter((d) => {
    const i = identify(d, true);
    return !vsixKeys.has(`${i.id.toLowerCase()}@${i.version}`);
  });

  const samples = [];
  const push = (target, isDir) => {
    const ident = identify(target, isDir);
    const key   = `${ident.id.toLowerCase()}@${ident.version}`;

    let label = opts.label != null ? Number(opts.label) : null;
    let tier = 'unknown', classification = '', meta = null;

    if (kind === 'vsmex') {
      meta = labels.byVersion.get(key) || labels.byId.get(ident.id.toLowerCase()) || null;
      classification = meta ? meta.classification : '';
      tier = meta ? meta.tier : 'unknown';
      // Every extension in VsMex was removed by Microsoft ⇒ positive class.
      if (label == null) label = 1;
    } else {
      // DataDog: ground truth is the tree the sample lives in. The tier is
      // derived from the resolved label, NOT only when the label was inferred —
      // an explicitly-passed --label must still produce a usable tier, or the
      // stratified reporting silently degrades to "unknown".
      if (label == null) {
        if (kind === 'datadog-malicious') label = 1;
        else if (kind === 'datadog-benign') label = 0;
        else label = null;
      }
      tier = label === 1 ? 'code' : label === 0 ? 'benign' : 'unknown';
      classification = label === 1 ? 'DataDog malicious' : label === 0 ? 'DataDog benign' : '';
    }

    samples.push({
      key, id: ident.id, publisher: ident.publisher, name: ident.name, version: ident.version,
      target, is_dir: isDir, dataset: datasetName, dataset_kind: kind,
      label, classification, tier,
      meta: meta || undefined,
    });
  };

  for (const v of vsixList) push(v, false);
  for (const d of dirList)  push(d, true);

  // Deterministic ordering so partial/limited runs are reproducible.
  samples.sort((a, b) => (a.id + a.version).localeCompare(b.id + b.version));

  let out = samples;

  // ── Evidence-tier filtering ────────────────────────────────────────────────
  //  Lets a run target only the population an engine is actually built for, e.g.
  //      discover(root, { includeTiers: ['code'] })       // code-level only
  //      discover(root, { excludeTiers: ['policy'] })     // drop impersonation etc.
  //
  //  ⚠ READ THIS BEFORE USING IT TO PRODUCE HEADLINE NUMBERS.
  //  Excluding a tier does NOT make the detector better; it changes which
  //  question the metric answers, and it cuts both ways. On this corpus the
  //  1,774 `policy` samples are not inert: 272 of them were independently
  //  scored MALICIOUS on code evidence (Microsoft's removal *reason* was
  //  impersonation, but the bundle also carried a payload — the dataset even
  //  contains explicit `Impersonation;Malware` rows). Dropping the tier
  //  therefore discards 272 genuine detections along with the unreachable ones.
  //
  //  That is why the DEFAULT remains "analyse everything, report stratified":
  //  benchmark.js publishes a code-level matrix, a full-corpus matrix and a
  //  per-removal-reason breakdown, so the out-of-scope population is visible and
  //  attributable rather than quietly deleted. Use these filters to answer a
  //  scoped question, not to improve a headline.
  const norm = (v) => (Array.isArray(v) ? v : String(v).split(',')).map((s) => String(s).trim().toLowerCase()).filter(Boolean);
  if (opts.includeTiers) {
    const keep = new Set(norm(opts.includeTiers));
    out = out.filter((s) => keep.has(s.tier));
  }
  if (opts.excludeTiers) {
    const drop = new Set(norm(opts.excludeTiers));
    out = out.filter((s) => !drop.has(s.tier));
  }

  if (opts.latestOnly) {
    const best = new Map();
    for (const s of out) {
      const cur = best.get(s.id.toLowerCase());
      if (!cur || compareVersions(s.version, cur.version) > 0) best.set(s.id.toLowerCase(), s);
    }
    out = [...best.values()].sort((a, b) => a.id.localeCompare(b.id));
  }
  if (opts.limit > 0) out = out.slice(0, opts.limit);

  const stats = {
    root, kind, dataset: datasetName,
    vsix_found: vsixList.length,
    unpacked_dirs_found: dirList.length,
    total_discovered: samples.length,
    selected: out.length,
    excluded_by_tier: samples.length - out.length - (opts.limit > 0 ? Math.max(0, out.length - opts.limit) : 0),
    tier_filter: opts.includeTiers ? { include: norm(opts.includeTiers) }
               : opts.excludeTiers ? { exclude: norm(opts.excludeTiers) } : undefined,
    tiers: countBy(out, (s) => s.tier),
    classifications: countBy(out, (s) => s.classification || '(none)'),
    metadata_rows: labels ? { per_version: labels.versionRows, per_extension: labels.extRows } : undefined,
  };

  return { root, kind, datasetName, samples: out, stats };
}

function countBy(arr, fn) {
  const m = {};
  for (const x of arr) { const k = fn(x); m[k] = (m[k] || 0) + 1; }
  return m;
}

/** Numeric-aware semver-ish comparison (returns <0, 0, >0). */
function compareVersions(a, b) {
  const pa = String(a || '').split(/[.\-+]/), pb = String(b || '').split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = parseInt(pa[i], 10), y = parseInt(pb[i], 10);
    const nx = Number.isNaN(x) ? -1 : x, ny = Number.isNaN(y) ? -1 : y;
    if (nx !== ny) return nx - ny;
  }
  return 0;
}

module.exports = {
  discover, identify, findVsix, findExtensionDirs,
  parseCsv, readCsv, tierOf, compareVersions, unwrapRoot, detectKind,
  CLASSIFICATION_TIERS, SKIP_DIRS,
};
