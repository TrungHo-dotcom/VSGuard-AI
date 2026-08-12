'use strict';
/**
 * data-intel.js — Sensitive-Data Intelligence & Exfiltration Taint Layer  (v3)
 * ============================================================================
 * Answers the question the detector previously could NOT: when a malicious
 * extension steals data, *what exactly* is it taking, and *where* does it
 * send it?
 *
 * v3 — STRICT CLOSED-LOOP TAINT
 * -----------------------------
 * v2 raised "data_stolen" whenever an outbound payload merely LOOKED like it
 * contained a secret (`via:'pattern'`). That is a false-positive engine: a
 * legitimate AI extension sending `Authorization: Bearer <its own token>`, or a
 * linter posting a file that happens to contain the word `SECRET=`, tripped it.
 *
 * v3 separates two fundamentally different claims:
 *
 *   CONFIRMED  A TAINT SOURCE and a TAINT SINK are joined by a closed loop:
 *              bytes this process watched the extension READ from a sensitive
 *              location are now present in bytes the extension is SENDING.
 *              Source → Sink is proven; the flow is recorded end-to-end.
 *              ONLY this drives a MALICIOUS verdict.
 *
 *   SUSPECTED  The payload matches a secret pattern but we never observed the
 *              corresponding read (it could be the extension's own credential,
 *              a fixture, or user-typed input). Reported, scored low, never
 *              sufficient on its own.
 *
 * Token strength is tracked too, because not all taint is equal:
 *   strong — the exact bytes of a recognised secret (private key, AKIA…, ghp_…)
 *   weak   — a distinctive line lifted from a sensitive file. Enough to prove a
 *            flow, but for `source_code` (which benign AI assistants legitimately
 *            upload) a weak match alone is downgraded to SUSPECTED so that
 *            "Copilot sent my file to its API" is not scored as theft.
 *
 * Evidence is REDACTED (first/last few chars) so the report proves the theft
 * without dumping raw private keys into log files.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Secret classification rules
//   pathRe    — matches the file path being read (location-based signal)
//   contentRe — matches inside the file content / payload (value-based signal)
//   sev       — severity to attach when this category is merely READ
//   quietRead — track for taint, but do not report the read itself
//   weakOnly  — a weak (line-level) taint hit is NOT enough to confirm theft
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_RULES = [
  { category: 'ssh_private_key',     sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.ssh[\/\\]/i,
    contentRe: /-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----/ },

  { category: 'aws_credentials',     sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.aws[\/\\](?:credentials|config)/i,
    contentRe: /aws_secret_access_key|AKIA[0-9A-Z]{16}/ },

  { category: 'gcp_credentials',     sev: 'CRITICAL',
    pathRe: /application_default_credentials\.json|[\/\\]gcloud[\/\\]/i,
    contentRe: /"private_key":\s*"-----BEGIN/ },

  { category: 'dotenv_secrets',      sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.env(\.\w+)?$/i,
    contentRe: /\b(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)\b\s*[:=]\s*\S+/i },

  { category: 'github_token',        sev: 'CRITICAL',
    pathRe: /\.config[\/\\]gh[\/\\]|hosts\.yml/i,
    contentRe: /gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/ },

  { category: 'npm_token',           sev: 'CRITICAL',
    pathRe: /(^|[\/\\])\.npmrc$/i,
    contentRe: /npm_[A-Za-z0-9]{20,}|_authToken\s*=/ },

  { category: 'slack_token',         sev: 'CRITICAL',
    contentRe: /xox[baprs]-[A-Za-z0-9-]{10,}/ },

  { category: 'google_api_key',      sev: 'CRITICAL',
    contentRe: /AIza[0-9A-Za-z\-_]{35}/ },

  { category: 'openai_key',          sev: 'CRITICAL',
    contentRe: /sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}/ },

  { category: 'stripe_key',          sev: 'CRITICAL',
    contentRe: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}/ },

  { category: 'generic_bearer',      sev: 'WARN',  weakOnly: true,
    contentRe: /bearer\s+[A-Za-z0-9._\-]{15,}/i },

  { category: 'crypto_wallet',       sev: 'CRITICAL',
    pathRe: /(id\.json|wallet\.json|keystore|MetaMask|Exodus|Electrum|Ledger Live|[\/\\]solana[\/\\]|\.config[\/\\]solana|Ethereum[\/\\]keystore)/i,
    // 64-hex secret key, BIP39 mnemonic field, or Solana keypair byte array
    contentRe: /"mnemonic"\s*:|\b[0-9a-fA-F]{64}\b|\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){31,}\s*\]/ },

  { category: 'seed_phrase',         sev: 'CRITICAL',
    // heuristic: 12–24 lowercase words in a row (BIP39 style)
    contentRe: /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/ },

  { category: 'browser_credentials', sev: 'CRITICAL',
    pathRe: /(Login Data|Web Data|Cookies|cookies\.sqlite|Local State|logins\.json|key4\.db|places\.sqlite)/i },

  { category: 'vscode_secrets',      sev: 'CRITICAL',
    pathRe: /(Code[\/\\]User[\/\\]|globalStorage|\.vscode[\/\\])/i,
    contentRe: /"?(?:sessionToken|access_token|refresh_token|serviceMachineId)"?\s*[:=]/i },

  { category: 'shell_history',       sev: 'WARN',
    pathRe: /\.(?:bash|zsh|sh)_history$|ConsoleHost_history\.txt$/i },

  { category: 'system_passwd',       sev: 'CRITICAL',
    pathRe: /^\/etc\/(?:passwd|shadow)$/ },

  // Tracked for taint only. Benign AI assistants upload source constantly, so a
  // weak line match here can never CONFIRM theft on its own.
  { category: 'source_code',         sev: 'WARN', quietRead: true, weakOnly: true,
    pathRe: /\.(?:js|ts|jsx|tsx|py|java|go|rs|c|cpp|cs|rb|php|sol)$/i },
];

/** Categories a *weak* (line-level) taint hit may not, by itself, confirm. */
const WEAK_ONLY = new Set(SECRET_RULES.filter((r) => r.weakOnly).map((r) => r.category));
/** Categories not worth reporting as a "sensitive read". */
const QUIET     = new Set(SECRET_RULES.filter((r) => r.quietRead).map((r) => r.category));

// ─────────────────────────────────────────────────────────────────────────────
//  Registries (per-process; one sandbox.js run = one extension)
// ─────────────────────────────────────────────────────────────────────────────

const SOURCES = [];  // { id, path, categories, sev, quiet }        — taint SOURCES
const TAINT   = [];  // { sourceId, category, token, strength }     — fingerprints
const STOLEN  = [];  // { destination, categories, confirmed, … }   — taint SINKS
const FLOWS   = [];  // { source, sink, category, strength }        — closed loops

const MAX_TAINT_TOKENS = 120;
const MIN_TOKEN_LEN    = 12;

/**
 * Values the HARNESS itself injects (fake auth tokens pre-seeded into
 * globalState so gated code paths execute). If the extension echoes one of
 * these back to its own server that is our data, not the victim's — never
 * count it as exfiltration.
 */
const HARNESS_VALUES = new Set();
function registerHarnessValue(v) { if (v && String(v).length >= 6) HARNESS_VALUES.add(String(v)); }
function isHarnessValue(s) { for (const v of HARNESS_VALUES) if (s === v || s.includes(v)) return true; return false; }

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

function toStr(x) {
  if (x == null) return '';
  if (Buffer.isBuffer(x)) return x.toString('utf8');
  return String(x);
}

function isPrintable(s) {
  if (!s) return false;
  let printable = 0;
  const n = Math.min(s.length, 2000);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 160) printable++;
  }
  return printable / n > 0.85;
}

/** Mask the middle of a secret so the report proves it without leaking it. */
function redact(s) {
  s = toStr(s).replace(/\s+/g, ' ').trim();
  if (s.length <= 12) return s.slice(0, 2) + '***' + s.slice(-2);
  return s.slice(0, 4) + '…[' + s.length + 'B]…' + s.slice(-4);
}

/** Produce decoded variants of an outbound payload so encoded exfil is caught. */
function decodeLayers(s) {
  s = toStr(s);
  const out = [s];
  const seen = new Set([s]);
  const push = (v) => { if (v && !seen.has(v)) { seen.add(v); out.push(v); } };

  // whole-string base64
  const t = s.trim();
  if (/^[A-Za-z0-9+/=\s]{16,}$/.test(t)) {
    try { const d = Buffer.from(t, 'base64').toString('utf8'); if (isPrintable(d)) push(d); } catch (e) {}
  }
  // embedded base64 blobs
  const blobs = s.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [];
  for (const b of blobs.slice(0, 16)) {
    try { const d = Buffer.from(b, 'base64').toString('utf8'); if (isPrintable(d) && d.length > 8) push(d); } catch (e) {}
  }
  // url-encoded
  try { const u = decodeURIComponent(s.replace(/\+/g, ' ')); push(u); } catch (e) {}
  // hex blob
  const hex = s.match(/\b[0-9a-fA-F]{32,}\b/);
  if (hex) { try { const d = Buffer.from(hex[0], 'hex').toString('utf8'); if (isPrintable(d)) push(d); } catch (e) {} }
  return out;
}

/** Classify a path against location-based rules. */
function classifyPath(p) {
  p = toStr(p);
  const hits = [];
  for (const r of SECRET_RULES) {
    if (r.pathRe && r.pathRe.test(p)) hits.push({ category: r.category, sev: r.sev });
  }
  return hits;
}

/** Classify content against value-based rules; returns [{category,sev,token,raw}]. */
function classifyContent(s) {
  s = toStr(s);
  if (!s) return [];
  const hits = [];
  for (const r of SECRET_RULES) {
    if (!r.contentRe) continue;
    const m = s.match(r.contentRe);
    if (m) hits.push({ category: r.category, sev: r.sev, token: redact(m[0]), raw: m[0] });
  }
  return hits;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 1 — TAINT SOURCE: record a file read, classify it, register taint
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string}        filePath
 * @param {Buffer|string} content   (may be undefined if only the path is known)
 * @param {Function}      logEvent  sandbox.js logger (module, fn, args, sev)
 * @returns {Object|null} { sourceId, categories, sev, quiet }
 */
function noteRead(filePath, content, logEvent) {
  const p   = toStr(filePath);
  const str = content != null ? toStr(content) : '';

  const cats = new Map(); // category -> sev
  for (const h of classifyPath(p)) cats.set(h.category, h.sev);
  const contentHits = classifyContent(str);
  for (const h of contentHits)     cats.set(h.category, h.sev);

  if (cats.size === 0) return null;

  const categories = [...cats.keys()];
  const worstSev   = [...cats.values()].includes('CRITICAL') ? 'CRITICAL' : 'WARN';
  const reportable = categories.filter((c) => !QUIET.has(c));

  // Register the SOURCE, then the fingerprints that let us recognise its bytes
  // if they ever leave the machine.
  const sourceId = `src${SOURCES.length + 1}`;
  SOURCES.push({ id: sourceId, path: p, categories, sev: worstSev, quiet: reportable.length === 0 });
  registerTaint(sourceId, categories[0], str, contentHits);

  // "Quiet" categories (e.g. source_code) are tracked for taint but NOT logged
  // as a sensitive read — benign tools read source files constantly.
  if (reportable.length === 0) return { sourceId, categories, sev: worstSev, quiet: true };

  if (typeof logEvent === 'function') {
    logEvent('data', 'sensitive_read', {
      source_id:   sourceId,
      path:        p,
      categories:  reportable.join(', '),
      evidence:    contentHits.map((h) => `${h.category}:${h.token}`).join(' | ') || '(path-based)',
      bytes:       str.length,
    }, worstSev);
  }
  return { sourceId, categories, sev: worstSev, quiet: false };
}

function registerTaint(sourceId, defaultCat, str, contentHits) {
  // 1) STRONG — exact secret tokens found by regex (unambiguous fingerprints)
  for (const h of contentHits) {
    if (h.raw && h.raw.length >= MIN_TOKEN_LEN) addTaint(sourceId, h.category, h.raw, 'strong');
  }
  // 2) WEAK — a few distinctive raw lines. Covers proprietary source / configs
  //    that have no famous regex but must still be traceable if exfiltrated.
  if (str && TAINT.length < MAX_TAINT_TOKENS) {
    const lines = str.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length >= 24);
    for (const l of lines.slice(0, 4)) addTaint(sourceId, defaultCat, l, 'weak');
  }
}

function addTaint(sourceId, category, token, strength) {
  if (!token || token.length < MIN_TOKEN_LEN) return;
  if (TAINT.length >= MAX_TAINT_TOKENS) return;
  if (isHarnessValue(token)) return;                     // our own injected value
  if (TAINT.some((t) => t.token === token)) return;
  TAINT.push({ sourceId, category, token, strength });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stage 2 — TAINT SINK: scan an outbound payload for tainted / secret data
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string}   destination  e.g. 'https://evil.tld/c2' or 'host:port'
 * @param {string}   payload      request body and/or URL
 * @param {Function} logEvent
 * @returns {Object|null} exfil record, or null when nothing matched
 */
function scanExfil(destination, payload, logEvent) {
  const dest   = toStr(destination) || 'unknown';
  const layers = decodeLayers(payload);

  // category -> { via, evidence, strength, sourceId, sourcePath }
  const found = new Map();
  const better = (a, b) => {                        // taint beats pattern; strong beats weak
    if (!a) return true;
    if (b.via === 'taint' && a.via !== 'taint') return true;
    if (b.via === a.via && b.strength === 'strong' && a.strength !== 'strong') return true;
    return false;
  };

  for (const layer of layers) {
    // (a) TAINT — bytes we watched being read are now leaving. Closed loop.
    for (const t of TAINT) {
      if (!layer.includes(t.token)) continue;
      const src = SOURCES.find((s) => s.id === t.sourceId);
      const rec = { via: 'taint', strength: t.strength, evidence: redact(t.token),
                    sourceId: t.sourceId, sourcePath: src ? src.path : '' };
      if (better(found.get(t.category), rec)) found.set(t.category, rec);
    }
    // (b) PATTERN — the payload merely LOOKS like it holds a secret. Suspicion
    //     only: we never observed the matching read, so the loop is open.
    for (const h of classifyContent(layer)) {
      if (h.raw && isHarnessValue(h.raw)) continue;     // harness-injected token
      const rec = { via: 'pattern', strength: 'strong', evidence: h.token };
      if (better(found.get(h.category), rec)) found.set(h.category, rec);
    }
  }

  if (found.size === 0) return null;

  // ── Closed-loop adjudication ──────────────────────────────────────────────
  // CONFIRMED requires an actual source→sink flow, and for the categories that
  // benign tooling legitimately transmits (source_code, generic_bearer) it
  // additionally requires a STRONG fingerprint rather than a line match.
  const confirmedCats = [], suspectedCats = [];
  for (const [cat, info] of found) {
    const isClosedLoop = info.via === 'taint';
    const strongEnough = info.strength === 'strong' || !WEAK_ONLY.has(cat);
    if (isClosedLoop && strongEnough) {
      confirmedCats.push(cat);
      FLOWS.push({ category: cat, strength: info.strength,
                   source: info.sourcePath || info.sourceId || '(unknown)', sink: dest });
    } else {
      suspectedCats.push(cat);
    }
  }

  const evidence = [...found.entries()].map(([cat, i]) =>
    `${cat} (${i.via}/${i.strength}${i.sourcePath ? ' from ' + i.sourcePath : ''}: ${i.evidence})`);

  const rec = {
    destination: dest,
    confirmed:   confirmedCats.length > 0,
    categories:  confirmedCats,
    suspected:   suspectedCats,
    evidence,
    via:         confirmedCats.length ? 'taint' : 'pattern',
  };
  STOLEN.push(rec);

  if (typeof logEvent === 'function') {
    if (rec.confirmed) {
      logEvent('data', 'exfiltration', {
        destination: dest,
        stole:       confirmedCats.join(', '),
        evidence:    evidence.join(' | ').slice(0, 400),
        method:      'closed-loop taint (read → send)',
      }, 'CRITICAL');
    } else {
      logEvent('data', 'exfiltration_suspected', {
        destination: dest,
        looks_like:  suspectedCats.join(', '),
        evidence:    evidence.join(' | ').slice(0, 400),
        method:      'pattern only — no observed read of this data',
      }, 'WARN');
    }
  }
  return rec;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Aggregation for the final report
// ─────────────────────────────────────────────────────────────────────────────

function getStolenSummary() {
  const confirmed = STOLEN.filter((s) => s.confirmed);
  const categories = [...new Set(confirmed.flatMap((s) => s.categories))];
  const suspected  = [...new Set(STOLEN.flatMap((s) => s.suspected || []))].filter((c) => !categories.includes(c));
  return {
    // STRICT signal — a proven source→sink loop. This is what drives MALICIOUS.
    data_stolen:        categories.length > 0,
    categories,
    destinations:       [...new Set(confirmed.map((s) => s.destination))],
    exfiltration_count: confirmed.length,
    flows:              FLOWS,
    // WEAK signal — pattern-only matches, reported but never decisive.
    suspected_categories:  suspected,
    suspected_count:       STOLEN.length - confirmed.length,
    suspected_destinations:[...new Set(STOLEN.filter((s) => !s.confirmed).map((s) => s.destination))],
    // Provenance
    events:             STOLEN,
    secrets_read:       [...new Set(SOURCES.filter((s) => !s.quiet).flatMap((s) => s.categories))],
    sources:            SOURCES.map((s) => ({ id: s.id, path: s.path, categories: s.categories })),
  };
}

function reset() {
  TAINT.length = 0; STOLEN.length = 0; SOURCES.length = 0; FLOWS.length = 0;
  HARNESS_VALUES.clear();
}

module.exports = {
  noteRead, scanExfil, getStolenSummary, reset, registerHarnessValue,
  classifyPath, classifyContent, decodeLayers, redact, SECRET_RULES,
};
