'use strict';
/**
 * decoy-profile.js — Synthetic Victim Environment (honeypot user profile)
 * =======================================================================
 * WHY
 * ---
 * The taint layer can only prove exfiltration when it observes BOTH ends of the
 * flow: a read of sensitive data, and that same data leaving. On a clean
 * analysis VM there is nothing to read — no `~/.ssh/id_rsa`, no `.aws/
 * credentials`, no browser login database, no wallet. An infostealer therefore
 * runs, finds nothing, sends an empty payload, and is scored BENIGN. That is a
 * structural false negative, and it was the dominant one.
 *
 * WHAT
 * ----
 * Before detonation we materialise a throw-away Windows-shaped user profile in
 * a temp directory and populate it with clearly-marked DECOY secrets:
 *
 *     C:\Users\dev\.ssh\id_rsa                 (OpenSSH private key)
 *     C:\Users\dev\.aws\credentials            (AKIA… + secret)
 *     C:\Users\dev\.npmrc                      (npm_… authToken)
 *     C:\Users\dev\.env                        (API keys)
 *     …\AppData\Roaming\npm\…, Local\Google\Chrome\User Data\Default\Login Data
 *     …\AppData\Roaming\Exodus\exodus.wallet\seed.seco
 *     …\AppData\Roaming\Code\User\settings.json
 *
 * `os.homedir()`, `os.userInfo()` and the Windows environment variables are
 * then pointed at it. A stealer walking `%USERPROFILE%` finds a full harvest,
 * reads it (→ TAINT SOURCE), and ships it (→ TAINT SINK) — closing the loop and
 * proving the theft with the exact bytes.
 *
 * SAFETY
 * ------
 *   • Every value is fabricated and structurally invalid. Nothing here
 *     authenticates against any real service.
 *   • The profile lives under os.tmpdir() and is removed after the run.
 *   • The REAL user profile is never exposed: because homedir() is redirected,
 *     a stealer that would otherwise have read the analyst's own keys reads the
 *     decoys instead. This module makes the sandbox safer, not less safe.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

/** Marker embedded in every decoy so a human reading a report cannot mistake it. */
const DECOY_TAG = 'VEXGUARD-DECOY';

/**
 * File map: relative path under the profile → contents.
 * Paths use forward slashes; they are normalised per-platform on write.
 */
function decoyFiles(userName) {
  return {
    '.ssh/id_rsa': [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      `b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt${DECOY_TAG}`,
      'cnNhAAAAAwEAAQAAAYEAsQ2tVexguardDecoyKeyMaterialNotAValidKey0000000000',
      'AAAAB3NzaC1yc2EAAAADAQABAAABgQCxDa1V6GBxrRBQiF1DecoyOnly00000000000',
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n'),

    '.ssh/known_hosts': `github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC${DECOY_TAG}decoyhostkey\n`,

    '.aws/credentials': [
      '[default]',
      'aws_access_key_id = AKIA4VEXGUARDDECOY00',
      `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/${DECOY_TAG}/bPxRfiCY`,
      'region = us-east-1',
    ].join('\n'),

    '.aws/config': '[default]\nregion = us-east-1\noutput = json\n',

    '.npmrc': `//registry.npmjs.org/:_authToken=npm_${DECOY_TAG}0000decoyTokenValue00\n`,

    '.env': [
      `OPENAI_API_KEY=sk-proj-${DECOY_TAG}00000000000000000decoy`,
      `GITHUB_TOKEN=ghp_${DECOY_TAG}0000000000000000decoy`,
      `STRIPE_SECRET_KEY=sk_live_${DECOY_TAG}00000000000decoy`,
      'DATABASE_PASSWORD=Pa55w0rd-vexguard-decoy',
    ].join('\n'),

    '.gitconfig': `[user]\n\tname = ${userName}\n\temail = ${userName}@example.invalid\n`,

    '.bash_history': 'ls -la\ncd project\ngit push origin main\nexport AWS_PROFILE=default\n',

    '.config/solana/id.json': `[${Array.from({ length: 64 }, (_, i) => (i * 3 + 7) % 256).join(',')}]`,

    'Documents/wallet.json': JSON.stringify({
      version: 3,
      id: 'decoy-wallet-0001',
      address: 'de0c0y0000000000000000000000000000000001',
      mnemonic: 'decoy vexguard sandbox witness trace mirror shadow lantern harbour beacon anchor cavern',
      crypto: { ciphertext: 'a'.repeat(64), cipher: 'aes-128-ctr' },
    }, null, 2),

    'AppData/Roaming/Code/User/settings.json': JSON.stringify({
      'editor.fontSize': 14,
      'telemetry.telemetryLevel': 'all',
      'sync.sessionToken': `${DECOY_TAG}-vscode-session-token-0001`,
      'github.access_token': `gho_${DECOY_TAG}0000000000vscode`,
    }, null, 2),

    // Browser credential stores are opened as binaries by stealers; the header
    // is enough for a SQLite sniff test to succeed and the marker is traceable.
    'AppData/Local/Google/Chrome/User Data/Default/Login Data':
      `SQLite format 3\u0000${DECOY_TAG}-chrome-login-data-decoy-blob`,
    'AppData/Local/Google/Chrome/User Data/Local State':
      JSON.stringify({ os_crypt: { encrypted_key: Buffer.from(`${DECOY_TAG}-chrome-master-key`).toString('base64') } }),
    'AppData/Roaming/Mozilla/Firefox/Profiles/decoy.default/logins.json':
      JSON.stringify({ logins: [{ hostname: 'https://example.invalid', encryptedPassword: `${DECOY_TAG}-ff-decoy` }] }),

    'AppData/Roaming/Exodus/exodus.wallet/seed.seco': `${DECOY_TAG}-exodus-seed-decoy-blob-0001`,
    'AppData/Roaming/Ethereum/keystore/UTC--decoy':
      JSON.stringify({ address: 'de0c0y0000000000000000000000000000000002', crypto: { ciphertext: 'b'.repeat(64) } }),

    'AppData/Roaming/discord/Local Storage/leveldb/000003.log': `${DECOY_TAG}-discord-token-decoy`,
    'AppData/Roaming/npm/etc/npmrc': `//registry.npmjs.org/:_authToken=npm_${DECOY_TAG}0000decoy2\n`,

    'Desktop/passwords.txt': `bank: ${DECOY_TAG}-p4ssw0rd\nemail: ${DECOY_TAG}-hunter2\n`,
    'Projects/app/.env': `SECRET_KEY=${DECOY_TAG}-project-secret-000\nAPI_KEY=AIza${DECOY_TAG}0000000000000000000000\n`,
  };
}

/**
 * Materialise the decoy profile.
 * @param {Object} [opts]
 * @param {string} [opts.userName='dev']
 * @returns {{root:string, home:string, userName:string, env:Object, files:string[], cleanup:Function}}
 */
function create(opts = {}) {
  const userName = opts.userName || 'dev';
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vexguard-decoy-'));
  // Shape the path like a Windows profile so string comparisons inside the
  // specimen (`\Users\`, `AppData`) still match.
  const home = path.join(root, 'Users', userName);

  const files = [];
  for (const [rel, content] of Object.entries(decoyFiles(userName))) {
    const abs = path.join(home, ...rel.split('/'));
    try {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content, 'utf8');
      files.push(abs);
    } catch (_) { /* a decoy that cannot be written is not fatal */ }
  }
  // Empty directories stealers commonly enumerate.
  for (const d of ['Downloads', 'Pictures', 'AppData/Local/Temp', 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup']) {
    try { fs.mkdirSync(path.join(home, ...d.split('/')), { recursive: true }); } catch (_) {}
  }

  const env = {
    USERPROFILE:   home,
    HOME:          home,
    HOMEDRIVE:     'C:',
    HOMEPATH:      `\\Users\\${userName}`,
    USERNAME:      userName,
    USER:          userName,
    LOGNAME:       userName,
    COMPUTERNAME:  'DESKTOP-VG7K21A',
    APPDATA:       path.join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA:  path.join(home, 'AppData', 'Local'),
    TEMP:          path.join(home, 'AppData', 'Local', 'Temp'),
    TMP:           path.join(home, 'AppData', 'Local', 'Temp'),
    ProgramData:   'C:\\ProgramData',
    ProgramFiles:  'C:\\Program Files',
    SystemRoot:    'C:\\WINDOWS',
    windir:        'C:\\WINDOWS',
    OS:            'Windows_NT',
    PROCESSOR_ARCHITECTURE: 'AMD64',
    NUMBER_OF_PROCESSORS:   '8',
    ComSpec:       'C:\\WINDOWS\\system32\\cmd.exe',
  };

  return {
    root, home, userName, env, files,
    cleanup() { try { fs.rmSync(root, { recursive: true, force: true }); } catch (_) {} },
  };
}

/** Every decoy secret value, so data-intel can pre-register them as taint. */
function decoyTokens(profile) {
  const out = [];
  for (const f of profile.files) {
    let s; try { s = fs.readFileSync(f, 'utf8'); } catch (_) { continue; }
    for (const line of s.split(/\r?\n/)) {
      const t = line.trim();
      if (t.length >= 16 && t.includes(DECOY_TAG)) out.push(t);
    }
  }
  return out;
}

module.exports = { create, decoyTokens, DECOY_TAG };
