# VEXGuard — Root-Cause Analysis of Residual FP / FN

Generated: 2026-08-13T13:34:32.879Z

False positives: **11** · False negatives: **83** · Analysis errors: **0**

Every misclassification below is attributed to a named cause with the specific
change that would address it. Causes prefixed `OUT_OF_SCOPE_` are dataset-labelling
artefacts rather than engine defects — see METRICS.md for why VsMex is stratified.

---

## FALSE POSITIVES — benign flagged as MALICIOUS

### RULE_OVERMATCH  (7)

**Fix:** Flagged by: static:+45 obfuscated dependency in node_modules invoking process execution (supply-chain trojan). Review the contributing rule's specificity.

- ⚠️ **HookyQR.beautify** v1.5.0 — score 45, decided by static
  - reasons: static:+45 obfuscated dependency in node_modules invoking process execution (supply-chain trojan)
- ⚠️ **ms-vscode-remote.remote-ssh** v0.125.2026080721 — score 125, decided by static
  - reasons: static:+50 drops an executable into a temp directory and launches it (dropper) ; static:+40 malicious preinstall lifecycle script in package.json ; static:+25 programmatically installs a VSIX (marketplace bypass) ; static:+12 AST: child_process invoked with a non-static/tainted command argument
- ⚠️ **ms-vscode.PowerShell** v2026.1.2 — score 95, decided by static
  - reasons: static:+50 tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel) ; static:+45 downloads an executable/script binary from a non-distribution host
- ⚠️ **njpwerner.autodocstring** v0.6.1 — score 62, decided by static
  - reasons: static:+50 tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel) ; static:+12 AST: child_process invoked with a non-static/tainted command argument
- ⚠️ **redhat.java** v1.56.2026080608 — score 57, decided by static
  - reasons: static:+45 downloads an executable/script binary from a non-distribution host ; static:+12 AST: child_process invoked with a non-static/tainted command argument
- ⚠️ **WakaTime.vscode-wakatime** v30.2.1 — score 62, decided by static
  - reasons: static:+50 tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel) ; static:+12 AST: child_process invoked with a non-static/tainted command argument
- ⚠️ **Zignd.html-css-class-completion** v1.20.0 — score 62, decided by static
  - reasons: static:+50 tunnelled C2 endpoint (ngrok / cloudflare / tcp tunnel) ; static:+12 AST: child_process invoked with a non-static/tainted command argument

### REVERSE_SHELL_OVERMATCH  (2)

**Fix:** Socket + child_process co-occurrence matched a language-server/debug-adapter client. Require the structural wiring (a socket data handler that executes its input) rather than co-occurrence.

- ⚠️ **Dart-Code.dart-code** v3.141.20260803 — score 67, decided by static
  - reasons: static:+55 AST: reverse shell — a socket data handler executes received input as a process ; static:+12 AST: child_process invoked with a non-static/tainted command argument
- ⚠️ **ms-vscode-remote.remote-containers** v0.467.0 — score 195, decided by static
  - reasons: static:+55 AST: reverse shell — a socket data handler executes received input as a process ; static:+55 reverse shell pattern (outbound TCP socket spawning a shell interpreter in the same file) ; static:+50 drops an executable into a temp directory and launches it (dropper) ; static:+25 programmatic

### CRADLE_OVERMATCH  (2)

**Fix:** The download-and-execute rule matched a command string that is not a cradle. Tighten isCradleLiteral(): the LOLBIN, the remote payload and the execution verb must all be present in one command.

- ⚠️ **GitHub.copilot-chat** v0.48.1 — score 79, decided by static
  - reasons: static:+55 download-and-execute cradle (one command string fetches a remote payload and runs it) ; static:+12 AST: child_process invoked with a non-static/tainted command argument ; static:+12 AST: dynamic eval()/new Function() on a constructed (non-static) value
- ⚠️ **ms-python.vscode-python-envs** v1.37.2026073101 — score 135, decided by static
  - reasons: static:+55 download-and-execute cradle (one command string fetches a remote payload and runs it) ; static:+45 downloads an executable/script binary from a non-distribution host ; static:+25 programmatically installs a VSIX (marketplace bypass) ; static:+25 harvests a stable host fingerprint (machine

---

## FALSE NEGATIVES — malicious not flagged as MALICIOUS

### DORMANT_NO_OBSERVABLE_PAYLOAD  (60)

**Cause:** The extension executed nothing observable and carries no static IOC — a clean re-publish, a first-stage placeholder awaiting a server-side trigger, or a payload gated behind a condition the simulator does not reproduce (specific workspace contents, a live C2 response, a real user credential).

- ❌ **498-00.httpformat** v1.1.2 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **ab-498.pythonformat** v1.0.50 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **ab-498.httpformat** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **BlockchainIndustries.bitcoin-toolkit** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **BenjaminFriedl.lexica-img-fix** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **BlockchainIndustries.hardhat-toolkit** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **BlockchainIndustries.solana-toolkit** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **Bobronium.darcula-from-pycharm** v0.9.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **CodamaSoftware.ai-docs-and-comments** v0.0.8 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **codevsce.codelddb-vscode** v1.11.9 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **csvmech.csvrainbow** v3.3.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=1 static=BENIGN)_
- ❌ **bphpburnsus.iconesvscode** v12.15.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **embeddteam.embedded-build-analyzer** v1.1.3 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **EchelonStudios.blockchain-language-support** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **embeddteam.embeddedprojectmanager** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **embeddteam.embeddedprojectmanager** v0.0.2 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **garytyler.darcula-pycharm** v1.0.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **example-api-extension-0.0.1** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **flutcode.flutter-extension** v3.122.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **icon-theme-materiall** v5.29.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **IconKief.icon-theme-material** v5.29.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **krabt.krabt-extension-pack** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **kraftwer1.darcula-extra** v0.6.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **labfile.labfile** v0.0.5 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **Local-Web-Server** v1.0.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **krabt.krabt-proto** v0.5.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **OktayAydoan.smarty-formatter** v2.1.2 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **nrwl.angular-console** v18.95.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **ovixcodes.basedpyright-vscode** v1.34.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **Puglight.inspiredaily** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **PriyanshuMallick.clipboard-history-manager** v0.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **rafaelrenanpacheco.darcula-theme** v1.18.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.glm-copilot** v1.0.12 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.glm-copilot** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.glm-copilot** v1.0.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.glm-copilot** v1.0.4 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.glm-copilot** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-coding-copilot** v1.0.12 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-coding-copilot** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-copilot** v1.0.12 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-copilot** v1.0.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-copilot** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.mimo-copilot** v1.0.12 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-copilot** v1.0.4 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.kimi-copilot** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.mimo-copilot** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.mimo-copilot** v1.0.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.mimo-copilot** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.minimax-copilot** v1.0.1 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.mimo-copilot** v1.0.4 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.minimax-copilot** v1.0.12 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.minimax-copilot** v1.0.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **saekiraku_rainbow-fart_1.4.0** v1.4.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.minimax-copilot** v1.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **sanchuan.minimax-copilot** v1.0.4 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **siffat-ahmed.ai-autocomplete-siffat-ahmed** v0.1.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **serialt.sugar-proto** v0.5.7 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **StefanYosif.axion-ai** v1.0.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **Vsceue.volar-vscode** v3.1.6 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **wlnxingdev.free-senltig** v17.6.0 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_

### BELOW_MALICIOUS_THRESHOLD  (13)

**Cause:** Evidence was found but scored 35, below the MALICIOUS bar. It IS caught by the TRIAGE rule. Mitigation: raise the weight of the contributing indicators, or treat SUSPICIOUS as positive.

- ❌ **ab-498.cppplayground** v1.0.42 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **AutoMind.automindX** v1.0.1 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **embeddteam.embedded-cortex-debug** v1.14.0 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **EthCompiler.among-eth** v1.0.2 → SUSPICIOUS _(tier code, "DataDog malicious"; events=4 net=1 exec=0 timers=0 static=BENIGN)_
- ❌ **embeddteam.embedded-cortex-debug** v1.14.1 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **extension-attack-suite-0.0.1** v0.0.1 → SUSPICIOUS _(tier code, "DataDog malicious"; events=33 net=0 exec=20 timers=0 static=BENIGN)_
- ❌ **hajoo.poisoned-extension** v1.0.3 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **JohnGaffney.blankebesxstnion** v1.0.2 → SUSPICIOUS _(tier code, "DataDog malicious"; events=4 net=1 exec=0 timers=0 static=BENIGN)_
- ❌ **juanblan281.solid281** v0.0.189 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **luater.luatide** v2.2.13 → SUSPICIOUS _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **OPENEDAI.OPENEDAI** v0.4.51 → SUSPICIOUS _(tier code, "DataDog malicious"; events=1 net=0 exec=0 timers=0 static=SUSPICIOUS)_
- ❌ **peakchen90_open-html-in-browser_2.1.3** v2.1.3 → SUSPICIOUS _(tier code, "DataDog malicious"; events=13 net=0 exec=13 timers=0 static=BENIGN)_
- ❌ **SmartContractAI.solaibot** v1.4.2 → SUSPICIOUS _(tier code, "DataDog malicious"; events=4 net=1 exec=0 timers=0 static=BENIGN)_

### RAN_BUT_UNRECOGNISED  (7)

**Cause:** Runtime activity occurred but matched no malicious signature. Mitigation: add a rule for the observed behaviour, or route the evidence digest to an LLM verdict engine.

- ❌ **ab-498.cppformat** v1.0.8 → BENIGN _(tier code, "DataDog malicious"; events=1 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **eamodas.shiny-vscode** v1.3.2 → BENIGN _(tier code, "DataDog malicious"; events=2 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **malicious-api-extension-0.0.1** v0.0.1 → BENIGN _(tier code, "DataDog malicious"; events=2 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **priskinski.theme-allhallowseve-remake** v1.0.0 → BENIGN _(tier code, "DataDog malicious"; events=1 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **SFRA-FAKA.sfra-toolkit** v0.0.2 → BENIGN _(tier code, "DataDog malicious"; events=2 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **WhenSunset.chatgpt-china** v9.5.3 → BENIGN _(tier code, "DataDog malicious"; events=1 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **zhukunpeng.chat-moss** v8.0.0 → BENIGN _(tier code, "DataDog malicious"; events=5 net=0 exec=0 timers=0 static=BENIGN)_

### TIMEOUT  (2)

**Cause:** Detonation was killed by the per-sample timeout before behaviour surfaced. Mitigation: raise --timeout, or lower SANDBOX_MAX_CMDS for command-heavy samples.

- ❌ **JosephDembele95.email-grabber** v1.0.6 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_
- ❌ **Puglight.sysmotivate** v0.0.3 → BENIGN _(tier code, "DataDog malicious"; events=0 net=0 exec=0 timers=0 static=BENIGN)_

### UNRECOGNISED_BEHAVIOUR  (1)

**Cause:** Observed 2 event(s) that no rule scored as malicious. Review the sample's execution-log.json.

- ❌ **amazonwebservices.amazon-q-vscode** v1.84.0 → BENIGN _(tier code, "DataDog malicious"; events=2 net=0 exec=0 timers=1 static=BENIGN)_
