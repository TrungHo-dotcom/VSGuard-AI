#!/usr/bin/env node
'use strict';
/**
 * time-machine.js — Virtual-Clock Time-Acceleration Engine (sandbox v2.2)
 * ======================================================================
 * A deterministic virtual clock + timer scheduler that lets the dynamic
 * sandbox "fast-forward" through time-based evasion, so delayed, scheduled,
 * or logic-bombed payloads DETONATE IMMEDIATELY during analysis instead of
 * out-waiting the observation window.
 *
 * WHY (ties directly to our FN problem):
 *   Malware routinely out-waits a sandbox —
 *     • `await sleep(600000)`                      (execution delay)
 *     • `setInterval(beacon, 3600000)`             (periodic C2 cron)
 *     • `if (Date.now() > TRIGGER) drop()`         (logic bomb)
 *   The v2 engine ended with a PASSIVE 30-second wall-clock wait. Anything
 *   scheduled beyond that window was never observed → the sample was scored
 *   BENIGN with 0 events (the dominant false-negative class in FAILURES.md).
 *   That passive wait is GONE as of v3 — this engine replaces it outright.
 *   The Time Machine decouples *observation* from *wall-clock
 *   time*: every time API the untrusted code can see is virtualized, and a
 *   scheduler jumps the virtual clock to each scheduled event, draining the
 *   whole timer queue in milliseconds of REAL time.
 *
 * SCOPE / SAFETY:
 *   install() returns a bundle of globals meant to be injected into the
 *   sandbox VM context ONLY. The analysis harness keeps the real clock. This
 *   separation is deliberate — harness waits stay real; only the specimen's
 *   perception of time is virtual. The engine executes nothing itself; it only
 *   re-times callbacks the specimen already scheduled.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

// ─────────────────────────────────────────────────────────────────────────────
//  Real primitives, captured at load time.
//  This module loads in the REAL Node context, so `setImmediate`/`Date` here
//  are genuine. We use them internally to yield to the real event loop; the
//  specimen never sees them.
// ─────────────────────────────────────────────────────────────────────────────
const _realSetImmediate = typeof setImmediate === 'function' ? setImmediate : (fn) => setTimeout(fn, 0);
const RealDate = Date;
const { spoofNativeToString } = require('./native-spoof');   // shared toString() cloaker

// Default fast-forward horizon: 1 YEAR + 1 DAY (366 days). This is the guard
// that stops a specimen from out-sleeping the sandbox: any sleep / delayed
// beacon / logic bomb scheduled within this window is detonated. Raised from
// 7 days so that long-dormant payloads (e.g. `sleep(30d)`, `sleep(300d)`, or a
// date bomb up to a year out) can no longer hide behind a >24h delay.
// One-shot long sleeps are cheap to skip to; runaway short intervals stay
// bounded by maxIntervalTicks + maxEvents, so widening the horizon is safe.
const DEFAULT_HORIZON_MS = 366 * 24 * 60 * 60 * 1000; // 31,622,400,000 ms

/**
 * Yield to the real event loop so microtasks + one macrotask phase settle.
 * Critical: when a fired virtual timer triggers a hooked network call, the
 * sandbox's http/fetch mocks resolve their response on the REAL loop (via the
 * real setImmediate). Draining here lets those Promise chains — and any NEW
 * virtual timers they schedule — surface before we pick the next event.
 * @returns {Promise<void>}
 */
function drainRealAsync() {
  return new Promise((resolve) => _realSetImmediate(resolve));
}

/**
 * Make a wrapper indistinguishable from a native function via toString(),
 * defeating the trivial `setTimeout.toString().includes('[native code]')`
 * hook-detection check.
 * @param {Function} fn
 * @param {string} name
 * @returns {Function}
 */
// Delegates to the shared cloaker (native-spoof.js) so time-machine's virtual
// timers/Date register into the SAME Function.prototype.toString guard the
// sandbox installs — defeating both fn.toString() and the
// Function.prototype.toString.call(fn) reflective bypass.
const makeNativeLike = spoofNativeToString;

/**
 * A Node-compatible timer handle. Node's setTimeout returns a `Timeout`
 * object (with ref/unref); browsers return a number. We return an object that
 * behaves like Node's but also coerces to its numeric id, so specimen code
 * using either convention keeps working.
 */
class VirtualTimerHandle {
  constructor(id) { this._id = id; this._refed = true; }
  ref()    { this._refed = true;  return this; }
  unref()  { this._refed = false; return this; }
  hasRef() { return this._refed; }
  refresh(){ return this; }
  close()  {}
  [Symbol.toPrimitive]() { return this._id; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  TimeMachine
// ─────────────────────────────────────────────────────────────────────────────
class TimeMachine {
  /**
   * @param {Object} [opts]
   * @param {number} [opts.epoch]            Virtual wall-clock start (ms since epoch). Default: real now.
   * @param {number} [opts.maxVirtualMs]     Horizon: max virtual time to simulate. Default 1 year 1 day (366 days).
   * @param {number} [opts.maxEvents]        Hard cap on timers fired per fast-forward. Default 200000.
   * @param {number} [opts.maxIntervalTicks] Max repeats simulated per setInterval. Default 1000.
   * @param {number} [opts.netLatencyMs]     Plausible RTT injected on network resolves. Default 35.
   * @param {boolean}[opts.autoAdvanceOnPoll]Break CPU busy-wait logic bombs. Default true.
   * @param {number} [opts.pollThreshold]    Consecutive Date reads before auto-advance. Default 4000.
   * @param {function(string, Object):void} [opts.onEvent] Telemetry sink (wire to logEvent).
   */
  constructor(opts = {}) {
    const now = opts.epoch != null ? opts.epoch : RealDate.now();
    this._wall   = now;   // virtual wall-clock ms  → drives Date.now() / new Date()
    this._mono   = 0;     // virtual monotonic ms   → drives performance.now() / hrtime()
    this._epoch0 = now;   // start, for horizon math

    this._timers = new Map();  // id -> record. (Linear scan for "earliest"; timer counts
                               //  in a single specimen are small. Swap for a binary heap
                               //  if you ever profile this as hot.)
    this._nextId = 1;
    this._firedTotal = 0;
    this._jumpCount  = 0;

    this.maxVirtualMs     = opts.maxVirtualMs     != null ? opts.maxVirtualMs     : DEFAULT_HORIZON_MS;
    this.maxEvents        = opts.maxEvents        != null ? opts.maxEvents        : 200000;
    this.maxIntervalTicks = opts.maxIntervalTicks != null ? opts.maxIntervalTicks : 1000;
    this.netLatencyMs     = opts.netLatencyMs     != null ? opts.netLatencyMs     : 35;
    this.autoAdvanceOnPoll= opts.autoAdvanceOnPoll!== false;
    this.pollThreshold    = opts.pollThreshold    != null ? opts.pollThreshold    : 4000;

    this._pollCount   = 0;
    this._pollStepCur = 50;   // busy-wait auto-advance step, grows exponentially to escape big gaps
    this.onEvent = typeof opts.onEvent === 'function' ? opts.onEvent : function () {};
  }

  // ── Clock advancement ──────────────────────────────────────────────────────
  /** Advance BOTH the wall clock and the monotonic clock together (they must
   *  never diverge — a specimen comparing Date.now() to performance.now() would
   *  otherwise detect the sandbox). @private */
  _advance(ms, reason) {
    if (!(ms > 0)) return;
    this._wall += ms;
    this._mono += ms;
    this._jumpCount++;
    this.onEvent('clock_jump', { advanced_ms: ms, reason: reason || 'scheduler', virtual_now: Math.floor(this._wall) });
  }

  /** Jump the virtual wall clock to an absolute time (for absolute-date logic
   *  bombs, e.g. run once "as if" it were next year). */
  setSystemTime(when) {
    const t = when instanceof RealDate ? when.getTime() : Number(when);
    if (Number.isNaN(t)) return;
    const delta = t - this._wall;
    this._wall = t;
    if (delta > 0) this._mono += delta;
    this.onEvent('clock_set', { virtual_now: Math.floor(t) });
  }

  /** Inject a plausible round-trip latency so a specimen that measures network
   *  timing (Date.now() before/after a request) sees a realistic non-zero delta
   *  instead of the tell-tale ~0 ms of a fully-mocked transport. Call from the
   *  sandbox's network hooks when a request resolves. */
  injectNetworkLatency(ms) { this._advance(ms != null ? ms : this.netLatencyMs, 'network_latency'); }

  // ── Time readouts handed to the specimen ───────────────────────────────────
  /** Backs Date.now() and new Date(). Also implements the busy-wait breaker:
   *  a tight `while (Date.now() < target) {}` loop never yields, so no timer can
   *  fire; we detect the hot polling and nudge (then exponentially grow) the
   *  clock forward to escape the gap. @private */
  _nowWall() {
    if (this.autoAdvanceOnPoll && ++this._pollCount >= this.pollThreshold) {
      this._pollCount = 0;
      this._pollStepCur = Math.min(this._pollStepCur * 2, 3600000); // cap 1 virtual hour / step
      this._advance(this._pollStepCur, 'busy_wait_poll');
    }
    return Math.floor(this._wall);
  }
  _nowMono() { return this._mono; }

  // ── Timer registration ─────────────────────────────────────────────────────
  /** @private */
  _schedule(type, cb, delay, args) {
    // A real scheduling call means the specimen is NOT in a busy-poll loop.
    this._pollCount = 0; this._pollStepCur = 50;

    // `setTimeout("code", n)` is a legacy eval vector — surface it, don't run it.
    if (typeof cb === 'string') {
      this.onEvent('timer_string_code', { kind: type, code_preview: cb.slice(0, 200) });
      return new VirtualTimerHandle(0);
    }
    if (typeof cb !== 'function') return new VirtualTimerHandle(0);

    let d = Number(delay); if (!(d >= 0)) d = 0;
    const id = this._nextId++;
    this._timers.set(id, {
      id, type, cb, args: args || [],
      delay: d, fireAt: this._wall + d, seq: id, cleared: false, ticks: 0,
    });
    this.onEvent('timer_scheduled', { kind: type, delay_ms: d, virtual_fire_at: Math.floor(this._wall + d), timer_id: id });
    return new VirtualTimerHandle(id);
  }

  /** @private */
  _clear(handle) {
    const id = (handle && typeof handle === 'object') ? handle._id : Number(handle);
    const rec = this._timers.get(id);
    if (rec) { rec.cleared = true; this._timers.delete(id); }
  }

  /** Earliest non-cleared timer (min fireAt, FIFO tie-break on insertion seq). @private */
  _earliest() {
    let best = null;
    for (const rec of this._timers.values()) {
      if (rec.cleared) continue;
      if (!best || rec.fireAt < best.fireAt || (rec.fireAt === best.fireAt && rec.seq < best.seq)) best = rec;
    }
    return best;
  }

  // ── The Fast-Forward Scheduler ─────────────────────────────────────────────
  /**
   * Advance virtual time event-by-event, firing each timer as its virtual
   * deadline arrives, until the queue is idle (or a guard trips). Because we
   * jump the clock straight to each deadline, a 10-minute sleep or a 24-hour
   * logic bomb resolves in microseconds of real time.
   *
   * @param {Object} [opts]
   * @param {boolean}[opts.untilIdle=true]  Drain until no timers remain.
   * @param {number} [opts.byMs]            Advance at most this much virtual time.
   * @param {number} [opts.untilVirtual]    Advance until this absolute virtual ms.
   * @param {number} [opts.maxEvents]       Override the fired-event cap for this run.
   * @returns {Promise<{fired:number, virtualNow:number, jumps:number}>}
   */
  async fastForward(opts = {}) {
    const horizonWall = opts.byMs != null ? this._wall + opts.byMs
                      : opts.untilVirtual != null ? opts.untilVirtual
                      : Infinity;
    const cap = opts.maxEvents != null ? opts.maxEvents : this.maxEvents;
    let fired = 0;
    this.onEvent('fast_forward_start', { from_virtual: Math.floor(this._wall) });

    while (fired < cap) {
      // Let awaits attached to the previously-fired timer settle (and possibly
      // schedule fresh timers) before we choose the next event.
      await drainRealAsync();

      const rec = this._earliest();
      if (!rec) {                                        // queue empty → specimen idle
        // Honour an explicit finite horizon even with nothing scheduled, so
        // `fastForward({ byMs })` / `{ untilVirtual }` still lets virtual time
        // pass (e.g. to age the clock before a second detonation pass).
        if (horizonWall !== Infinity && horizonWall > this._wall) this._advance(horizonWall - this._wall, 'horizon_idle');
        break;
      }
      if (rec.fireAt > horizonWall) { this._advance(horizonWall - this._wall, 'horizon'); break; }
      if (rec.fireAt - this._epoch0 > this.maxVirtualMs) {
        this.onEvent('horizon_reached', { virtual_horizon_ms: this.maxVirtualMs, timer_id: rec.id });
        break;
      }

      // Jump the clock to the deadline, then fire.
      this._advance(rec.fireAt - this._wall, rec.type);

      if (rec.type === 'interval') {
        rec.ticks++;
        rec.fireAt = this._wall + (rec.delay > 0 ? rec.delay : 1);  // re-arm; guard 0-delay spin
        if (rec.ticks > this.maxIntervalTicks) { rec.cleared = true; this._timers.delete(rec.id); }
      } else {
        rec.cleared = true; this._timers.delete(rec.id);
      }

      this.onEvent('timer_fired', { kind: rec.type, tick: rec.ticks || 1, delay_ms: rec.delay, virtual_now: Math.floor(this._wall), timer_id: rec.id });
      this._firedTotal++;
      try {
        rec.cb.apply(undefined, rec.args);
      } catch (e) {
        this.onEvent('timer_error', { message: e && e.message, timer_id: rec.id });
      }
      fired++;
    }

    await drainRealAsync();
    this.onEvent('fast_forward_complete', { fired, virtual_now: Math.floor(this._wall), jumps: this._jumpCount });
    return { fired, virtualNow: this._wall, jumps: this._jumpCount };
  }

  // ── Virtualized constructors / namespaces ──────────────────────────────────
  /** A `Date` subclass whose no-arg form reads the virtual clock. All other
   *  constructor forms and static parse/UTC are inherited unchanged. */
  makeDateClass() {
    const tm = this;
    class VirtualDate extends RealDate {
      constructor(...a) { if (a.length === 0) super(tm._nowWall()); else super(...a); }
      static now() { return tm._nowWall(); }
    }
    makeNativeLike(VirtualDate.now, 'now');   // Date.now.toString() must also read as native
    return makeNativeLike(VirtualDate, 'Date');
  }

  /** A `performance`-like object sharing the virtual monotonic clock. */
  makePerformance() {
    const tm = this;
    return { now: makeNativeLike(() => tm._nowMono(), 'now'), timeOrigin: this._epoch0 };
  }

  /** A `process.hrtime`-compatible function (array + .bigint) on virtual time. */
  makeHrtime() {
    const tm = this;
    const hr = function hrtime(prev) {
      const totalNs = Math.round(tm._nowMono() * 1e6);
      let s = Math.floor(totalNs / 1e9), ns = totalNs % 1e9;
      if (Array.isArray(prev)) { s -= prev[0]; ns -= prev[1]; if (ns < 0) { s--; ns += 1e9; } }
      return [s, ns];
    };
    hr.bigint = () => BigInt(Math.round(tm._nowMono() * 1e6));
    return hr;
  }

  /**
   * A virtualized `chrome.alarms` mock (browser-extension periodic scheduler).
   * VS Code extensions don't expose chrome.alarms, but the pattern is identical
   * for ANY platform alarm: map create()/periodInMinutes onto virtual timers so
   * the fast-forwarder detonates the alarm callbacks too. Expose this on the
   * sandbox `chrome` global when analyzing browser/webext specimens.
   */
  createAlarmsMock() {
    const tm = this;
    const listeners = [];
    const fire = (name) => { const info = { name, scheduledTime: tm._nowWall() }; for (const l of listeners) { try { l(info); } catch (_) {} } };
    return {
      create(name, info) {
        if (typeof name === 'object') { info = name; name = ''; }
        info = info || {};
        const delayMs  = info.when != null ? Math.max(0, info.when - tm._nowWall())
                       : info.delayInMinutes != null ? info.delayInMinutes * 60000 : 0;
        const periodMs = info.periodInMinutes != null ? info.periodInMinutes * 60000 : 0;
        tm.onEvent('alarm_created', { name, delay_ms: delayMs, period_ms: periodMs });
        tm._schedule('timeout', () => {
          fire(name);
          if (periodMs > 0) tm._schedule('interval', () => fire(name), periodMs, []);
        }, delayMs, []);
      },
      clear:    (name, cb) => { if (cb) cb(true); },
      clearAll: (cb)       => { if (cb) cb(true); },
      onAlarm:  { addListener: (l) => listeners.push(l), removeListener: () => {} },
    };
  }

  // ── Bundling / reporting ───────────────────────────────────────────────────
  /**
   * Return the bundle of virtualized globals to inject into the sandbox VM
   * context. Note we deliberately DO NOT virtualize setImmediate/queueMicrotask
   * — they carry no *delay*, so no time-evasion leverage, and keeping them real
   * lets Promise/IO settle naturally inside the specimen.
   * @returns {{setTimeout:Function,setInterval:Function,clearTimeout:Function,clearInterval:Function,Date:Function,performance:Object,hrtime:Function}}
   */
  install() {
    const tm = this;
    return {
      setTimeout:    makeNativeLike((cb, delay, ...args) => tm._schedule('timeout',  cb, delay, args), 'setTimeout'),
      setInterval:   makeNativeLike((cb, delay, ...args) => tm._schedule('interval', cb, delay, args), 'setInterval'),
      clearTimeout:  makeNativeLike((h) => tm._clear(h), 'clearTimeout'),
      clearInterval: makeNativeLike((h) => tm._clear(h), 'clearInterval'),
      Date:          tm.makeDateClass(),
      performance:   tm.makePerformance(),
      hrtime:        tm.makeHrtime(),
    };
  }

  /** Snapshot for the analysis report (attach under report.time_machine). */
  getStats() {
    return {
      virtual_start_iso:  new RealDate(this._epoch0).toISOString(),
      virtual_now_iso:    new RealDate(this._wall).toISOString(),
      virtual_elapsed_ms: Math.floor(this._wall - this._epoch0),
      timers_fired:       this._firedTotal,
      clock_jumps:        this._jumpCount,
      pending_timers:     [...this._timers.values()].filter((r) => !r.cleared).length,
    };
  }
}

module.exports = { TimeMachine, VirtualTimerHandle, makeNativeLike };
