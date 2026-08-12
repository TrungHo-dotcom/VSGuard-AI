'use strict';
/**
 * native-spoof.js — anti-analysis toString() cloaking for API hooks
 * =================================================================
 * Malware fingerprints our sandbox by reading the source of the functions we
 * hook, e.g.:
 *     if (child_process.exec.toString().includes('[native code]')) …trust…
 *     else …we are being analysed → stay dormant…
 * or the harder bypass that ignores an own-property override:
 *     Function.prototype.toString.call(setTimeout)   // real source leaks through
 *
 * This module makes a hooked function indistinguishable from a genuine native
 * built-in on BOTH paths:
 *   1. spoofNativeToString(fn, name) — sets an own toString() returning
 *      `function <name>() { [native code] }`, and registers fn in a WeakMap.
 *   2. installToStringGuard() — patches Function.prototype.toString once so
 *      `Function.prototype.toString.call(hook)` also returns the spoofed string
 *      (it consults the WeakMap; everything unregistered delegates to the real
 *      toString). Returns a restore() — call it when the run ends.
 *
 * Shared by sandbox.js and time-machine.js so every hook in either realm
 * registers into the same guard.
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

// fn -> the exact "native" string it should report. WeakMap so spoofed hooks are
// GC-able and the registry never leaks across runs.
const NATIVE = new WeakMap();

let _origFnToString = null;   // saved Function.prototype.toString while the guard is installed

/**
 * Make `targetFunction` report itself as a native built-in via toString().
 * Idempotent and safe on any function.
 * @param {Function} targetFunction  the hook to cloak
 * @param {string}   functionName    the built-in name to impersonate (e.g. 'exec', 'setTimeout')
 * @returns {Function} the same function, for chaining
 */
function spoofNativeToString(targetFunction, functionName) {
  if (typeof targetFunction !== 'function') return targetFunction;
  const name = functionName || targetFunction.name || 'anonymous';
  const nativeStr = `function ${name}() { [native code] }`;

  NATIVE.set(targetFunction, nativeStr);   // covers Function.prototype.toString.call(fn)

  try {
    // Presentation: correct .name and a non-enumerable own toString() that lies.
    Object.defineProperty(targetFunction, 'name', { value: name, configurable: true });
    Object.defineProperty(targetFunction, 'toString', {
      value: function toString() { return nativeStr; },
      writable: true, configurable: true, enumerable: false,
    });
    // Nested check: `fn.toString.toString()` must itself look native.
    NATIVE.set(targetFunction.toString, 'function toString() { [native code] }');
  } catch (_) { /* frozen/exotic fn — WeakMap entry still covers the .call() path */ }

  return targetFunction;
}

/**
 * Patch Function.prototype.toString so the reflective bypass
 * `Function.prototype.toString.call(hook)` also returns the spoofed native
 * string. Non-registered functions are unaffected (delegates to the original).
 * Install once at run start; call the returned restore() at run end.
 * @returns {function():void} restore
 */
function installToStringGuard() {
  if (_origFnToString) return function noop() {};   // already installed
  const orig = Function.prototype.toString;
  _origFnToString = orig;

  const patched = function toString() {
    const spoof = NATIVE.get(this);
    return spoof !== undefined ? spoof : orig.call(this);
  };
  // The guard itself must not give itself away.
  NATIVE.set(patched, 'function toString() { [native code] }');

  try {
    Object.defineProperty(Function.prototype, 'toString', {
      value: patched, writable: true, configurable: true,
    });
  } catch (_) { _origFnToString = null; return function noop() {}; }

  return function restoreToStringGuard() {
    try {
      Object.defineProperty(Function.prototype, 'toString', {
        value: orig, writable: true, configurable: true,
      });
    } catch (_) { /* best-effort */ }
    _origFnToString = null;
  };
}

/**
 * Convenience: cloak every own function property of a hooked module object
 * (e.g. the object returned by createChildProcessHook()).
 * @param {Object} mod
 * @returns {Object} mod
 */
function spoofModuleFunctions(mod) {
  if (!mod || typeof mod !== 'object') return mod;
  for (const key of Object.keys(mod)) {
    if (typeof mod[key] === 'function') spoofNativeToString(mod[key], key);
  }
  return mod;
}

module.exports = { spoofNativeToString, installToStringGuard, spoofModuleFunctions };
