/**
 * mock-vscode.js
 * ==============
 * Comprehensive stub of the `vscode` module for the Dynamic Analysis Sandbox.
 *
 * VS Code extensions call `require('vscode')` to access the editor API.
 * Outside a real VS Code host this module does not exist, so the extension
 * crashes immediately. This stub provides enough surface area that most
 * extensions reach their `activate()` function without throwing.
 *
 * Design principles:
 *   – Every API call returns a sensible default or a no-op Disposable.
 *   – All event listeners are accepted and stored but never fired unless
 *     the sandbox explicitly fires them.
 *   – The internal helper `_createExtensionContext()` is exported so
 *     sandbox.js can build the fake ExtensionContext passed to activate().
 *
 * Project: CSN 304 — "Towards Identifying Malicious VS Code Extensions"
 */

'use strict';

const { EventEmitter } = require('events');
const path = require('path');
const os   = require('os');


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 1 — Core primitives  (Uri, Position, Range, Disposable, etc.)
// ─────────────────────────────────────────────────────────────────────────────

/** Resource wrapper – extensions register disposables in context.subscriptions */
class Disposable {
  constructor(fn) { this._fn = fn || (() => {}); }
  dispose() { try { this._fn(); } catch (_) {} }
  static from(...disposables) {
    return new Disposable(() => disposables.forEach(d => d && d.dispose && d.dispose()));
  }
}

/**
 * VS Code EventEmitter wrapper.
 * `emitter.event` is the subscription function returned to callers.
 * `emitter.fire(data)` dispatches to all registered listeners.
 *
 * `listenerCount` exists so the sandbox can tell whether anybody is actually
 * subscribed before it does expensive work. Event fuzzing rewrites the mock
 * document and re-fires the document lifecycle for every candidate keyword;
 * against an extension that never subscribed to a document event that is pure
 * waste, and measured against the VsMex corpus it pushed 13 slow samples past
 * the per-sample timeout — costing 3 detections to reach payloads that were not
 * there. Firing into the void is not free.
 */
class VSEventEmitter {
  constructor() {
    this._emitter = new EventEmitter();
    this._emitter.setMaxListeners(200);
    this.event = (listener) => {
      this._emitter.on('event', listener);
      return new Disposable(() => this._emitter.removeListener('event', listener));
    };
  }
  fire(data)  { this._emitter.emit('event', data); }
  get listenerCount() { return this._emitter.listenerCount('event'); }
  dispose()   {}
}

class Uri {
  constructor(scheme, authority, uriPath, query, fragment) {
    this.scheme    = scheme    || 'file';
    this.authority = authority || '';
    this.path      = uriPath   || '';
    this.query     = query     || '';
    this.fragment  = fragment  || '';
    this.fsPath    = this.path;
  }
  static file(p) { return new Uri('file', '', p || '', '', ''); }
  static parse(str) {
    try {
      const u = new URL(str);
      return new Uri(u.protocol.replace(':', ''), u.hostname, u.pathname, u.search.slice(1), u.hash.slice(1));
    } catch { return new Uri('file', '', str || '', '', ''); }
  }
  static joinPath(base, ...parts) {
    return new Uri(base.scheme, base.authority, path.posix.join(base.path, ...parts), '', '');
  }
  with(change) {
    return new Uri(
      change.scheme    !== undefined ? change.scheme    : this.scheme,
      change.authority !== undefined ? change.authority : this.authority,
      change.path      !== undefined ? change.path      : this.path,
      change.query     !== undefined ? change.query     : this.query,
      change.fragment  !== undefined ? change.fragment  : this.fragment,
    );
  }
  toString() { return `${this.scheme}://${this.authority}${this.path}`; }
  toJSON()   { return this.toString(); }
}

class Position {
  constructor(line, character) { this.line = line || 0; this.character = character || 0; }
  translate(lineDelta, charDelta) { return new Position(this.line + (lineDelta || 0), this.character + (charDelta || 0)); }
  with(line, char)  { return new Position(line !== undefined ? line : this.line, char !== undefined ? char : this.character); }
  isEqual(o)        { return this.line === o.line && this.character === o.character; }
  isBefore(o)       { return this.line < o.line || (this.line === o.line && this.character < o.character); }
  isAfter(o)        { return !this.isBefore(o) && !this.isEqual(o); }
  isBeforeOrEqual(o){ return !this.isAfter(o); }
  isAfterOrEqual(o) { return !this.isBefore(o); }
  compareTo(o)      { return this.isBefore(o) ? -1 : this.isEqual(o) ? 0 : 1; }
}

class Range {
  constructor(startOrLine, endOrChar, endLine, endChar) {
    if (startOrLine instanceof Position) {
      this.start = startOrLine;
      this.end   = endOrChar instanceof Position ? endOrChar : new Position(0, 0);
    } else {
      this.start = new Position(startOrLine || 0, endOrChar  || 0);
      this.end   = new Position(endLine     || 0, endChar    || 0);
    }
  }
  get isEmpty()      { return this.start.isEqual(this.end); }
  get isSingleLine() { return this.start.line === this.end.line; }
  contains()         { return true; }
  intersection(r)    { return this; }
  union(r)           { return this; }
  isEqual(o)         { return this.start.isEqual(o.start) && this.end.isEqual(o.end); }
}

class Selection extends Range {
  constructor(anchorLine, anchorChar, activeLine, activeChar) {
    if (anchorLine instanceof Position) {
      super(anchorLine, anchorChar);
      this.anchor = anchorLine;
      this.active = anchorChar instanceof Position ? anchorChar : new Position(0, 0);
    } else {
      super(anchorLine || 0, anchorChar || 0, activeLine || 0, activeChar || 0);
      this.anchor = new Position(anchorLine || 0, anchorChar || 0);
      this.active = new Position(activeLine || 0, activeChar || 0);
    }
  }
  get isReversed() { return this.active.isBefore(this.anchor); }
}

// ─── Auxiliary value types ────────────────────────────────────────────────────

class ThemeIcon   { constructor(id, color) { this.id = id; this.color = color; } static get File()   { return new ThemeIcon('file');   } static get Folder() { return new ThemeIcon('folder'); } }
class ThemeColor  { constructor(id)        { this.id = id; } }
class MarkdownString {
  constructor(v, supportThemeIcons) { this.value = v || ''; this.isTrusted = false; this.supportThemeIcons = supportThemeIcons || false; this.supportHtml = false; }
  appendText(v)           { this.value += v; return this; }
  appendMarkdown(v)       { this.value += v; return this; }
  appendCodeblock(code, lang) { this.value += `\`\`\`${lang||''}\n${code}\n\`\`\``; return this; }
}
class Diagnostic  { constructor(range, message, severity) { this.range = range; this.message = message; this.severity = severity !== undefined ? severity : 0; this.source = undefined; this.code = undefined; this.relatedInformation = undefined; this.tags = undefined; } }
class Location    { constructor(uri, rangeOrPos) { this.uri = uri; this.range = rangeOrPos instanceof Position ? new Range(rangeOrPos, rangeOrPos) : rangeOrPos; } }
class WorkspaceEdit {
  constructor() { this._edits = []; }
  replace(uri, range, text)  { this._edits.push({ type: 'replace', uri, range, newText: text }); }
  insert(uri, pos, text)     { this._edits.push({ type: 'insert',  uri, position: pos, newText: text }); }
  delete(uri, range)         { this._edits.push({ type: 'delete',  uri, range }); }
  has(uri)    { return this._edits.some(e => String(e.uri) === String(uri)); }
  set(uri, edits) { edits.forEach(e => this._edits.push({ ...e, uri })); }
  get(uri)    { return this._edits.filter(e => String(e.uri) === String(uri)); }
  entries()   { return []; }
  get size()  { return this._edits.length; }
}
class RelativePattern { constructor(base, pattern) { this.base = base; this.pattern = pattern; } }
class FileSystemError extends Error {
  constructor(message) { super(message); this.name = 'FileSystemError'; }
  static FileNotFound(uri)      { return new FileSystemError(`FileNotFound: ${uri}`); }
  static FileExists(uri)        { return new FileSystemError(`FileExists: ${uri}`); }
  static NoPermissions(uri)     { return new FileSystemError(`NoPermissions: ${uri}`); }
  static Unavailable(uri)       { return new FileSystemError(`Unavailable: ${uri}`); }
  static FileNotADirectory(uri) { return new FileSystemError(`FileNotADirectory: ${uri}`); }
  static FileIsADirectory(uri)  { return new FileSystemError(`FileIsADirectory: ${uri}`); }
}
class CompletionItem  { constructor(label, kind) { this.label = label; this.kind = kind; } }
class CompletionList  { constructor(items, isIncomplete) { this.items = items || []; this.isIncomplete = isIncomplete || false; } }
class Hover           { constructor(contents, range) { this.contents = Array.isArray(contents) ? contents : [contents]; this.range = range; } }
class CodeLens        { constructor(range, command) { this.range = range; this.command = command; this.isResolved = !!command; } }
class TreeItem        { constructor(labelOrUri, cs) { if (typeof labelOrUri === 'string') this.label = labelOrUri; else this.resourceUri = labelOrUri; this.collapsibleState = cs || 0; } }
class SemanticTokensLegend { constructor(types, mods) { this.tokenTypes = types || []; this.tokenModifiers = mods || []; } }
class SemanticTokensBuilder { constructor() { this._data = []; } push(l,c,len,t,m) { this._data.push(l,c,len,t,m||0); } build(id) { return { data: new Uint32Array(this._data), resultId: id }; } }
class InlayHint       { constructor(position, label, kind) { this.position = position; this.label = label; this.kind = kind; } }
class FoldingRange    { constructor(start, end, kind) { this.start = start; this.end = end; this.kind = kind; } }
class SelectionRange  { constructor(range, parent) { this.range = range; this.parent = parent; } }


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 2 — Factory helpers
// ─────────────────────────────────────────────────────────────────────────────

const noop        = () => {};
const noopPromise = () => Promise.resolve(undefined);
const noopDisp    = () => new Disposable();

function mkDoc(uriOrPath, content) {
  const docUri = uriOrPath instanceof Uri ? uriOrPath : Uri.file(String(uriOrPath || '/mock/file.js'));
  const text   = content || '';
  return {
    uri: docUri, fileName: docUri.path, languageId: 'plaintext', version: 1,
    isDirty: false, isUntitled: false, isClosed: false, lineCount: 1, eol: 1, encoding: 'utf8',
    getText:              () => text,
    lineAt:               () => ({ lineNumber:0, text, range: new Range(0,0,0,text.length), firstNonWhitespaceCharacterIndex:0, isEmptyOrWhitespace: !text.trim() }),
    offsetAt:             () => 0,
    positionAt:           (off) => new Position(0, off),
    validateRange:        (r)   => r,
    validatePosition:     (p)   => p,
    getWordRangeAtPosition: ()  => undefined,
    save: () => Promise.resolve(true),
  };
}

function mkEditor() {
  return {
    document: mkDoc('/mock/active.js'),
    selection: new Selection(new Position(0,0), new Position(0,0)),
    selections: [new Selection(new Position(0,0), new Position(0,0))],
    visibleRanges: [new Range(new Position(0,0), new Position(100,0))],
    options: { tabSize: 4, insertSpaces: true, cursorStyle: 1, lineNumbers: 1 },
    viewColumn: 1,
    edit:           (cb) => { cb({ replace: noop, insert: noop, delete: noop, setEndOfLine: noop }); return Promise.resolve(true); },
    insertSnippet:  () => Promise.resolve(true),
    setDecorations: noop, revealRange: noop, show: noop, hide: noop,
  };
}

function mkOutputChannel(name) {
  return {
    name,
    append:     (t) => process.stdout.write(`  [vscode.out:${name}] ${t}`),
    appendLine: (t) => process.stdout.write(`  [vscode.out:${name}] ${t}\n`),
    replace: noop, clear: noop, show: noop, hide: noop, dispose: noop,
  };
}

function mkTerminal(nameOrOpts) {
  const name = typeof nameOrOpts === 'string' ? nameOrOpts : (nameOrOpts && nameOrOpts.name) || 'Terminal';
  return { name, processId: Promise.resolve(99999), creationOptions: {}, exitStatus: undefined, state: { isInteractedWith: false }, sendText: noop, show: noop, hide: noop, dispose: noop };
}

function mkStatusBarItem() {
  return { id: 'mock', alignment: 1, priority: 0, text: '', tooltip: '', color: undefined, backgroundColor: undefined, command: undefined, name: '', accessibilityInformation: undefined, show: noop, hide: noop, dispose: noop };
}

function mkWebviewPanel(viewType, title) {
  const onDispose = new VSEventEmitter();
  const onState   = new VSEventEmitter();
  return {
    viewType, title, options: {},
    webview: { html: '', options: {}, cspSource: 'mock', onDidReceiveMessage: new VSEventEmitter().event, postMessage: () => Promise.resolve(true), asWebviewUri: (u) => u },
    viewColumn: 1, active: true, visible: true,
    onDidDispose: onDispose.event, onDidChangeViewState: onState.event,
    reveal: noop, dispose: noop,
  };
}

function mkDiagCollection(name) {
  const _map = new Map();
  return {
    name,
    set: (u,d) => _map.set(String(u),d), delete: (u) => _map.delete(String(u)), clear: () => _map.clear(),
    forEach: (cb) => _map.forEach(cb), get: (u) => _map.get(String(u)) || [], has: (u) => _map.has(String(u)),
    dispose: () => _map.clear(), [Symbol.iterator]: function*() { yield* _map.entries(); },
  };
}

function mkTreeView(viewId) {
  const ev = new VSEventEmitter();
  return { onDidExpandElement: ev.event, onDidCollapseElement: ev.event, onDidChangeSelection: ev.event, onDidChangeVisibility: ev.event, selection: [], visible: true, message: undefined, title: viewId, description: undefined, badge: undefined, reveal: () => Promise.resolve(), dispose: noop };
}

// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 3 — ExtensionContext  (injected into activate())
// ─────────────────────────────────────────────────────────────────────────────

function createExtensionContext(extensionPath) {
  const g = new Map(), w = new Map(), s = new Map();
  const mkMemento = (map) => ({
    get:            (k, def) => map.has(k) ? map.get(k) : def,
    update:         (k, v)   => { map.set(k, v); return Promise.resolve(); },
    keys:           ()       => [...map.keys()],
    setKeysForSync: noop,
  });
  return {
    subscriptions:     [],
    globalState:       mkMemento(g),
    workspaceState:    mkMemento(w),
    secrets: {
      get:    (k)    => Promise.resolve(s.get(k)),
      store:  (k, v) => { s.set(k, v); return Promise.resolve(); },
      delete: (k)    => { s.delete(k); return Promise.resolve(); },
      onDidChange: new VSEventEmitter().event,
    },
    extensionUri:      Uri.file(extensionPath),
    extensionPath,
    storagePath:       path.join(os.tmpdir(), 'vscode-mock-storage'),
    globalStoragePath: path.join(os.tmpdir(), 'vscode-mock-global'),
    logPath:           path.join(os.tmpdir(), 'vscode-mock-logs'),
    storageUri:        Uri.file(path.join(os.tmpdir(), 'vscode-mock-storage')),
    globalStorageUri:  Uri.file(path.join(os.tmpdir(), 'vscode-mock-global')),
    logUri:            Uri.file(path.join(os.tmpdir(), 'vscode-mock-logs')),
    extensionMode:     1,  // Production
    extension: { id: 'mock.extension', extensionUri: Uri.file(extensionPath), extensionPath, isActive: true, packageJSON: {}, exports: undefined, activate: () => Promise.resolve() },
    asAbsolutePath:    (rel) => path.join(extensionPath, rel),
    environmentVariableCollection: { persistent: true, replace: noop, append: noop, prepend: noop, get: () => undefined, forEach: noop, delete: noop, clear: noop, getScoped: () => ({}), description: '', [Symbol.iterator]: function*() {} },
    languageModelAccessInformation: { onDidChange: new VSEventEmitter().event, canSendRequest: () => undefined },
  };
}


// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 4 — Named event emitters
//  These are kept as VSEventEmitter objects (not just `.event` subscriptions)
//  so that sandbox.js can call `.fire(data)` on them after activate() to
//  simulate real editor behaviour and trigger event-driven malware/greyware.
//
//  Exposed as vscode._events  so the sandbox can reach them without knowing
//  the internal structure of window/workspace.
// ─────────────────────────────────────────────────────────────────────────────

//  v3.1: the registry covers every module-level (window/workspace/tasks/
//  debug/languages/env/notebooks/lm) event an extension can plausibly hang a
//  payload on. Every emitter listed here is reachable from `vscode._events`
//  and fireable by sandbox.js during detonation. Anything left as an
//  anonymous `new VSEventEmitter().event` is an event the sandbox can never
//  trigger — a silent false-negative channel.
//
//  Known remaining exception, NOT covered by this registry: the two
//  ExtensionContext-scoped emitters (`context.secrets.onDidChange`,
//  `context.languageModelAccessInformation.onDidChange` — see
//  createExtensionContext() above) are created fresh per-activation rather
//  than at module scope, so they can't be wired into this shared, static
//  registry the same way. A payload gated exclusively on either of those
//  two specific events will not fire. Documented rather than silently
//  claimed solved.
const _windowEmitters = {
  onDidChangeActiveTextEditor:        new VSEventEmitter(),
  onDidChangeVisibleTextEditors:      new VSEventEmitter(),
  onDidChangeTextEditorSelection:     new VSEventEmitter(),
  onDidChangeWindowState:             new VSEventEmitter(),
  onDidChangeActiveColorTheme:        new VSEventEmitter(),
  onDidOpenTerminal:                  new VSEventEmitter(),
  onDidChangeActiveTerminal:          new VSEventEmitter(),
  onDidCloseTerminal:                 new VSEventEmitter(),
  // Added: were previously wired to brand-new anonymous emitters at their
  // use site below, disconnected from anything sandbox.js could fire.
  onDidChangeTextEditorViewColumn:    new VSEventEmitter(),
  onDidChangeTextEditorVisibleRanges: new VSEventEmitter(),
  onDidChangeTextEditorOptions:       new VSEventEmitter(),
  onDidChangeTabGroups:               new VSEventEmitter(),
  onDidChangeTabs:                    new VSEventEmitter(),
};

const _workspaceEmitters = {
  onDidOpenTextDocument:        new VSEventEmitter(),
  onDidSaveTextDocument:        new VSEventEmitter(),
  onDidChangeTextDocument:      new VSEventEmitter(),
  onDidCloseTextDocument:       new VSEventEmitter(),
  onWillSaveTextDocument:       new VSEventEmitter(),
  onDidChangeConfiguration:     new VSEventEmitter(),
  onDidChangeWorkspaceFolders:  new VSEventEmitter(),
  onDidCreateFiles:             new VSEventEmitter(),
  onDidDeleteFiles:             new VSEventEmitter(),
  onDidRenameFiles:             new VSEventEmitter(),
  onDidGrantWorkspaceTrust:     new VSEventEmitter(),
  onDidOpenNotebookDocument:    new VSEventEmitter(),
  onDidSaveNotebookDocument:    new VSEventEmitter(),
  // Added: same disconnected-anonymous-emitter issue as the window ones above.
  onWillCreateFiles:            new VSEventEmitter(),
  onWillDeleteFiles:            new VSEventEmitter(),
  onWillRenameFiles:            new VSEventEmitter(),
  onDidChangeNotebookDocument:  new VSEventEmitter(),
  onDidCloseNotebookDocument:   new VSEventEmitter(),
  onWillSaveNotebookDocument:   new VSEventEmitter(),
};

const _otherEmitters = {
  onDidStartDebugSession:       new VSEventEmitter(),
  onDidTerminateDebugSession:   new VSEventEmitter(),
  onDidChangeSessions:          new VSEventEmitter(),
  extensionsOnDidChange:        new VSEventEmitter(),
  onDidStartTask:               new VSEventEmitter(),
  onDidEndTask:                 new VSEventEmitter(),
  // Added: same disconnected-anonymous-emitter issue as above, across
  // debug/tasks/languages/env/notebooks/lm.
  onDidChangeActiveDebugSession:        new VSEventEmitter(),
  onDidReceiveDebugSessionCustomEvent:  new VSEventEmitter(),
  onDidChangeBreakpoints:                new VSEventEmitter(),
  onDidStartTaskProcess:                 new VSEventEmitter(),
  onDidEndTaskProcess:                   new VSEventEmitter(),
  onDidChangeDiagnostics:                 new VSEventEmitter(),
  onDidChangeTelemetryEnabled:            new VSEventEmitter(),
  onDidChangeLogLevel:                    new VSEventEmitter(),
  onDidChangeShell:                       new VSEventEmitter(),
  onDidChangeNotebookCellExecutionState:  new VSEventEmitter(),
  onDidChangeChatModels:                  new VSEventEmitter(),
};

// ─────────────────────────────────────────────────────────────────────────────
//  SECTION 5 — Main vscode namespace
// ─────────────────────────────────────────────────────────────────────────────

const vscode = {

  // ── Enums ─────────────────────────────────────────────────────────────────
  StatusBarAlignment:         { Left: 1, Right: 2 },
  DiagnosticSeverity:         { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  CompletionItemKind:         { Text:0, Method:1, Function:2, Constructor:3, Field:4, Variable:5, Class:6, Interface:7, Module:8, Property:9, Unit:10, Value:11, Enum:12, Keyword:13, Snippet:14, Color:15, File:16, Reference:17, Folder:18 },
  SymbolKind:                 { File:0, Module:1, Namespace:2, Package:3, Class:4, Method:5, Property:6, Field:7, Constructor:8, Enum:9, Interface:10, Function:11, Variable:12, Constant:13 },
  TextEditorRevealType:       { Default:0, InCenter:1, InCenterIfOutsideViewport:2, AtTop:3 },
  TextEditorCursorStyle:      { Line:1, Block:2, Underline:3 },
  TextEditorLineNumbersStyle: { Off:0, On:1, Relative:2 },
  EndOfLine:                  { LF:1, CRLF:2 },
  FileType:                   { Unknown:0, File:1, Directory:2, SymbolicLink:64 },
  ViewColumn:                 { Active:-1, Beside:-2, One:1, Two:2, Three:3 },
  ExtensionKind:              { UI:1, Workspace:2 },
  ExtensionMode:              { Production:1, Development:2, Test:3 },
  OverviewRulerLane:          { Left:1, Center:2, Right:4, Full:7 },
  DecorationRangeBehavior:    { OpenOpen:0, ClosedClosed:1, OpenClosed:2, ClosedOpen:3 },
  ConfigurationTarget:        { Global:1, Workspace:2, WorkspaceFolder:3 },
  TreeItemCollapsibleState:   { None:0, Collapsed:1, Expanded:2 },
  QuickPickItemKind:          { Separator:-1, Default:0 },
  InputBoxValidationSeverity: { Info:1, Warning:2, Error:3 },
  ProgressLocation:           { SourceControl:1, Window:10, Notification:15 },
  LogLevel:                   { Off:0, Trace:1, Debug:2, Info:3, Warning:4, Error:5 },
  ColorThemeKind:             { Light:1, Dark:2, HighContrast:3 },
  TaskRevealKind:             { Always:1, Silent:2, Never:3 },
  TaskPanelKind:              { Shared:1, Dedicated:2, New:3 },
  TaskScope:                  { Global:1, Workspace:2 },
  InlayHintKind:              { Type:1, Parameter:2 },
  FoldingRangeKind:           { Comment:1, Imports:2, Region:3 },
  NotebookCellKind:           { Markup:1, Code:2 },
  LanguageStatusSeverity:     { Information:0, Warning:1, Error:2 },
  UIKind:                     { Desktop:1, Web:2 },
  CodeActionTriggerKind:      { Invoke:1, Automatic:2 },
  SignatureHelpTriggerKind:   { Invoke:1, TriggerCharacter:2, ContentChange:3 },
  CompletionTriggerKind:      { Invoke:0, TriggerCharacter:1, TriggerForIncompleteCompletions:2 },
  DiagnosticTag:              { Unnecessary:1, Deprecated:2 },
  CodeActionKind: { Empty:{value:''}, QuickFix:{value:'quickfix'}, Refactor:{value:'refactor'}, RefactorExtract:{value:'refactor.extract'}, RefactorInline:{value:'refactor.inline'}, RefactorRewrite:{value:'refactor.rewrite'}, Source:{value:'source'}, SourceOrganizeImports:{value:'source.organizeImports'}, SourceFixAll:{value:'source.fixAll'} },

  // ── Classes ───────────────────────────────────────────────────────────────
  Uri, Position, Range, Selection, Disposable,
  EventEmitter: VSEventEmitter,
  ThemeIcon, ThemeColor, MarkdownString, Diagnostic, Location,
  WorkspaceEdit, RelativePattern, FileSystemError,
  CompletionItem, CompletionList, Hover, CodeLens, TreeItem,
  SemanticTokensLegend, SemanticTokensBuilder,
  InlayHint, FoldingRange, SelectionRange,

  CancellationTokenSource: class {
    constructor() { this.token = { isCancellationRequested: false, onCancellationRequested: new VSEventEmitter().event }; }
    cancel()  { this.token.isCancellationRequested = true; }
    dispose() {}
  },

  // ── vscode.window ─────────────────────────────────────────────────────────
  window: {
    activeTextEditor:  mkEditor(),
    visibleTextEditors:[],
    terminals: [],
    activeTerminal: undefined,
    state: { focused: true },
    activeColorTheme: { kind: 2, label: 'Default Dark+' },
    tabGroups: { all:[], activeTabGroup:{ tabs:[], isActive:true, activeTab:undefined, viewColumn:1 }, onDidChangeTabGroups: _windowEmitters.onDidChangeTabGroups.event, onDidChangeTabs: _windowEmitters.onDidChangeTabs.event, close: () => Promise.resolve(false) },

    // Named emitters — these are stored in vscode._events so sandbox.js can fire them
    onDidChangeActiveTextEditor:        _windowEmitters.onDidChangeActiveTextEditor.event,
    onDidChangeVisibleTextEditors:      _windowEmitters.onDidChangeVisibleTextEditors.event,
    onDidChangeTextEditorSelection:     _windowEmitters.onDidChangeTextEditorSelection.event,
    onDidChangeTextEditorViewColumn:    _windowEmitters.onDidChangeTextEditorViewColumn.event,
    onDidChangeTextEditorVisibleRanges: _windowEmitters.onDidChangeTextEditorVisibleRanges.event,
    onDidChangeTextEditorOptions:       _windowEmitters.onDidChangeTextEditorOptions.event,
    onDidOpenTerminal:                  _windowEmitters.onDidOpenTerminal.event,
    onDidCloseTerminal:                 _windowEmitters.onDidCloseTerminal.event,
    onDidChangeActiveTerminal:          _windowEmitters.onDidChangeActiveTerminal.event,
    onDidChangeWindowState:             _windowEmitters.onDidChangeWindowState.event,
    onDidChangeActiveColorTheme:        _windowEmitters.onDidChangeActiveColorTheme.event,

    showInformationMessage: (msg) => { process.stdout.write(`  [vscode.info] ${msg}\n`); return Promise.resolve(undefined); },
    showWarningMessage:     (msg) => { process.stdout.write(`  [vscode.warn] ${msg}\n`); return Promise.resolve(undefined); },
    showErrorMessage:       (msg) => { process.stdout.write(`  [vscode.err]  ${msg}\n`); return Promise.resolve(undefined); },
    showQuickPick:             () => Promise.resolve(undefined),
    showInputBox:              () => Promise.resolve(undefined),
    showOpenDialog:            () => Promise.resolve(undefined),
    showSaveDialog:            () => Promise.resolve(undefined),
    showWorkspaceFolderPick:   () => Promise.resolve(undefined),
    showTextDocument:          () => Promise.resolve(mkEditor()),

    createOutputChannel:            (name) => mkOutputChannel(name),
    createStatusBarItem:            ()     => mkStatusBarItem(),
    createTerminal:                 (n)    => mkTerminal(n),
    createWebviewPanel:             (vt, t) => mkWebviewPanel(vt, t),
    createTextEditorDecorationType: ()     => ({ key: 'mock-deco', dispose: noop }),
    createTreeView:                 (id)   => mkTreeView(id),

    registerTreeDataProvider:       () => noopDisp(),
    registerWebviewViewProvider:    () => noopDisp(),
    registerWebviewPanelSerializer: () => noopDisp(),
    registerTerminalProfileProvider:() => noopDisp(),
    registerCustomEditorProvider:   () => noopDisp(),
    registerUriHandler:             () => noopDisp(),
    setStatusBarMessage:            () => noopDisp(),
    withProgress: (options, task) => {
      const progress = { report: noop };
      const token    = { isCancellationRequested: false, onCancellationRequested: new VSEventEmitter().event };
      return Promise.resolve().then(() => task(progress, token));
    },
  },

  // ── vscode.workspace ──────────────────────────────────────────────────────
  workspace: {
    name: 'MockWorkspace', rootPath: '/mock/workspace',
    workspaceFolders: [{ uri: Uri.file('/mock/workspace'), name: 'workspace', index: 0 }],
    workspaceFile: undefined, isTrusted: true, notebookDocuments: [], textDocuments: [],
    fs: {
      stat:           () => Promise.resolve({ type:1, ctime: Date.now(), mtime: Date.now(), size: 0 }),
      readDirectory:  () => Promise.resolve([]),
      createDirectory:() => Promise.resolve(),
      readFile:       () => Promise.resolve(new Uint8Array()),
      writeFile:      () => Promise.resolve(),
      delete:         () => Promise.resolve(),
      rename:         () => Promise.resolve(),
      copy:           () => Promise.resolve(),
      isWritableFileSystem: () => true,
    },
    // Named emitters — fireable from sandbox.js via vscode._events
    onDidChangeWorkspaceFolders:    _workspaceEmitters.onDidChangeWorkspaceFolders.event,
    onDidOpenTextDocument:          _workspaceEmitters.onDidOpenTextDocument.event,
    onDidCloseTextDocument:         _workspaceEmitters.onDidCloseTextDocument.event,
    onDidChangeTextDocument:        _workspaceEmitters.onDidChangeTextDocument.event,
    onWillSaveTextDocument:         _workspaceEmitters.onWillSaveTextDocument.event,
    onDidSaveTextDocument:          _workspaceEmitters.onDidSaveTextDocument.event,
    onDidCreateFiles:               _workspaceEmitters.onDidCreateFiles.event,
    onDidDeleteFiles:               _workspaceEmitters.onDidDeleteFiles.event,
    onDidRenameFiles:               _workspaceEmitters.onDidRenameFiles.event,
    onWillCreateFiles:              _workspaceEmitters.onWillCreateFiles.event,
    onWillDeleteFiles:              _workspaceEmitters.onWillDeleteFiles.event,
    onWillRenameFiles:              _workspaceEmitters.onWillRenameFiles.event,
    onDidChangeConfiguration:       _workspaceEmitters.onDidChangeConfiguration.event,
    onDidGrantWorkspaceTrust:       _workspaceEmitters.onDidGrantWorkspaceTrust.event,
    onDidChangeNotebookDocument:    _workspaceEmitters.onDidChangeNotebookDocument.event,
    onDidOpenNotebookDocument:      _workspaceEmitters.onDidOpenNotebookDocument.event,
    onDidCloseNotebookDocument:     _workspaceEmitters.onDidCloseNotebookDocument.event,
    onWillSaveNotebookDocument:     _workspaceEmitters.onWillSaveNotebookDocument.event,
    onDidSaveNotebookDocument:      _workspaceEmitters.onDidSaveNotebookDocument.event,

    getConfiguration: () => ({ get: (k, def) => def, has: () => false, inspect: (k) => ({ key: k, defaultValue: undefined, globalValue: undefined, workspaceValue: undefined }), update: () => Promise.resolve() }),
    getWorkspaceFolder: () => ({ uri: Uri.file('/mock/workspace'), name: 'workspace', index: 0 }),
    asRelativePath:     (p)  => String(p),
    updateWorkspaceFolders: () => false,
    findFiles:          ()   => Promise.resolve([]),
    findTextInFiles:    ()   => Promise.resolve({ results: [], limitHit: false }),
    openTextDocument:   (u)  => Promise.resolve(mkDoc(String(u || ''))),
    saveAll:            ()   => Promise.resolve(true),
    applyEdit:          ()   => Promise.resolve(true),
    requestWorkspaceTrust: () => Promise.resolve(true),
    createFileSystemWatcher: () => ({ onDidCreate: new VSEventEmitter().event, onDidChange: new VSEventEmitter().event, onDidDelete: new VSEventEmitter().event, dispose: noop }),
    registerTextDocumentContentProvider: () => noopDisp(),
    registerFileSystemProvider:          () => noopDisp(),
    registerTaskProvider:                () => noopDisp(),
    registerNotebookSerializer:          () => noopDisp(),
  },

  // ── vscode.commands ───────────────────────────────────────────────────────
  // FIX: Use a real Map registry so registerCommand() stores handlers and
  // executeCommand() actually calls them. Without this, the sandbox sees 0
  // events because all command handlers are silently discarded.
  commands: (function() {
    const _registry = new Map();
    return {
      _registry,   // exposed so sandbox.js can inspect what got registered
      registerCommand(cmd, handler) {
        _registry.set(cmd, handler);
        return new Disposable(() => _registry.delete(cmd));
      },
      registerTextEditorCommand(cmd, handler) {
        _registry.set(cmd, handler);
        return new Disposable(() => _registry.delete(cmd));
      },
      async executeCommand(cmd, ...args) {
        if (_registry.has(cmd)) {
          try {
            const result = await Promise.resolve(_registry.get(cmd)(...args));
            return result;
          } catch (e) {
            process.stderr.write(`  [vscode.cmd] executeCommand('${cmd}') threw: ${e.message}\n`);
            return undefined;
          }
        }
        return undefined;
      },
      getCommands() { return Promise.resolve([..._registry.keys()]); },
    };
  })(),

  // ── vscode.languages ──────────────────────────────────────────────────────
  languages: {
    getLanguages:            () => Promise.resolve(['javascript', 'typescript', 'python', 'plaintext']),
    setTextDocumentLanguage: (d) => Promise.resolve(d),
    match:                   () => 1,
    createDiagnosticCollection: mkDiagCollection,
    registerCompletionItemProvider:              () => noopDisp(),
    registerHoverProvider:                       () => noopDisp(),
    registerDefinitionProvider:                  () => noopDisp(),
    registerTypeDefinitionProvider:              () => noopDisp(),
    registerImplementationProvider:              () => noopDisp(),
    registerReferenceProvider:                   () => noopDisp(),
    registerDocumentHighlightProvider:           () => noopDisp(),
    registerDocumentSymbolProvider:              () => noopDisp(),
    registerWorkspaceSymbolProvider:             () => noopDisp(),
    registerCodeActionsProvider:                 () => noopDisp(),
    registerCodeLensProvider:                    () => noopDisp(),
    registerDocumentFormattingEditProvider:      () => noopDisp(),
    registerDocumentRangeFormattingEditProvider: () => noopDisp(),
    registerOnTypeFormattingEditProvider:        () => noopDisp(),
    registerSignatureHelpProvider:               () => noopDisp(),
    registerRenameProvider:                      () => noopDisp(),
    registerDocumentSemanticTokensProvider:      () => noopDisp(),
    registerDocumentRangeSemanticTokensProvider: () => noopDisp(),
    registerDocumentLinkProvider:                () => noopDisp(),
    registerColorProvider:                       () => noopDisp(),
    registerFoldingRangeProvider:                () => noopDisp(),
    registerSelectionRangeProvider:              () => noopDisp(),
    registerCallHierarchyProvider:               () => noopDisp(),
    registerTypeHierarchyProvider:               () => noopDisp(),
    registerInlayHintsProvider:                  () => noopDisp(),
    registerLinkedEditingRangeProvider:           () => noopDisp(),
    registerInlineCompletionItemProvider:         () => noopDisp(),
    registerInlineValuesProvider:                 () => noopDisp(),
    onDidChangeDiagnostics: _otherEmitters.onDidChangeDiagnostics.event,
    getDiagnostics: (uri) => uri ? [] : [],
  },

  // ── vscode.extensions ────────────────────────────────────────────────────
  extensions: { all: [], onDidChange: _otherEmitters.extensionsOnDidChange.event, getExtension: () => undefined },

  // ── vscode.env ───────────────────────────────────────────────────────────
  //  Values are DECOYS, not zeros. A stealer that ships `machineId` off-box must
  //  ship something recognisable, otherwise the taint layer sees an all-zero
  //  GUID in the payload and cannot prove the flow. Likewise the clipboard
  //  returns a plausible wallet address so clipboard-hijacking payloads take
  //  their malicious branch instead of bailing on an empty string.
  env: {
    appName: 'Visual Studio Code', appRoot: 'C:\\Program Files\\Microsoft VS Code', appHost: 'desktop',
    language: 'en', uriScheme: 'vscode',
    machineId: 'a41c9f2e-7b58-4d0a-93c6-decoy0machine',
    sessionId: 'b72d8e13-4a6f-4c19-8ee2-decoy0session1',
    isNewAppInstall: false, isTelemetryEnabled: true, remoteName: undefined,
    logLevel: 3, shell: 'C:\\WINDOWS\\System32\\cmd.exe', uiKind: 1,
    clipboard: {
      readText:  () => Promise.resolve('0xDEcoY0000000000000000000000000000000BEEF'),
      writeText: (v) => { process.stdout.write(`  🟡 [vscode.clipboard.writeText] ${String(v).slice(0, 120)}\n`); return Promise.resolve(); },
    },
    onDidChangeTelemetryEnabled: _otherEmitters.onDidChangeTelemetryEnabled.event,
    onDidChangeLogLevel:         _otherEmitters.onDidChangeLogLevel.event,
    onDidChangeShell:            _otherEmitters.onDidChangeShell.event,
    openExternal:  () => Promise.resolve(false),
    asExternalUri: (uri) => Promise.resolve(uri),
    createTelemetryLogger: () => ({ logUsage: noop, logError: noop, dispose: noop, onDidChangeEnableStates: new VSEventEmitter().event, isUsageEnabled: false, isErrorsEnabled: false }),
  },

  // ── vscode.debug ─────────────────────────────────────────────────────────
  debug: {
    activeDebugSession: undefined, activeDebugConsole: { append: noop, appendLine: noop }, breakpoints: [],
    onDidStartDebugSession:              _otherEmitters.onDidStartDebugSession.event,
    onDidTerminateDebugSession:          _otherEmitters.onDidTerminateDebugSession.event,
    onDidChangeActiveDebugSession:       _otherEmitters.onDidChangeActiveDebugSession.event,
    onDidReceiveDebugSessionCustomEvent: _otherEmitters.onDidReceiveDebugSessionCustomEvent.event,
    onDidChangeBreakpoints:              _otherEmitters.onDidChangeBreakpoints.event,
    registerDebugAdapterDescriptorFactory: () => noopDisp(),
    registerDebugConfigurationProvider:    () => noopDisp(),
    registerDebugAdapterTrackerFactory:    () => noopDisp(),
    startDebugging:  () => Promise.resolve(false), stopDebugging: () => Promise.resolve(),
    addBreakpoints: noop, removeBreakpoints: noop, asDebugSourceUri: () => Uri.file('/mock'),
  },

  // ── vscode.scm ───────────────────────────────────────────────────────────
  scm: {
    inputBox: { value:'', placeholder:'', enabled:true, visible:true },
    createSourceControl: (id, label, rootUri) => ({ id, label, rootUri, inputBox:{value:''}, count:0, quickDiffProvider:undefined, commitTemplate:undefined, acceptInputCommand:undefined, statusBarCommands:undefined, createResourceGroup:(id,label)=>({id,label,hideWhenEmpty:false,resourceStates:[],dispose:noop}), dispose:noop }),
  },

  // ── vscode.tasks ─────────────────────────────────────────────────────────
  tasks: {
    taskExecutions: [],
    // Was wired to brand-new anonymous emitters here, disconnected from the
    // ones sandbox.js actually fires via vscode._events — task-gated
    // payloads registering these listeners never ran.
    onDidStartTask: _otherEmitters.onDidStartTask.event, onDidEndTask: _otherEmitters.onDidEndTask.event,
    onDidStartTaskProcess: _otherEmitters.onDidStartTaskProcess.event, onDidEndTaskProcess: _otherEmitters.onDidEndTaskProcess.event,
    registerTaskProvider: () => noopDisp(),
    fetchTasks: () => Promise.resolve([]), executeTask: () => Promise.resolve({ task:null, terminate:noop }),
  },

  // ── vscode.authentication ─────────────────────────────────────────────────
  //  A decoy session is returned rather than `undefined`: extensions that steal
  //  the user's GitHub/Microsoft OAuth token call getSession() and give up when
  //  it is empty, so an empty mock silently suppresses the very behaviour we
  //  are looking for. The token is a marked decoy the taint layer can trace.
  authentication: {
    getSession: (providerId, scopes) => Promise.resolve({
      id: 'decoy-session-1',
      accessToken: 'gho_DECOYtokenForSandboxTaintTracing0001',
      account: { id: 'decoy-user', label: 'decoy-user' },
      scopes: scopes || ['repo', 'user'],
      provider: providerId || 'github',
    }),
    getSessions: () => Promise.resolve([]),
    registerAuthenticationProvider: () => noopDisp(),
    onDidChangeSessions: _otherEmitters.onDidChangeSessions.event,
  },

  // ── vscode.notebooks ─────────────────────────────────────────────────────
  notebooks: {
    createNotebookController: (id, nt, label) => ({ id, notebookType:nt, label, createNotebookCellExecution:()=>null, executeHandler:noop, dispose:noop, onDidChangeSelectedNotebooks: new VSEventEmitter().event }),
    registerNotebookCellStatusBarItemProvider: () => noopDisp(),
    registerNotebookSerializer: () => noopDisp(),
    onDidChangeNotebookCellExecutionState: _otherEmitters.onDidChangeNotebookCellExecutionState.event,
  },

  // ── vscode.lm ────────────────────────────────────────────────────────────
  lm: { selectChatModels: () => Promise.resolve([]), onDidChangeChatModels: _otherEmitters.onDidChangeChatModels.event, invokeTool: () => Promise.resolve(null), registerTool: () => noopDisp(), tools: [] },

  // ── Internal helpers for sandbox.js ──────────────────────────────────────
  _createExtensionContext: createExtensionContext,

  /**
   * _events — gives sandbox.js direct access to the named VSEventEmitter
   * objects so it can call .fire(data) after activate() to simulate real
   * editor events that trigger lazy / event-driven extension behaviour.
   *
   * Usage in sandbox.js:
   *   hooked.vscode._events.onDidOpenTextDocument.fire(mockDoc);
   */
  _events: Object.assign({}, _windowEmitters, _workspaceEmitters, _otherEmitters),

  /**
   * Safe event dispatch for the sandbox driver.
   * Centralises the "does this emitter exist / did the listener throw" dance
   * that was duplicated at every fire site in sandbox.js.
   * @param {string} name    key in _events
   * @param {*}      payload event argument
   * @returns {boolean} true if an emitter existed and fire() did not throw
   */
  _fire(name, payload) {
    const em = this._events[name];
    if (!em || typeof em.fire !== 'function') return false;
    try { em.fire(payload); return true; } catch (_) { return false; }
  },

  /**
   * How many listeners the extension registered across the named events.
   * Lets the driver skip fuzzing rounds nobody is listening for.
   * @param {string[]} names
   * @returns {number}
   */
  _listenerCount(names) {
    let n = 0;
    for (const name of names || Object.keys(this._events)) {
      const em = this._events[name];
      if (em && typeof em.listenerCount === 'number') n += em.listenerCount;
    }
    return n;
  },
};

module.exports = vscode;
