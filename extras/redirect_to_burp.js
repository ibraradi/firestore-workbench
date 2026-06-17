/*
 * redirect_to_burp.js  (OPTIONAL extra — not part of the Firestore capture flow)
 *
 * Frida helper to push a proxy-unaware Android app's general REST/HTTPS traffic
 * into Burp. Flutter/Dart and many native apps ignore the system proxy and/or
 * pin TLS; this script:
 *   1) rewrites outbound TCP connections (443/80) to Burp, and
 *   2) disables certificate validation (BoringSSL + Java) so Burp can MITM.
 *
 * Note: Firestore traffic is binary gRPC and won't render usefully in Burp even
 * if redirected — use firestore_agent.js for Firestore. This is for the app's
 * OTHER REST endpoints.
 *
 * BURP SETUP: add a Proxy listener on a LAN IP the device can reach and enable
 * "Support invisible proxying" on it (Proxy settings -> the listener -> Request
 * handling). The redirect sends raw connections, so invisible proxying is required.
 *
 * Usage:  frida -U -f <package> -l redirect_to_burp.js
 * Only use against apps you are authorized to test.
 */

'use strict';

// ====== CONFIG ============================================================
var BURP_HOST = '127.0.0.1';   // Burp listener IP reachable from the device (set to your LAN IP)
var BURP_PORT = 8080;
var REDIRECT_PORTS = [443, 80, 8443];
var SKIP_IPS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112']; // DoH resolvers — don't break DNS
var VERBOSE = true;
// ==========================================================================

function log(m) { if (VERBOSE) console.log('[burp] ' + m); }

// resolve an export across Frida 16 and 17 (the Module API changed in 17)
function exp(modName, name) {
  try { if (modName === null && typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name); } catch (e) {}
  try { if (modName !== null && typeof Process.findModuleByName === 'function') { var m = Process.findModuleByName(modName); return m ? m.findExportByName(name) : null; } } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(modName, name); } catch (e) {}
  return null;
}

function ipBytes(ip) { return ip.split('.').map(function (x) { return parseInt(x, 10) & 0xff; }); }

function installConnectRedirect() {
  var connectPtr = exp(null, 'connect');
  if (!connectPtr) { log('connect() not found'); return; }
  var burp = ipBytes(BURP_HOST);
  Interceptor.attach(connectPtr, {
    onEnter: function (args) {
      try {
        var sa = args[1]; if (sa.isNull()) return;
        var family = sa.readU16();
        if (family === 2) {                                  // AF_INET
          var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
          var ip = [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.');
          if (ip === BURP_HOST || ip.indexOf('127.') === 0) return;
          if (SKIP_IPS.indexOf(ip) !== -1) return;
          if (REDIRECT_PORTS.indexOf(port) === -1) return;
          sa.add(2).writeU8((BURP_PORT >> 8) & 0xff); sa.add(3).writeU8(BURP_PORT & 0xff);
          sa.add(4).writeU8(burp[0]); sa.add(5).writeU8(burp[1]); sa.add(6).writeU8(burp[2]); sa.add(7).writeU8(burp[3]);
          this._redir = ip + ':' + port;
        } else if (family === 10) {                          // AF_INET6 -> force IPv4 fallback
          this._v6 = true; sa.writeU16(0);
        }
      } catch (e) {}
    },
    onLeave: function () {
      if (this._redir) log('redirected ' + this._redir + ' -> ' + BURP_HOST + ':' + BURP_PORT);
    }
  });
  log('connect() redirect -> ' + BURP_HOST + ':' + BURP_PORT + ' (ports ' + REDIRECT_PORTS.join(',') + ')');
}

function installBoringSSLBypass() {
  ['libflutter.so', 'libapp.so', 'libssl.so', 'libboringssl.so'].forEach(function (lib) {
    ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach(function (sym) {
      var addr = exp(lib, sym); if (!addr) return;
      try {
        Interceptor.attach(addr, { onEnter: function (args) { args[2] = new NativeCallback(function () { return 0; }, 'int', ['pointer', 'pointer']); } });
        log('hooked ' + lib + '!' + sym);
      } catch (e) {}
    });
  });
}

function installJavaBypass() {
  if (!Java.available) return;
  Java.perform(function () {
    try {
      var X509TM = Java.use('javax.net.ssl.X509TrustManager'), SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TM = Java.registerClass({ name: 'burp.TrustAll', implements: [X509TM],
        methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {}, getAcceptedIssuers: function () { return []; } } });
      var tms = [TM.$new()];
      var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) { init.call(this, km, tms, sr); };
      log('Java TrustManager bypass installed');
    } catch (e) {}
    try { var CP = Java.use('okhttp3.CertificatePinner'); CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {}; log('OkHttp CertificatePinner neutralized'); } catch (e) {}
    try { var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl'); TMI.checkTrustedRecursive.implementation = function () { return Java.use('java.util.ArrayList').$new(); }; log('Conscrypt bypass installed'); } catch (e) {}
    try { var WVC = Java.use('android.webkit.WebViewClient'); WVC.onReceivedSslError.implementation = function (v, h, e) { h.proceed(); }; } catch (e) {}
  });
}

log('starting...');
installConnectRedirect();
installBoringSSLBypass();
installJavaBypass();
setTimeout(installBoringSSLBypass, 2000);
log('ready — use the app, watch Burp Proxy history.');
