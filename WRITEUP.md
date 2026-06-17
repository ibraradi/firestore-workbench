# Intercepting and Tampering Firestore: building a proxy/repeater for a Firebase mobile app

A field write-up on how a small observation — "I changed my name and there was no request" — turned into a reusable tool for intercepting, editing, and replaying Google Cloud Firestore traffic from a mobile app.

The target was a **Flutter-based Android application backed by Google Firebase/Firestore**. Everything below is anonymized; document paths, project ids, hosts and tokens are generic placeholders.

---

## 1. The observation that started it

While poking at the app's profile screen, something stood out: editing a profile field (say, the display name) took effect **instantly and everywhere** — across every screen in the app and on the company's web portal — yet **no request showed up** in the intercepting proxy at the moment of the change.

That contradiction is the whole story. If the change is reaching a backend, there must be traffic. If there's no traffic, how does it persist and propagate? The answer turned out to define the entire engagement.

## 2. Why a normal proxy sees nothing

Firebase Firestore mobile SDKs don't speak plain REST. They keep a **single, long-lived gRPC stream over HTTP/2** to the Firestore endpoint, and reads/writes are **binary protobuf frames multiplexed inside that one connection**.

A normal HTTP proxy (Burp, mitmproxy, HTTP Toolkit) is built around discrete request/response pairs. A write riding an already-open bidirectional gRPC stream doesn't appear as a new entry — at best you see one opaque, never-ending connection. So "no request" was an illusion: the write was there, just not in a form the proxy could surface.

On top of that, mobile adds three more walls:

- **The app ignores the system proxy.** Flutter/Dart's HTTP stack doesn't honor the Android Wi‑Fi proxy at all.
- **TLS trust is independent.** Flutter ships its own CA set in its bundled BoringSSL, so trusting your proxy's CA at the OS level isn't enough; and many apps pin.
- **Cleartext is blocked.** Modern Android apps forbid plaintext HTTP by default (`NetworkSecurityPolicy`).

### Why Burp Suite and HTTP proxies specifically didn't work

It's worth being concrete, because Burp is the reflex tool and it fails here for several independent reasons — fixing one just exposes the next:

1. **The traffic never reaches the proxy.** Setting the device Wi‑Fi proxy to Burp does nothing, because the Flutter/Dart networking layer doesn't read the system proxy setting. Burp's history stays empty not because there's nothing to see, but because nothing is routed to it.

2. **Even when forced to Burp, TLS fails.** Push the traffic to Burp anyway (transparent redirect / VPN / Frida) and the TLS handshake breaks: Firestore's client uses BoringSSL with its **own compiled-in CA roots**, so Burp's interception certificate isn't trusted even though Burp's CA was installed in the Android system store. You get handshake failures, not decrypted traffic — until you separately defeat that with a Frida TLS-bypass.

3. **Burp is request/response; Firestore is a stream.** This is the killer. Even after you get bytes into Burp, Firestore rides a **single long-lived gRPC/HTTP‑2 connection** carrying **binary protobuf** `Listen`/`Write` frames. Burp's model is one request → one response. A long-lived bidirectional stream shows up (if at all) as one opaque connection; individual document reads/writes are framed protobuf *inside* it, which Burp's history, Repeater, and message editor can't split out, decode, or meaningfully edit.

4. **HTTP Toolkit hit the same wall.** It captures Flutter REST fine, but Firestore's gRPC stream is the same opaque binary blob there too — same protocol mismatch, different UI.

5. **Operational dead-ends along the way.** When we *did* force connections into Burp to prove the point, the proxy errored with `Invalid client request received: First line of request did not contain an absolute URL` (raw redirected connections need Burp's **invisible proxying** enabled), and redirecting the app's DNS‑over‑HTTPS to Burp broke name resolution entirely. Even after solving those, point (3) still stands.

The takeaway: **Burp/HTTP proxies are the right tool for REST and the wrong tool for Firestore's transport.** Not a configuration problem — a protocol mismatch. That's what forced the move to SDK-level instrumentation.

## 3. Mapping the architecture

Firestore is a **real-time data layer**: clients subscribe to documents with snapshot listeners, and the moment a document changes the server **pushes** the new value to every subscriber. That's why the name change appeared everywhere instantly — the app and the web portal are both just subscribers to the same document.

This reframed the goal. You don't intercept Firestore by sitting on the wire; you either:

1. talk to the **Firestore REST API** (the same data is reachable as ordinary HTTPS+JSON with the right token), or
2. **hook the SDK** inside the app, below the network and above the encryption.

We ended up using both: REST for replay, SDK hooks for capture.

## 4. First attempts, and why they fell short

**Proxy-only.** Pointing the proxy at the device produced the expected nothing-useful for Firestore. Confirmed the gRPC theory.

**Redirect everything into the proxy with Frida.** A reasonable instinct: use Frida to rewrite outbound connections to the proxy and disable TLS validation, so even a proxy-unaware app shows up. This *worked for the app's ordinary REST endpoints* and is a handy capability in its own right (it's shipped as an optional extra), but it taught us several practical lessons the hard way:

- The proxy listener must have **invisible proxying** enabled — we were sending raw redirected connections with no `CONNECT` line, and without invisible mode the proxy silently rejected them (`First line of request did not contain an absolute URL`).
- **Don't redirect DNS-over-HTTPS.** The app resolved names via DoH (`1.1.1.1:443`); redirecting that broke resolution, so the app spun forever retrying DoH and never made its real calls. We had to exclude the resolvers.
- **IPv6.** The Firestore endpoint resolved to IPv6 first; our IPv4-only redirect plus an IPv6 block was killing those connections outright.

And even after all that, Firestore over the wire is *still* binary gRPC — redirecting it into the proxy gives you an opaque stream, not readable operations. The conclusion was clear: **for Firestore, intercept at the SDK, not the network.**

## 5. The pivot: hooking the SDK with Frida

[Frida](https://frida.re/) lets you run JavaScript inside the target process and hook arbitrary methods. That's exactly the altitude we needed: the data is in plaintext objects at the SDK layer, before it's serialized, encrypted, and streamed.

The complication: this was a **release build with R8 obfuscation**. `DocumentReference`, `CollectionReference` and their `set`/`update`/`get` methods are all renamed to single letters. You can't hook `DocumentReference.set()` by name because that name doesn't exist anymore.

**The trick: discover classes by signature, not by name.** The public entry point `com.google.firebase.firestore.FirebaseFirestore` keeps its name (Firebase's consumer ProGuard rules preserve the API surface entry points). From there:

- Enumerate `FirebaseFirestore`'s methods that take a single `String` — these are `collection()`, `document()`, `collectionGroup()`. Their **return types** are the obfuscated reference classes.
- For each candidate return type, inspect *its* methods: the class with a method `(Object, …) -> Task` is `DocumentReference` (that's `set`); the one with `(Object) -> <ref>` is `CollectionReference` (that's `add`).
- Recover the document path at runtime by calling the no-arg `String` getter that returns a value containing `/`.

This signature-based discovery is the key to generality — it adapts to whatever the obfuscator renamed things to, on any app:

```js
// FirebaseFirestore keeps its name under R8; the reference classes are renamed.
const FF = Java.use('com.google.firebase.firestore.FirebaseFirestore');

// document()/collection() take a String and return the obfuscated ref classes.
// DocumentReference is the one whose class exposes set(Object, …) -> Task.
let docRef = null;
FF.class.getDeclaredMethods()
  .filter(m => m.getParameterTypes().length === 1 &&
               m.getParameterTypes()[0].getName() === 'java.lang.String')
  .forEach(m => {
    const cn = m.getReturnType().getName();
    const hasSet = Java.use(cn).class.getDeclaredMethods().some(x => {
      const p = x.getParameterTypes();
      return p.length >= 1 && p[0].getName() === 'java.lang.Object' &&
             x.getReturnType().getName().includes('Task');   // set() returns a Task
    });
    if (hasSet) docRef = cn;
  });
```

With the class resolved, we hook every `set`/`update` overload by signature, recover the document path from its no-arg `String` getter, and walk the written Java object into plain JSON:

```js
const DR = Java.use(docRef);
DR.class.getDeclaredMethods().forEach(m => {
  const p = m.getParameterTypes().map(t => t.getName());
  const op = (p[0] === 'java.lang.Object') ? 'set'
           : (p.length === 1 && p[0] === 'java.util.Map') ? 'update' : null;
  if (!op) return;
  const ov = DR[m.getName()].overload(...p);
  ov.implementation = function () {
    send({ op, path: getPath(this), data: toJson(arguments[0]) }); // -> Workbench
    return ov.apply(this, arguments);                              // let the write proceed
  };
});
```

Now we can *see* every Firestore write the app makes, decoded.

## 6. Building the tool: Firestore Workbench

Frida console logs prove the concept but aren't a workflow. What we actually wanted was the Firestore equivalent of **Burp's Proxy + Repeater**: a live feed of operations you can click, edit, and replay.

So we built **Firestore Workbench**:

- **A tiny local server** (Python standard library only — no dependencies). It serves a single-page GUI and exposes two endpoints: one that **ingests captures** from the Frida agent, and a generic **send/proxy** endpoint that performs the outbound Firestore REST calls server-side (so the browser GUI has no CORS problems).
- **The Frida agent** streams each captured write — operation, document path, data, project id, and the user's token — to the server over a **raw socket** (more on that below).
- **The GUI** shows a live "capture" panel (the proxy view). Click any capture and it loads into an editor with the method, the Firestore REST URL, the body, and the auth pre-filled (the repeater view). Edit and send. It encodes/decodes Firestore's verbose typed-value JSON automatically, has an **IDOR helper** that highlights the document id for quick swapping, and an auth toggle to test what an *unauthenticated* client can do. Replays can optionally be routed through Burp for logging.

The result: **capture (from the live app) → click → edit → replay (over REST)** — exactly the loop you'd want, for a protocol that normally has no such tooling.

## 7. The hard part: getting the token

To replay a write *authenticated as the app*, we needed the app's Firebase **ID token**. This was the longest fight of the project, and worth documenting because each dead end is instructive:

1. **Read it off disk.** Firebase persists the user in shared preferences — but the value was `ENCRYPTED:` (newer Firebase Auth encrypts the persisted token with an Android Keystore key). Can't decrypt offline.
2. **Hook the gRPC `authorization` metadata.** The token is attached as a `Bearer` header on the gRPC channel — but Firebase **shades and obfuscates** its bundled gRPC, so there's no `io.grpc.Metadata` class to hook, and no class even *ends* in `.Metadata`. Dead end.
3. **Ask `FirebaseAuth` for it** (`getCurrentUser().getIdToken()`, or `Tasks.await`). This fought two problems at once: at app startup `FirebaseApp` isn't initialized yet (the earliest writes happen before auth is ready), and the relevant helper classes were shaded/renamed (`not a function`). Unreliable.
4. **The winner: hook the decryption.** The token only exists in plaintext *in memory*, right after Firebase decrypts the persisted blob. So we hooked `javax.crypto.Cipher.doFinal` and scanned its output for a JWT. When Firebase loads or refreshes the user, the decrypted JSON flows through `doFinal`, and we lift the ID token straight out of it:

```js
const Cipher = Java.use('javax.crypto.Cipher');
Cipher.doFinal.overloads.forEach(ov => {
  ov.implementation = function () {
    const out = ov.apply(this, arguments);              // decrypted bytes
    try {
      const s = '' + Java.use('java.lang.String').$new(out, 'UTF-8');
      const jwt = s.match(/eyJ[\w-]+\.[\w-]+\.[\w-]+/);  // the Firebase ID token
      if (jwt) reportToken(jwt[0]);                      // -> Workbench (auto-adopted)
    } catch (e) {}
    return out;
  };
});
```

This is robust precisely because it doesn't depend on any obfuscated/shaded names or on timing — it sits on a standard platform crypto API that *everything* eventually goes through.

Once captured, the agent posts the token to the Workbench, and the GUI **auto-adopts** it — so replays are authenticated with the app's own identity, with **no manual login and no password required**. That last point matters: in a real assessment you often can't get a token "manually" (social login, no credentials, someone else's session). Lifting it from the running process sidesteps that entirely.

## 8. A transport gotcha worth knowing

The agent's first attempt to ship captures used `HttpURLConnection` — and silently delivered nothing. The cause was the same cleartext-HTTP policy mentioned earlier: the app forbids plain `http://` via the platform HTTP stack. The fix was to **POST over a raw `java.net.Socket`**, hand-writing the HTTP request. Raw sockets aren't subject to `NetworkSecurityPolicy`, so captures flowed immediately.

## 9. Engineering friction (the unglamorous truth)

A fair amount of time went to plumbing, not exploitation:

- **Orphaned processes.** Background Frida and server processes outlived their shells; `pkill` doesn't reliably kill Windows-side processes, so stale agents and a stale server kept answering on the same port, masking new code with old behavior. The tell was code changes "not taking effect" — and the fix was hunting PIDs by listening port and command line.
- **The device dropped off Wi‑Fi ADB** mid-run, which surfaced as a hung `frida-ps`. Reconnect, restart `frida-server`, carry on.
- **Two Frida sessions can't spawn the same app**, so a leftover agent made new spawns hang on "waiting for USB device."

None of this is exotic, but it's the reality of dynamic instrumentation work, and recognizing the symptoms saves hours.

## 10. What the tooling unlocked

With reliable capture + authenticated replay, the actual testing became straightforward and, more importantly, *fast*:

- **Is the client trusted to write its own data?** The app writes its profile document directly to Firestore (`profiles/{uid}`). That means the **Firestore Security Rules are the only access control** on those writes — there's no server-side API validating them.
- **Field-level validation.** Replaying the captured write with extra or modified fields — including authorization-relevant ones the UI never exposes — showed the rules accepted *any* field with *any* value on the owner's own document. (All test mutations were reverted.)
- **IDOR.** The IDOR helper made it trivial to swap the document id to another user's and resend, to check whether ownership is enforced (it was, for the main documents — a good negative result worth recording).
- **Read-vs-write asymmetry.** Subcollections that were clearly *named* to be server-controlled turned out to be client-writable, and some were cross-user readable while the parent document was not — the kind of rule inconsistency that's only obvious once you can replay arbitrary reads/writes quickly.

The point isn't any single finding; it's that **a protocol with no off-the-shelf intercept tooling became as testable as ordinary HTTP**, because we built the missing tool.

### Representative findings (anonymized)

The capture/replay loop turned vague hunches into confirmed, reproducible issues. Three generalized examples of what surfaced once Firestore was as testable as HTTP:

- **Collection-wide PII exposure — Critical.** The Security Rules let *any authenticated user* read and **list an entire collection of user-profile documents**, returning every user's personal data (names, emails, locations, job titles, etc.). Root cause: read access scoped to "is signed in" instead of "is the document owner," with no deny on collection-level listing. Reproduced with a single authenticated REST read against the collection.

- **Private conversations fully readable — High.** A single structured query against the messaging collection returned **all conversations** — messages *and* participant identities — to any authenticated user. Same root cause: reads weren't restricted to conversation participants. Reproduced with one `runQuery`.

- **Role escalation via a self-writable profile field — Medium.** Because the client writes its own profile document directly and the rules didn't validate fields, a user could set an **authorization-relevant role/persona field on their own document** and gain access to role-restricted channels. This is precisely the client-trust gap the tooling was built to probe: replay the captured profile write with the role field changed, then read a previously restricted resource.

- **Unauthenticated write to server-side telemetry — Medium.** On a *second* app sharing the same backend, a family of log/telemetry collections turned out to be **world-writable with no authentication at all**: an unauthenticated read returned `403`, but an unauthenticated `PATCH` returned `200`. Any anonymous client can inject or poison those audit/telemetry records (and if they're rendered in an admin console, that's a stored-injection vector). Found by replaying a captured write **with no `Authorization` header**.

Each was a one-liner to reproduce once the token was in hand (paths/collection names below are generic placeholders):

```http
# 1) Collection-wide read — returns every user's profile document
GET /v1/projects/<project>/databases/(default)/documents/profiles HTTP/1.1
Host: firestore.googleapis.com
Authorization: Bearer <any-authenticated-user-token>
```

```http
# 2) Query the messaging collection — returns all conversations + participants
POST /v1/projects/<project>/databases/(default)/documents:runQuery HTTP/1.1
Host: firestore.googleapis.com
Authorization: Bearer <any-authenticated-user-token>

{ "structuredQuery": { "from": [ { "collectionId": "messages" } ] } }
```

```http
# 3) Overwrite a role field on your OWN profile, then read a restricted resource
PATCH /v1/projects/<project>/databases/(default)/documents/profiles/<your-uid>?updateMask.fieldPaths=role HTTP/1.1
Host: firestore.googleapis.com
Authorization: Bearer <your-token>

{ "fields": { "role": { "stringValue": "<elevated-role>" } } }
```

```http
# 4) Write to a telemetry/log doc with NO auth header — server accepts it (200)
PATCH /v1/projects/<project>/databases/(default)/documents/<telemetry-collection>/<id>?updateMask.fieldPaths=x HTTP/1.1
Host: firestore.googleapis.com

{ "fields": { "x": { "stringValue": "anyone-can-write-this" } } }
```

The common thread across all four is the same architectural lesson: in a Firebase app the **Security Rules are the entire authorization layer**, and the only way to exercise them thoroughly is to read, write, and query Firestore directly — which is what the workbench makes possible.

### Proving it generalizes — and a bug it exposed

Pointing the same agent at a *different* app on the same stack (just a new package name) validated the design — and surfaced a bug worth noting. The second app was a **non-obfuscated** build, and the naive class discovery ("the reference class with an `(Object) -> Task` method") misfired: `CollectionReference.add(Object)` *also* returns a `Task`, so it was mistaken for `DocumentReference`. The fix was to key on a signature only `DocumentReference` has — `update(Map) -> Task` / `set(Object, SetOptions) -> Task` — which is correct on **both** obfuscated and clean builds. Lesson: validate signature heuristics against more than one build.

That second app also authenticated Firestore via **App Check** (device-attested) rather than a bearer token, so `Cipher.doFinal` yielded nothing — a reminder that the token-capture trick only applies to apps using a Firebase ID token. It didn't matter for the unauthenticated-write finding, since that rule required no auth at all.

### Burp integration

For teams that live in Burp: run the workbench with `--proxy http://127.0.0.1:8080` and every replay is routed through Burp into the Proxy history (and on to Repeater/Intruder); an optional "auto-send" toggle forwards each capture as it arrives. A subtlety worth stating: **captures don't traverse Burp** (the agent posts them straight to the workbench) — only *replays* do. For bearer-token apps the workbench auto-adopts the token and auto-fills the project id from the token's `aud` claim, so the loop is hands-off: **the app writes → it shows up, authenticated, in Burp.**

## 11. Takeaways

- **Firebase pushes trust to the client.** When the app writes documents directly, the Security Rules *are* the application's authorization layer. Test them as such — at the field level, cross-user, and per-collection.
- **Firestore needs SDK-level interception, not a network proxy.** gRPC streaming defeats request/response proxies; hook the SDK or use the REST API.
- **Obfuscation is not a wall.** Signature-based discovery from a kept entry-point class recovers renamed classes reliably.
- **The right place to grab a secret is where it's used in plaintext.** When at-rest storage is encrypted and the network layer is shaded, the decryption call (`Cipher.doFinal`) is a dependable choke point.
- **Build the tool.** A few hundred lines of standard-library Python plus one Frida script turned a "you can't really see Firestore" situation into a full capture/edit/replay workflow that generalizes to any Firestore-backed Android app.

---

## References

- **Get started with Firestore Security Rules** — https://firebase.google.com/docs/firestore/security/get-started
- **Firestore Security Rules overview** — https://firebase.google.com/docs/firestore/security/overview
- **Frida** — https://frida.re/

If you take one thing from the "Get started" guide: rules default to *deny*, but the common mistake is widening them to `allow read, write: if request.auth != null` ("any signed-in user") instead of `if request.auth.uid == userId` ("only the owner"). That single difference is the root cause behind every finding above.

---

## Appendix: the toolkit

- **`firestore_workbench.py`** — local server + GUI; live capture ingest and REST replay (capture → edit → replay), with typed-value encode/decode and an IDOR helper.
- **`firestore_agent.js`** — Frida agent; signature-based SDK discovery, `set`/`update`/`add` hooks, `Cipher.doFinal` token capture, raw-socket capture transport.
- **`extras/redirect_to_burp.js`** — optional, separate; pipes a proxy-unaware app's *non-Firestore* REST/HTTPS traffic into Burp (connection redirect + TLS-validation bypass).

All target-agnostic; point them at any Android app you are **authorized** to test.
