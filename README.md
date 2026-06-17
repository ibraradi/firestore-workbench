# Firestore Workbench

A **proxy + repeater for Google Cloud Firestore** — the Burp-style "intercept → edit → replay" loop, but for Firestore instead of HTTP.

Mobile apps talk to Firestore over a binary, persistent **gRPC stream**, so a normal HTTP proxy (Burp/mitmproxy) can't show individual reads/writes. Firestore Workbench solves this in two halves:

- **Proxy** — an optional [Frida](https://frida.re/) agent hooks the app's Firestore SDK and streams every document **write** (`set` / `update` / `add`) into the tool, with the project id and the app's own ID token auto-captured.
- **Repeater** — a local GUI where you click a captured op, edit the path / data / auth, and replay it over the **Firestore REST API** (optionally through Burp). You can also craft requests from scratch.

No external dependencies — pure Python standard library + a single Frida script.

> ⚠️ **Authorized testing only.** Use this exclusively against apps/projects you own or are explicitly permitted to test.

---

## Quick start

### 1. Run the Workbench (GUI)

Pure standard library, so it runs anywhere Python 3.9+ does — Linux, macOS, Windows.

```bash
# Linux / macOS
python3 firestore_workbench.py      # or:  ./run.sh
# Windows
python firestore_workbench.py       # or:  double-click run.bat
# GUI opens at http://127.0.0.1:8799
```
Useful flags:
```bash
python firestore_workbench.py --host 0.0.0.0          # so a device can post captures (default)
python firestore_workbench.py --port 9000
python firestore_workbench.py --proxy http://127.0.0.1:8080   # route REPLAYS through Burp
python firestore_workbench.py --no-browser
```

The GUI alone is a complete **manual** Firestore REST client: enter a `projectId` + Web API key, pick an auth mode (none / anonymous / email+password / paste ID token / refresh token), and Get / List / Query / Write / Delete any document. It encodes/decodes Firestore's typed-value JSON for you.

### 2. (Optional) Live capture from an app — the "proxy"
On a **rooted device with `frida-server` running**:

1. Edit the top of `firestore_agent.js` and set `WB_HOST` to this machine's LAN IP (the device must be able to reach it). Start the Workbench with `--host 0.0.0.0`.
2. Run the agent:
   ```bash
   frida -U -f <package-name> -l firestore_agent.js
   ```
3. Use the app. Every Firestore write appears in the Workbench's **Live capture** panel, and the app's ID token is captured automatically (so replays are authenticated — no login needed).

### 3. Replay / tamper — the "repeater"
- Click a capture → it loads into the editor (method, REST URL, body, auth all pre-filled).
- Edit and **Send** (`Ctrl/Cmd+Enter`):
  - **IDOR helper** highlights the document id — change it to another user's and resend.
  - **Auth header → without** — test what an unauthenticated client can do.
  - Change a field — replay a tampered write.
- The response shows **Decoded** (typed values → plain JSON), Pretty, Raw, and Headers.

---

### 4. Route replays through Burp (optional)

Run the workbench with `--proxy` and every replay is sent through Burp, so it lands in Burp's **Proxy history** (and can go to Repeater/Intruder):

```bash
python3 firestore_workbench.py --proxy http://127.0.0.1:8080
```

- **Captures don't go through Burp** — they're posted by the agent directly to the workbench. Only **Sends/replays** traverse Burp. (The left panel *is* your capture history; Burp shows what you replay.)
- TLS verification is auto-disabled for replays so Burp's MITM cert is accepted.
- Tick **"auto-send new → proxy/Burp"** in the capture panel to replay every new capture automatically as it arrives — Burp fills by itself. ⚠ This **re-executes the operation** (writes get re-sent), so it's off by default.

### Zero manual setup

Once a capture with a token arrives, the GUI **auto-adopts the token** and **auto-fills the Project ID** (read from the token's `aud` claim) — so for a bearer-token app you don't type the project or authenticate at all. Apps that authenticate Firestore via **App Check** (device-attested) won't yield a replayable token; set the Project ID manually and replays will be unauthenticated.

## How the agent works (and why)

| Problem | Approach |
|---|---|
| App is obfuscated (R8) — class names are renamed | Discover `DocumentReference` / `CollectionReference` **by method signature** via `FirebaseFirestore` (whose name is kept) |
| Firestore writes are binary gRPC, invisible to proxies | Hook the SDK `set`/`update`/`add` directly and read the data object |
| App forbids cleartext HTTP (`NetworkSecurityPolicy`) | Send captures over a **raw socket**, not `HttpURLConnection` |
| ID token is encrypted at rest (Keystore) + SDK is shaded | Hook `javax.crypto.Cipher.doFinal` and lift the JWT out of the **decrypted** blob in memory |

Because of the signature-based discovery, the agent adapts to each app's obfuscation automatically.

---

## Scope / limitations

- **Works:** any **Android** app using the **native Firebase Firestore SDK** (native Android, or Flutter + Firebase). Requires root + `frida-server`.
- **GUI is universal:** the REST client/repeater works against any Firebase project regardless of the agent.
- **Not covered:** iOS (the agent is Frida-Java/Android); non-Firestore backends (Supabase, custom REST, AppSync); non-Firebase auth (the token grab assumes a Firebase ID token); apps doing crypto in native/NDK code instead of `javax.crypto`.
- The agent currently captures **writes** (`set`/`update`/`add`). Reads (`get`/snapshot listeners) are not captured — you can still read anything via the GUI.

---

## Files

```
firestore_workbench.py     # the GUI + local server (proxy ingest + REST replay)
firestore_agent.js         # Frida agent: capture writes + token from the app
run.sh / run.bat           # launchers (Linux-macOS / Windows)
extras/redirect_to_burp.js # OPTIONAL, separate: pipe the app's general REST/HTTPS into Burp
                           #   (not needed for Firestore — that's what the agent is for)
```

`extras/redirect_to_burp.js` is unrelated to Firestore; it's a Frida helper for getting a proxy-unaware app's *other* REST traffic into Burp (redirects connections + disables TLS verification). Use it only if you also want to intercept non-Firestore HTTP.

## License

MIT — see [LICENSE](LICENSE).
