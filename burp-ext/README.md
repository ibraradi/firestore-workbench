# Firestore Workbench — Burp extension

The Burp-native version of Firestore Workbench. Instead of the standalone Python GUI,
this **Montoya extension** listens for capture events from the Frida agent and drops
each one straight into **Burp Repeater**. No separate GUI, no `--proxy`, no browser.

```
Frida agent (on device)  ──HTTP POST /api/capture──►  Burp extension  ──►  Repeater tab
```

## Build

Requires a JDK (17+) and Gradle.

```bash
cd burp-ext
gradle shadowJar
# -> build/libs/firestore-workbench-burp.jar
```

(If you don't have Gradle installed, install it, or generate a wrapper with `gradle wrapper` once and use `./gradlew shadowJar`.)

## Load in Burp

Burp → **Extensions → Installed → Add** → Extension type **Java** → select
`build/libs/firestore-workbench-burp.jar`.

The Output tab should show:

```
Firestore Workbench: listening on http://0.0.0.0:8799/api/capture
```

## Use

1. Edit `../firestore_agent.js` and set `WB_HOST` to the machine running Burp (its LAN
   IP, reachable from the device) and `WB_PORT = 8799`.
2. Run the agent: `frida -U -f <package> -l ../firestore_agent.js`.
3. Use the app. Each captured write (`set`/`update`/`add`) appears as a **Repeater tab**,
   pre-built with the document path, typed-value body, and the captured `Authorization:
   Bearer` token. The project id is taken from the capture or derived from the token's
   `aud` claim.
4. Edit and **Send** from Repeater (swap the doc id for IDOR, drop the auth header, change
   a field, etc.).

## Why this vs. the Python tool

- **Non-destructive:** captures become Repeater tabs — nothing fires until *you* hit Send
  (no auto-replay side effects).
- **No TLS/CA/cleartext juggling:** requests go through Burp's own HTTP stack.
- **One moving part:** just the Frida agent + Burp. No Python server.

The standalone `firestore_workbench.py` is still useful when you want the live capture
list / typed-value editor / quick replay outside Burp. Same agent feeds both.

## Notes

- Listens on `0.0.0.0:8799` so the device can reach it; change `PORT` in the source if needed.
- Only `set`/`update`/`add` writes are captured by the agent; reads aren't (build those in Repeater).
- Apps that authenticate Firestore via **App Check** won't yield a replayable token — the
  request still goes to Repeater, just unauthenticated.

Use only against apps you are authorized to test.
