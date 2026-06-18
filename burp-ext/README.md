# Firestore Workbench — Burp extension

The Burp-native version of Firestore Workbench. Instead of the standalone Python GUI,
this **Montoya extension** listens for capture events from the Frida agent and sends
each one **through Burp's proxy** so it appears in **Proxy → HTTP history** — where you
review them and send the ones you want to Repeater yourself.

```
Frida agent (on device) ──POST /api/capture──► extension ──through Burp proxy──► Proxy HTTP history
```

## Configuration

Defaults at the top of `FirestoreWorkbenchExtension.java` (change and rebuild if needed):

| Constant | Default | Meaning |
|---|---|---|
| `LISTEN_PORT` | `8799` | where the Frida agent posts captures |
| `PROXY_HOST` | `127.0.0.1` | Burp's proxy listener host (placeholder — change only if Burp runs elsewhere) |
| `PROXY_PORT` | `8080` | Burp's proxy listener port |
| `DEFAULT_PROJECT` | `""` | fallback project id when there's no token to derive it from (e.g. App Check apps); leave empty to skip tokenless captures |

## Build

Requires a JDK (17+) and Gradle:

```bash
cd burp-ext
gradle shadowJar
# -> build/libs/firestore-workbench-burp.jar
```

No Gradle? Build manually with the JDK:

```bash
cd burp-ext
mkdir -p libs out build/libs
curl -L -o libs/montoya-api.jar https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar
curl -L -o libs/gson.jar        https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar
javac -cp "libs/montoya-api.jar:libs/gson.jar" -d out src/main/java/firestoreworkbench/FirestoreWorkbenchExtension.java
(cd out && jar xf ../libs/gson.jar && rm -rf META-INF module-info.class)
jar cf build/libs/firestore-workbench-burp.jar -C out .
```
(On Windows use `;` instead of `:` in the `-cp` separator.)

## Load in Burp

Burp → **Extensions → Installed → Add** → type **Java** → select
`build/libs/firestore-workbench-burp.jar`.

Output should show:

```
Firestore Workbench: capture listener on http://0.0.0.0:8799/api/capture
Captures are sent through Burp proxy 127.0.0.1:8080 -> Proxy HTTP history.
```

## Use

1. In `../firestore_agent.js`, set `WB_HOST` to the machine running Burp (reachable from
   the device) and `WB_PORT = 8799`.
2. Run the agent: `frida -U -f <package> -l ../firestore_agent.js`.
3. Use the app. Each captured write is sent through Burp and appears in **Proxy → HTTP
   history** as a `firestore.googleapis.com` request (with the captured `Authorization:
   Bearer` token; project derived from the token's `aud`). Review there, then right-click
   → **Send to Repeater** on the ones you want.

## Notes

- **Sending executes the request** (re-runs writes) — that's required to land in Proxy
  history. Reads/denied writes simply log a 4xx.
- Burp's proxy listener must be running on `PROXY_HOST:PROXY_PORT`. If you see
  *"proxy CONNECT failed"* in Output, that listener isn't there.
- Listens on `0.0.0.0:8799` so the device can reach it.
- Only `set`/`update`/`add` writes are captured by the agent; reads aren't.
- Apps that authenticate Firestore via **App Check** won't yield a replayable token — the
  request still goes through, just unauthenticated.

The standalone `firestore_workbench.py` is still useful for a live capture list / typed-value
editor / quick replay outside Burp. Same agent feeds both.

Use only against apps you are authorized to test.
