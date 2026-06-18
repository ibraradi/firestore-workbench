package firestoreworkbench;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

/**
 * Firestore Workbench — Burp extension.
 *
 * Listens for capture events from firestore_agent.js (the Frida agent), builds the
 * equivalent Firestore REST request (with the captured Bearer token), and sends it
 * THROUGH Burp's own proxy (127.0.0.1:PROXY_PORT) so it shows up in Proxy → HTTP
 * history. From there you send the ones you want to Repeater yourself.
 *
 * Sending executes the request (re-runs writes). Reads/denied writes just log a 4xx.
 */
public class FirestoreWorkbenchExtension implements BurpExtension {

    private static final int LISTEN_PORT = 8799;        // where the Frida agent posts captures
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 8080;          // Burp's proxy listener
    private static final String FS_HOST = "firestore.googleapis.com";
    // Fallback project id for apps with no bearer token (e.g. App Check) where it can't be
    // derived from the token's aud. Leave "" to skip such captures.
    private static final String DEFAULT_PROJECT = "";

    private MontoyaApi api;
    private ServerSocket serverSocket;
    private volatile boolean running = true;
    private SSLSocketFactory trustAll;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Firestore Workbench");
        this.trustAll = trustAllFactory();

        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("0.0.0.0", LISTEN_PORT));
            Thread t = new Thread(this::acceptLoop, "fs-workbench-listener");
            t.setDaemon(true);
            t.start();
            api.logging().logToOutput("Firestore Workbench: capture listener on http://0.0.0.0:" + LISTEN_PORT + "/api/capture");
            api.logging().logToOutput("Captures are sent through Burp proxy " + PROXY_HOST + ":" + PROXY_PORT + " -> Proxy HTTP history.");
        } catch (Exception e) {
            api.logging().logToError("Failed to start capture listener on port " + LISTEN_PORT + ": " + e);
        }

        api.extension().registerUnloadingHandler(() -> {
            running = false;
            try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        });
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket sock = serverSocket.accept();
                handle(sock);
            } catch (Exception e) {
                if (running) api.logging().logToError("accept: " + e);
            }
        }
    }

    /** Read one capture POST (headers until CRLFCRLF, then Content-Length bytes), reply 200. */
    private void handle(Socket sock) {
        try {
            sock.setSoTimeout(5000);
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            String headers = readHeaders(in);
            int contentLength = 0;
            for (String line : headers.split("\r\n")) {
                int idx = line.indexOf(':');
                if (idx > 0 && line.substring(0, idx).trim().equalsIgnoreCase("Content-Length")) {
                    try { contentLength = Integer.parseInt(line.substring(idx + 1).trim()); } catch (Exception ignored) {}
                }
            }
            byte[] body = new byte[Math.max(0, contentLength)];
            int read = 0;
            while (read < contentLength) {
                int r = in.read(body, read, contentLength - read);
                if (r < 0) break;
                read += r;
            }
            if (read > 0) {
                try { process(JsonParser.parseString(new String(body, 0, read, StandardCharsets.UTF_8)).getAsJsonObject()); }
                catch (Exception e) { api.logging().logToError("capture parse/process error: " + e); }
            }
            byte[] resp = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + resp.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(resp);
            out.flush();
        } catch (Exception e) {
            if (running) api.logging().logToError("handle: " + e);
        } finally {
            try { sock.close(); } catch (Exception ignored) {}
        }
    }

    /** Build the Firestore REST request for one capture and send it through Burp's proxy. */
    private void process(JsonObject c) {
        String op = str(c, "op", "get");
        if ("auth".equals(op)) return; // token beacon, nothing to send

        String token = str(c, "token", null);
        String project = str(c, "project", null);
        if (project == null && token != null) project = projectFromJwt(token);
        if (project == null && !DEFAULT_PROJECT.isEmpty()) project = DEFAULT_PROJECT;
        if (project == null) {
            api.logging().logToError("no project id (and none derivable from token); skipping " + str(c, "path", ""));
            return;
        }

        String path = str(c, "path", "");
        String collection = str(c, "collection", path);
        JsonObject data = (c.has("data") && c.get("data").isJsonObject()) ? c.getAsJsonObject("data") : new JsonObject();

        String base = "/v1/projects/" + project + "/databases/(default)/documents/";
        String method, pathAndQuery, jsonBody = null;
        switch (op) {
            case "set":
                method = "PATCH"; pathAndQuery = base + path; jsonBody = wrapFields(data); break;
            case "update":
                method = "PATCH";
                StringBuilder mask = new StringBuilder();
                for (String k : data.keySet())
                    mask.append(mask.length() == 0 ? "?" : "&").append("updateMask.fieldPaths=").append(urlenc(k));
                pathAndQuery = base + path + mask; jsonBody = wrapFields(data); break;
            case "add":
                method = "POST"; pathAndQuery = base + collection; jsonBody = wrapFields(data); break;
            case "delete":
                method = "DELETE"; pathAndQuery = base + path; break;
            default:
                method = "GET"; pathAndQuery = base + path;
        }

        sendViaProxy(method, pathAndQuery, token, jsonBody, op + " " + (path.isEmpty() ? collection : path));
    }

    /** Send an HTTPS request to Firestore through Burp's proxy (CONNECT tunnel + TLS). */
    private void sendViaProxy(String method, String pathAndQuery, String token, String jsonBody, String label) {
        Socket tunnel = null;
        SSLSocket ssl = null;
        try {
            tunnel = new Socket(PROXY_HOST, PROXY_PORT);
            tunnel.setSoTimeout(10000);
            OutputStream tout = tunnel.getOutputStream();
            InputStream tin = tunnel.getInputStream();

            tout.write(("CONNECT " + FS_HOST + ":443 HTTP/1.1\r\nHost: " + FS_HOST + ":443\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            tout.flush();
            String connectResp = readHeaders(tin);
            String statusLine = connectResp.split("\r\n", 2)[0];
            if (!statusLine.contains(" 200")) {
                api.logging().logToError("proxy CONNECT failed (" + statusLine + ") — is Burp's proxy on " + PROXY_HOST + ":" + PROXY_PORT + "?");
                return;
            }

            ssl = (SSLSocket) trustAll.createSocket(tunnel, FS_HOST, 443, true);
            ssl.startHandshake();
            OutputStream out = ssl.getOutputStream();

            StringBuilder req = new StringBuilder();
            req.append(method).append(' ').append(pathAndQuery).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(FS_HOST).append("\r\n");
            if (token != null) req.append("Authorization: Bearer ").append(token).append("\r\n");
            if (jsonBody != null) {
                byte[] bb = jsonBody.getBytes(StandardCharsets.UTF_8);
                req.append("Content-Type: application/json\r\n");
                req.append("Content-Length: ").append(bb.length).append("\r\n");
            }
            req.append("Connection: close\r\n\r\n");
            out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            if (jsonBody != null) out.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            out.flush();

            // drain so Burp records the full response
            InputStream sin = ssl.getInputStream();
            byte[] buf = new byte[8192];
            while (sin.read(buf) != -1) { /* discard */ }

            api.logging().logToOutput("-> proxy: " + method + " " + shortPath(pathAndQuery));
        } catch (Exception e) {
            api.logging().logToError("sendViaProxy [" + label + "]: " + e);
        } finally {
            try { if (ssl != null) ssl.close(); } catch (Exception ignored) {}
            try { if (tunnel != null) tunnel.close(); } catch (Exception ignored) {}
        }
    }

    // ---- small HTTP helper ----

    private static String readHeaders(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            buf.write(b);
            byte[] a = buf.toByteArray();
            int n = a.length;
            if (n >= 4 && a[n - 4] == '\r' && a[n - 3] == '\n' && a[n - 2] == '\r' && a[n - 1] == '\n') break;
            if (n > 65536) break;
        }
        return buf.toString("ISO-8859-1");
    }

    private SSLSocketFactory trustAllFactory() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{ new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            return ctx.getSocketFactory();
        } catch (Exception e) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    // ---- Firestore typed-value encoding (plain JSON -> {fields:{...}}) ----

    private String wrapFields(JsonObject data) {
        JsonObject root = new JsonObject();
        root.add("fields", encodeFields(data));
        return root.toString();
    }

    private JsonObject encodeFields(JsonObject data) {
        JsonObject fields = new JsonObject();
        for (Map.Entry<String, JsonElement> e : data.entrySet())
            fields.add(e.getKey(), encodeValue(e.getValue()));
        return fields;
    }

    private JsonObject encodeValue(JsonElement el) {
        JsonObject o = new JsonObject();
        if (el == null || el.isJsonNull()) {
            o.add("nullValue", JsonNull.INSTANCE);
        } else if (el.isJsonPrimitive()) {
            JsonPrimitive p = el.getAsJsonPrimitive();
            if (p.isBoolean()) {
                o.addProperty("booleanValue", p.getAsBoolean());
            } else if (p.isNumber()) {
                double d = p.getAsDouble();
                if (d == Math.floor(d) && !Double.isInfinite(d)) o.addProperty("integerValue", String.valueOf(p.getAsLong()));
                else o.addProperty("doubleValue", d);
            } else {
                o.addProperty("stringValue", p.getAsString());
            }
        } else if (el.isJsonArray()) {
            JsonArray values = new JsonArray();
            for (JsonElement e : el.getAsJsonArray()) values.add(encodeValue(e));
            JsonObject av = new JsonObject();
            av.add("values", values);
            o.add("arrayValue", av);
        } else if (el.isJsonObject()) {
            JsonObject mv = new JsonObject();
            mv.add("fields", encodeFields(el.getAsJsonObject()));
            o.add("mapValue", mv);
        }
        return o;
    }

    // ---- helpers ----

    private String projectFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;
            byte[] payload = Base64.getUrlDecoder().decode(padB64(parts[1]));
            JsonObject p = JsonParser.parseString(new String(payload, StandardCharsets.UTF_8)).getAsJsonObject();
            if (p.has("aud")) return p.get("aud").getAsString();
            if (p.has("iss")) {
                String iss = p.get("iss").getAsString();
                return iss.substring(iss.lastIndexOf('/') + 1);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String padB64(String s) {
        int m = s.length() % 4;
        return m == 0 ? s : s + "====".substring(m);
    }

    private static String str(JsonObject o, String k, String def) {
        return (o.has(k) && !o.get(k).isJsonNull()) ? o.get(k).getAsString() : def;
    }

    private static String urlenc(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static String shortPath(String p) {
        String[] s = p.split("/");
        return s.length <= 2 ? p : (".../" + s[s.length - 2] + "/" + s[s.length - 1]);
    }
}
