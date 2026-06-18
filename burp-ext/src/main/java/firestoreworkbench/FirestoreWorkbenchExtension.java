package firestoreworkbench;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Firestore Workbench — Burp extension.
 *
 * Listens for capture events from firestore_agent.js (the Frida agent) on a local
 * socket, builds the equivalent Firestore REST request (with the captured Bearer
 * token), and drops it into Burp Repeater. No separate GUI, no proxy plumbing.
 *
 * Uses a plain ServerSocket (not com.sun.net.httpserver, which Burp's extension
 * classloader doesn't expose).
 */
public class FirestoreWorkbenchExtension implements BurpExtension {

    private static final int PORT = 8799;
    private static final String FS = "https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s";

    private MontoyaApi api;
    private ServerSocket serverSocket;
    private volatile boolean running = true;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Firestore Workbench");

        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("0.0.0.0", PORT));
            Thread t = new Thread(this::acceptLoop, "fs-workbench-listener");
            t.setDaemon(true);
            t.start();
            api.logging().logToOutput("Firestore Workbench: listening on http://0.0.0.0:" + PORT + "/api/capture");
            api.logging().logToOutput("Point firestore_agent.js WB_HOST/WB_PORT here; captures land in Repeater.");
        } catch (Exception e) {
            api.logging().logToError("Failed to start capture listener on port " + PORT + ": " + e);
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

    /** Minimal HTTP/1.1 read: headers until CRLFCRLF, then Content-Length bytes; reply 200. */
    private void handle(Socket sock) {
        try {
            sock.setSoTimeout(5000);
            InputStream in = sock.getInputStream();
            OutputStream out = sock.getOutputStream();

            ByteArrayOutputStream hbuf = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != -1) {
                hbuf.write(b);
                byte[] a = hbuf.toByteArray();
                int n = a.length;
                if (n >= 4 && a[n - 4] == '\r' && a[n - 3] == '\n' && a[n - 2] == '\r' && a[n - 1] == '\n') break;
                if (n > 65536) break;
            }
            String headers = hbuf.toString("ISO-8859-1");

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
            String head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + resp.length + "\r\nConnection: close\r\n\r\n";
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            out.write(resp);
            out.flush();
        } catch (Exception e) {
            if (running) api.logging().logToError("handle: " + e);
        } finally {
            try { sock.close(); } catch (Exception ignored) {}
        }
    }

    /** Build the REST request for one capture and send it to Repeater. */
    private void process(JsonObject c) {
        String op = str(c, "op", "get");
        if ("auth".equals(op)) return; // token-only beacon, nothing to replay

        String token = str(c, "token", null);
        String project = str(c, "project", null);
        if (project == null && token != null) project = projectFromJwt(token);
        if (project == null) {
            api.logging().logToError("no project id (and none derivable from token); skipping " + str(c, "path", ""));
            return;
        }

        String path = str(c, "path", "");
        String collection = str(c, "collection", path);
        JsonObject data = (c.has("data") && c.get("data").isJsonObject())
                ? c.getAsJsonObject("data") : new JsonObject();

        String method;
        String url;
        String jsonBody = null;

        switch (op) {
            case "set":
                method = "PATCH";
                url = String.format(FS, project, path);
                jsonBody = wrapFields(data);
                break;
            case "update":
                method = "PATCH";
                StringBuilder mask = new StringBuilder();
                for (String k : data.keySet())
                    mask.append(mask.length() == 0 ? "?" : "&").append("updateMask.fieldPaths=").append(urlenc(k));
                url = String.format(FS, project, path) + mask;
                jsonBody = wrapFields(data);
                break;
            case "add":
                method = "POST";
                url = String.format(FS, project, collection);
                jsonBody = wrapFields(data);
                break;
            case "delete":
                method = "DELETE";
                url = String.format(FS, project, path);
                break;
            default:
                method = "GET";
                url = String.format(FS, project, path);
        }

        HttpRequest req = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        if (token != null) req = req.withAddedHeader("Authorization", "Bearer " + token);
        if (jsonBody != null) req = req.withAddedHeader("Content-Type", "application/json").withBody(jsonBody);

        String label = "fs:" + op + " " + shortPath(path.isEmpty() ? collection : path);
        api.repeater().sendToRepeater(req, label);
        api.logging().logToOutput("-> Repeater [" + label + "]");
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
