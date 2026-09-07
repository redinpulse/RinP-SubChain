# RinP SubChain

> **rinp-subchain**

Subdomain chaining audit under a controlled-subdomain hypothesis. Answer one question before an engagement: **if I controlled one subdomain of the victim's registrable domain, what would chain across the parent?**

The idea: browser origin isolation is strong, but cookie scoping, CSP trust and CORS are domain-aware. A single controlled subdomain (a real takeover, a forgotten DNS record, a delegated service) turns into parent-domain impact when siblings leak these primitives:

```
                    ┌─ Domain=.victim.com cookies ──► sent to YOUR subdomain (HttpOnly too)
victim.com ──────── ├─ CSP *.victim.com in script-src ──► your host is a trusted script source
   siblings ─────── ├─ CORS reflecting your origin + credentials ──► authenticated reads
                    └─ no frame-ancestors ──► iframe + postMessage probing
```

## Chaining classes

| Label | Meaning |
|---|---|
| `RECEIVABLE` | Cookie set with `Domain=.victim.com` (or `Domain=victim.com`) is sent to every subdomain, including yours. `HttpOnly` does not help the victim: the cookie rides on requests to your host, capture it server-side. |
| `TOSSABLE` | You can overwrite or fixate it by setting the same name with `Domain=victim.com` from your subdomain. `__Secure-` prefixed variants need your host on https; `__Host-` prefixed ones cannot be tossed. |
| `SHADOW` (host-only) | Cookie without a `Domain` attribute never reaches you, but you can still inject a same-name Domain-wide cookie; servers that parse first/last occurrence may read yours. |
| `TRUSTED-<directive>` | CSP source list containing `*.victim.com` (or `*`) admits your host: script/object sources become loadable, form-action/connect-src accept your endpoints, frame-ancestors allows embedding. |
| `CORS-CREDENTIALED` / `CORS-OPEN` | `Access-Control-Allow-Origin` reflects your subdomain's origin (with credentials) or is `*`. |
| `FRAMABLE` | No `X-Frame-Options` and no `frame-ancestors`: embed the sibling in an iframe from your subdomain and probe `postMessage` listeners. |

Technical notes encoded in the report: `SameSite=Strict/Lax` do **not** protect subdomain-to-subdomain traffic, because every `*.victim.com` host is the same site (schemeful same-site caveat: an `http://` controlled host is cross-site to `https://` siblings). The protections that actually matter intra-domain are host-only cookies and `__Host-` prefixes.

## Verified against a real browser

Every chain class was proven end-to-end in Chromium against a local lab (`*.localtest.me`), not just by header parsing:

- **Full data exfiltration**: with the app's CSP allowing the wildcard, a script served from the controlled subdomain executed inside the app origin and beamed to the attacker's server: readable cookies, a localStorage JWT, DOM contents and a same-origin API response including an API key. This is the phishing-to-data proof: the victim's browser itself delivers the target application's data.
- **HttpOnly is no protection here**: the session cookie was invisible to `document.cookie` yet arrived intact in requests to the controlled subdomain (captured server-side).
- **SameSite=Strict did not block** subdomain-to-subdomain delivery (same site, one eTLD+1).
- **Tossing worked**: a `Domain=.victim` cookie set from the controlled subdomain replaced the app's session value; shadowing sent both the host-only original and the attacker's Domain-wide cookie to the app.
- **`__Host-` was rejected** by the browser when it arrived with a `Domain` attribute; `__Secure-` tossing requires https.
- **postMessage**: the controlled origin framed an unprotected sibling (`FRAMABLE`) and received the listener's secret with a single message.

Empirical CSP port rule (Chromium): a host-source without a port part matches only the scheme's default ports. `*.victim.com` therefore trusts your subdomain on 443, but not on `:8443`, unless the policy lists that port or `:*`. The recon report annotates portful sources and downgrades `strict-dynamic` policies, where CSP3 ignores host allowlists entirely. Deep-scoped cookies (`Domain=www.victim.com`) are reported as `SCOPED-DEEPER`: outside your subdomain's reach, but still shadowable with a Domain-wide cookie (observed in the wild: Cloudflare's `__cf_bm`).

## Usage

**recon**: audit a provided list of sibling subdomains (no discovery, keep scope tight) against a hypothetical controlled host:

```sh
python3 subchain.py recon --domain victim.com \
    --controlled assets.victim.com --list subdomains.txt --json report.json
```

`subdomains.txt` is one host per line (`#` comments allowed, `host:port` accepted). The tool fetches each sibling twice (plain, then with an `Origin: https://<controlled>` header to test reflection) and prints a per-host report plus a chain summary. Only GET requests are issued.

**serve**: cookie-capture server to deploy behind your controlled subdomain, plus a toss helper for fixation tests:

```sh
python3 subchain.py serve --domain victim.com --port 8080 --out captured.jsonl

# every request is logged with its full Cookie header (JSONL + console)
# toss a Domain-wide cookie from the browser/tool of your choice:
curl "https://<your-subdomain>:8080/toss?name=session&value=fixated"
# -> Set-Cookie: session=fixated; Domain=victim.com; Path=/; Secure
```

## Limitations

- Header-based audit: JavaScript-issued cookies, OAuth `redirect_uri` patterns and `postMessage` handlers need manual follow-up (the FRAMABLE/CORS labels tell you where to look).
- Redirect chains are followed, but `Set-Cookie` headers on intermediate hops are not retained.
- Authenticated areas (behind login) are invisible to an unauthenticated fetch; rerun recon from an authenticated session when in scope.

## References & credits

The chaining methodology stands on published research and field writeups:

- [Can I Take Your Subdomain? Related-Domain Attackers in Modern Browsers](https://arxiv.org/abs/2012.01946) (Squarcina et al., ACM CCS 2021): the related-domain attacker model and measurement methodology behind the tool's classes
- [Cookie Crumbles: Breaking and Fixing Web Session Integrity](https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina) (USENIX Security 2023): cookie tossing, shadowing and prefix analysis
- [Hijacking OAuth Flows via Cookie Tossing](https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/) (Snyk Labs) and the [Zoom session takeover](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html) writeup: path-precedence tossing in the wild
- [Flarum GHSA-hg9j-64wp-m9px](https://github.com/flarum/framework/security/advisories/GHSA-hg9j-64wp-m9px): a real session hijack via authoritative subdomain cookie overwrite
- [Reading CSPs Like an Attacker](https://medium.com/@marduk.i.am/reading-csps-like-an-attacker-dbe162f2594e): wildcard `script-src` and dangling DNS

The browser-verified chain walkthrough behind this tool is documented on our blog: <https://redinpulse.com/en/blog>.

## Try it in the lab

The repository ships the lab itself, so you can live the chain in your own browser instead of trusting screenshots: a victim dashboard (`app.localtest.me`), a naive sibling (`victim2.localtest.me`) and your controlled subdomain (`evil.localtest.me`) with an interactive attacker console: live capture of what the browser sends you, toss/shadow/`__Host-` buttons, a CSP variant switcher and a postMessage playground. Everything runs on `*.localtest.me` (public DNS for 127.0.0.1), stdlib only:

```sh
python3 lab/server.py
```

Follow [lab/GUIDE.md](lab/GUIDE.md): eight steps that verify every report label by hand, ending with the data-exfiltration proof.

## Disclaimer

Published for **educational purposes and authorized red-team engagements only**. Use exclusively against systems and domains you have written permission to test. The authors accept no liability for any misuse.

## License

MIT, see the [LICENSE](LICENSE) file. By **Red in Pulse — Mr.Gedik** (<https://redinpulse.com>).
