# Evidence: Moodle platform signature (Phase 1)

Captured from real public Moodle deployments on 2026-08-16 to ground the
persona in observed reality rather than invented values (per the project
record: "copying observed reality beats inventing plausible values").

## Sources

| Host | Deployment | What it shows |
|---|---|---|
| `sandbox.moodledemo.net` | Official Moodle demo, **nginx behind** | Clean, minimally-proxied Moodle response headers + full login page structure |
| `moodle.uclouvain.be` | UCLouvain, **Apache/Debian** | Themed Moodle 404 page; Apache variant; load-balancer cookie |
| `elearning.unimib.it` | UNIMIB, Apache | Themed Moodle 404; favicon served via `pluginfile.php` |
| `moodle.hw.ac.uk` | Heriot-Watt | Confirms no custom `robots.txt` |

`moodle.org` (the site named in the Phase 1 plan) is fronted by Cloudflare and
returns a bot-mitigation challenge for non-browser UAs, so it is unusable as
evidence. The official demo sandbox was used instead.

## Moodle-invariant response headers (present on two different stacks)

Observed on both the nginx sandbox and the Apache UCLouvain host, so these are
reliable persona indicators:

```
content-language: en
content-script-type: text/javascript
content-style-type: text/css
x-ua-compatible: IE=edge
cache-control: no-store, no-cache, must-revalidate, no-transform
pragma: no-cache
expires: Mon, 20 Aug 1969 09:23:00 GMT
accept-ranges: none
x-frame-options: sameorigin
set-cookie: MoodleSession=<token>; path=/
content-type: text/html; charset=utf-8
```

## Session cookie

`MoodleSession` is the canonical Moodle session cookie. Values observed were
32 lowercase hex characters (`6c622e7447640f5e831fbfa339b48efc`) on the sandbox,
and a short lowercase token on the Apache host. The persona uses the 32-hex
form. The nginx backend generates it per request via `$request_id` (nginx
produces 32 hex characters), which is both the right shape and unique per
request, matching real Moodle's no-store, per-request session behaviour.

## Platform (`Server`) header

Real Moodles genuinely run on nginx *and* Apache. The official sandbox reports
just `nginx` (version hidden); UCLouvain reports `Apache/2.4.67 (Debian)`.
Decision: the persona presents as a Moodle behind **nginx** and reports
`Server: nginx` with the version hidden (`server_tokens off`). This is coherent,
not a giveaway. The real giveaway in Phase 0 was `Via: 1.1 Caddy`, which no
stock Moodle would emit; that is stripped at the proxy layer.

## Things deliberately NOT copied

- **`SERVERID=lmsf-5`** (UCLouvain). This is a load-balancer backend cookie, an
  operator-specific artifact that varies between hosts. Copying it could help
  fingerprinting against a specific cluster and adds no Moodle signal.
- **Matomo/analytics tags** (UCLouvain). Real deployments vary; the persona
  stays content-free.
- **Moodle icons/artwork**. The favicon is original SVG artwork in a
  Moodle-like style, to avoid reproducing Moodle's copyrighted assets.

## Error pages

Real Moodle installs serve a *themed* error page for unknown paths: UCLouvain
and UNIMIB returned their Moodle-themed 404 (with `<html dir="ltr" lang=...>`,
`<meta name="keywords" content="moodle, ...">`, a `pluginfile.php` favicon
reference) rather than the web server's default. The persona implements themed
403/404/500 pages in the same style. (The official sandbox returned its nginx
default 404 for unknown paths, so themed-not-default is a real-Moodle behaviour,
just with deployment variability.)

## robots.txt

None of the four real hosts served a custom `robots.txt` (all returned 404
for `/robots.txt`). However the methodology lists `robots.txt` as part of a
persona bundle and many managed Moodles do ship one. Decision: the persona
serves a conservative, standard Moodle-style `robots.txt` (disallow admin and
management areas, allow public course catalogue). This is documented here so
the choice is transparent: it is a convention applied to the persona, not a
literal capture.

## Syntax of real login form (from the demo sandbox)

```html
<form class="login-form" action="https://.../login/index.php" method="post" id="login">
  <input type="hidden" name="logintoken" value="...">         <!-- CSRF token -->
  <input type="text" name="username" id="username" class="form-control" value=""
         placeholder="Enter your username" autocomplete="username">
  <input type="password" name="password" id="password" value=""
         class="form-control" placeholder="Enter your password" autocomplete="current-password">
  ...
</form>
<form action="https://.../login/index.php" method="post" id="guestlogin">
  <input type="hidden" name="username" value="guest">
  <input type="hidden" name="password" value="guest">
```

The login page also contains the Moodle marker sentence "You are not logged in.",
which the persona reproduces.
