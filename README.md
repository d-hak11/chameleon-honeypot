# chameleon-honeypot

An adaptive web honeypot built for my MSc dissertation. Caddy fronts four static
nginx personas (a Moodle VLE, a student registry, a finance portal, and a research
portal), and a Python engine reads the access log, classifies each visitor's
session, and rotates which persona is served at runtime.

A custom Caddy module can also hold responses back by a realistic delay. That was
the original research question: do scanning tools react differently to induced
latency in a way that reveals how invested they are? The short answer is not
usefully. The finding, and why, is in the dissertation.

It is deliberately not high-interaction. The personas are content-free static
sites with nothing real behind them, so there is nothing to compromise. Everything
runs in Docker. The engine and analysis are stdlib Python; the proxy modules are
Go, built into the image with xcaddy.

---

## Quickstart (local)

**Prerequisites**

- Docker with Compose (I run it under WSL2 with Docker Desktop, WSL integration on)
- Python 3 on the host. The engine, feature extractor and self-tests are stdlib only.
- Go, only to run the proxy module tests outside Docker. The image builds them with xcaddy.
- Terraform and the AWS CLI, only for deploying to EC2.

**Run it**

```sh
make salt     # once: writes secrets/source_salt.env (gitignored)
make up
make check    # brings it up, then runs the give-away scan and coherence check
```

The proxy comes up on <http://localhost:8080>. If `make check` passes, you're running.

**Everyday commands**

```sh
make switch P=finance   # force a persona: moodle | registry | finance | research
make engine-test        # engine self-test (host Python)
make extract-test       # feature-extractor self-test (host Python)
make engine-logs        # tail the engine
make attack-start       # attacker container, for generating traffic
make trap-secret        # rotate trap cookie secret and recompute nginx MACs together
make down
```

The classifier analysis needs scikit-learn, which deliberately never goes in the
engine image. Run it in a throwaway container instead:

```sh
docker run --rm -v "$PWD":/work -w /work python:3.11-slim \
  sh -c "pip install -q scikit-learn pandas numpy && \
         python3 analysis/rf_analysis.py generation/stage4_labelled.csv"
```

Proxy module tests run outside Docker:

```sh
cd proxy/timingprobe && go test ./...   # likewise for sourcehash and traps
```

---

## Repository layout

| Path | What's in it |
| --- | --- |
| `proxy/` | Caddy config and three Go modules (`timingprobe`, `sourcehash`, `traps`). `caddy.json` is the live config and single source of truth; it is rewritten on every switch. |
| `personas/<name>/` | `conf/nginx.conf`, the `static/` site, and `manifest.yml` (what the persona claims to be: stack, timing range, traps). |
| `engine/` | The loop: tail, sessionise, classify, policy, actuate. |
| `analysis/` | Feature extraction, classifier training and evaluation, live labelling. |
| `generation/` | Controlled attack generation, manifest-driven, with `tc netem` network profiles. |
| `attack/` | The attacker image. `attack/docs/` is the research record (see the end). |
| `tools/` | Quality gates, persona switching, observation scripts. |
| `terraform/` | EC2 deployment. |
| `evidence/` | Captured reference material the Moodle persona was built from. |

---

## How the engine works

It tails `/var/log/caddy/access.json`, groups requests into sessions by
pseudonymised source, and classifies each with a RandomForest trained on content
features only. The model lives in `engine/models/` and is walked in pure Python by
`rf_inference.py`, which is what keeps scikit-learn out of the container entirely.
A switch is a POST of the rewritten config to Caddy's admin API `/load`, with no
restart and no dropped connections.

It fails open: if the engine dies, Caddy keeps serving whatever persona was last
loaded. The proxy never depends on the engine.

**Two things to know before editing it:**

- `engine/content_features.py` must stay byte-identical to
  `analysis/extract_features.py`, rounding included. `analysis/test_feature_parity.py`
  enforces this, and it has caught real drift.
- `classify_rules()` is the old rule-based classifier. It is kept because it was the
  one live during the 7 to 18 September 2026 collection, so it is the reference the
  RandomForest is measured against.

All engine settings are environment variables, listed with defaults in
`engine/config.py`.

---

## What gets switched, and when

Every 10 seconds the engine classifies each active session and decides whether to
move Caddy to a different persona. The logic is in `engine/policy.py` and the loop
in `engine/main.py`.

### What triggers what

The RandomForest labels each session as `broad_scanning`, `indexing`,
`active_backend_testing`, or `insufficient_data`. The labels are checked in this
order, and the first one seen in any current session wins:

| Seen in any current session | Action |
| --- | --- |
| `active_backend_testing` | Hold the current persona. This wins over everything else, so a source probing the backend is never disturbed. |
| `indexing` | Rotate to a random persona other than the current one. |
| `broad_scanning` | Rotate the same way. |
| `insufficient_data` or nothing | No switch. Once the site has been quiet for `QUIET_SETTLE` (600 s), restore `moodle`. |

The rotation pool is `moodle`, `registry`, `finance`, `research`, and `moodle` is
the default face.

Holding on `active_backend_testing` is the case that matters most: a source doing
sustained backend testing has committed to this surface, and rotating would end the
interaction the honeypot exists to observe. There the most useful output is the
instruction not to change.

### When a switch can actually happen

A classification does not rotate the persona on its own. Four gates apply:

- **Dwell.** No switch within 45 s (`SWITCH_DWELL`) of the last one, so the
  honeypot cannot oscillate between identities.
- **No mid-session changes.** If any source sent a request in the last 15 s
  (`ACTIVE_GRACE`), the rotation is queued rather than applied, and fires on the
  first tick when nobody is active. The queued target is recalculated every tick,
  so a stale decision never goes through. This is what stops a single source from
  watching the served identity change underneath it, the most obvious possible tell.
- **Own traffic ignored.** Private and loopback sources, plus anything in
  `EXCLUDE_IPS`, are never classified as attackers.
- **Health check.** The actuator only switches to a persona container that
  responds. If the chosen one is down it tries the others; if Caddy's admin API
  rejects the new config, the config file is rolled back and the persona stays put.

### The switch itself

The engine rewrites three fields in `proxy/caddy.json` together (the persona
upstream, the persona log field, and the timing-probe persona), then POSTs the file
to Caddy's `/load`. All three change as one unit, because a half-applied switch is
exactly the inconsistency fingerprinting looks for.

### One quirk worth knowing

The quiet timer only restarts on `indexing` or `active_backend_testing` (the
`HOSTILE` set in `engine/classify.py`), not on `broad_scanning`. So a rotation
caused only by broad scanning is typically undone on the first calm tick after the
45 s dwell, rather than being held for the full `QUIET_SETTLE` period. This is
consistent with broad scanning being the lowest-commitment class: it is worth
showing a fresh face to, but not worth holding that face for. If broad scanning
should instead hold the rotated persona for the full quiet period, add it to
`HOSTILE`.

---

## Adding a persona

The four personas share one set of routing, logging and trap wiring, so a new one
has to plug into all of it. Four steps.

### 1. Build the static site

Create `personas/<name>/` with `conf/nginx.conf`, a `static/` tree (index, login,
403/404/500 pages, `robots.txt`, `sitemap.xml`, favicon, theme assets), and a
`manifest.yml`. Keep it content-free: static pages, no real application, no real
vulnerability. All persona identity lives in the nginx config, not in Caddy.

### 2. Fill in the manifest

`manifest.yml` declares what the persona claims to be: server stack, headers,
cookie name and format, brand, and a `timing:` block with a `verified` flag. Set
`verified: true` only if the timing was measured from a real instance with
`tools/observe.sh`; otherwise leave it `false` and treat probe data from that
persona with that in mind.

### 3. Wire it into the switch

Three fields change together on every rotation:

- the `reverse_proxy` upstream dial in `caddy.json`
- the `persona` `log_append` value
- the `timing_probe` `persona`

`engine/actuate.py` and `tools/switch_caddy.py` already update all three as one
unit. Add the new persona to the set they know about; do not wire a fourth field by
hand.

### 4. Pass the gates

`make check` will not deploy it until both gates pass:

- `tools/give_away_scan.py` finds no honeypot or study vocabulary anywhere under
  `static/` (the bare word "research" is allowed, since it is the research persona's
  own name)
- `tools/coherence_check.py` confirms every exposed indicator belongs to this one
  persona and no other

---

## Personas

| Persona | Brand | Cookie | Basis |
| --- | --- | --- | --- |
| `moodle` | Greenwood College | `MoodleSession` | **Measured.** Boost theme tokens captured from the 4.5 sandbox with `tools/observe.sh` (see `evidence/`). |
| `registry` | Greenwood Student Records | `SISESSION` | **Designed.** Real SIS products are licence-gated, so there is nothing public to observe. |
| `finance` | Greenwood Finance Portal | `FIN_SESSION` | **Designed.** Real portals sit behind auth and a WAF. |
| `research` | Greenwood Research Portal | `RES_SESSION` | **Designed.** Same reason. |

All brands are fictional; all artwork and copy are original. The personas are
deliberately content-free static sites, which is why crawling tools find almost
nothing to follow, and part of why they look so different from real traffic.
"Designed" personas get invented trap identifiers; `moodle` is meant to carry only
observed ones (see `attack/docs/part3-traps.md`). Its `MOODLE_PREF` cookie trap is
the one open exception, logged as N1 in the code review.

---

## Deploying

```sh
cd terraform
terraform apply          # default workspace = the live collection instance
```

Controlled generation uses its own workspace and bucket:

```sh
terraform workspace select stage4-gen
terraform apply -var-file=stage4-gen.tfvars
```

The stack ships to the instance as a zip via S3, so the box holds no git
credentials. The live instance serves plain HTTP on `:80` with no TLS. The
reasoning, that a self-signed certificate is a worse fingerprint than none, is in
`attack/docs/DESIGN_NOTES.md`.

---

## Troubleshooting

| Symptom | Look at | Likely fix |
| --- | --- | --- |
| `make check` fails on the give-away scan | its output naming the file and term | Something under `static/` reads as honeypot or study vocabulary. "research" is allowed; anything else has to go. |
| `make check` fails on coherence | `tools/coherence_check.py` output | An indicator on one persona (header, cookie name, brand, 404) matches another. Each persona must be internally consistent. |
| Every visitor looks like they tampered with the cookie | | The trap secret was rotated without recomputing the nginx MACs. Always use `make trap-secret`, which does both. |
| Persona switches don't take effect | `make engine-logs` | The engine POSTs to Caddy's admin API; if it cannot reach `/load`, check the admin API is up on the internal network (it must never be published to the host). |
| Timing probe never fires | `probe_rate` in the engine env | It defaults to `0.0` (inert) and was `0.0` for the whole live deployment. Set it above zero to enable; it still never probes a session's first three requests. |
| Feature-parity test fails | `analysis/test_feature_parity.py` | `content_features.py` and `extract_features.py` have drifted; they must compute identically, rounding included. |
| Engine crashes | `make engine-logs` | Caddy keeps serving the last-loaded persona regardless. The proxy never depends on the engine, so collection continues while you debug. |

---

## Hard rules

- **Never give Caddy's admin API (`:2019`) a `ports:` entry.** It stays on the
  internal Compose network. Publishing it is handing out remote control of the
  honeypot.
- The source salt and trap secret never go in git. `proxy/caddy.json` is tracked,
  so neither ever lives in it.
- Do not rotate the trap secret without recomputing the nginx cookie MACs.
  `make trap-secret` does both at once.
- Do not reorder the four probe `log_append` handlers relative to `timing_probe` in
  `caddy.json`. The ordering is what lets them read the values the module sets, and
  it keeps the JSON types native.

---

## Research record

`attack/docs/` is the paper trail behind the dissertation, not clutter:

- `DEVELOPMENT_RECORD.md`, the development log
- `DISSERTATION_FACTS.md`, the verified numbers used in the write-up
- `SYSTEM_OVERVIEW.md`, the systematic explanation of the whole system
- `DESIGN_NOTES.md`, design rules and their rationale
- `part3-traps.md`, the honeytrap design
- `annotation_rubric.md`, the live-session labelling instrument
- the September 2026 code review

These are the dissertation's methodological evidence, so they stay.
