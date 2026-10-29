# CyberStrikeAI — Security Audit

**Date:** 2026-10-29
**Target:** `popcrocks/CyberStrikeAI` @ branch `claude/hopeful-wright-gztymi` (commit `5affb4d`)
**Method:** Multi-agent audit across 11 attack surfaces; every candidate finding independently, adversarially re-verified against the actual code before being reported.

---

## 0. The headline you asked about first: PHP

**This application contains zero PHP.** It is **803 Go files** (Go 1.25, module `cyberstrike-ai`), a Go-template + vanilla-JS web dashboard, a small Java Burp plugin, and ~2 Python helper files. There is no PHP interpreter, no `.php`/`.phtml`, no `composer.json`, no templating engine that evaluates PHP.

Therefore **no PHP CVE and no "php2shell"-style vulnerability can apply here** — the attack surface they target does not exist in this stack. I audited the stack that *is* here instead.

## 1. Honest bottom line

I did not find — and I will not invent — an unauthenticated remote-code-execution "0-day," a remote data-exfiltration critical, or a magic one-shot takeover. **This codebase is, on the whole, unusually well-defended** (see §6 for the controls I verified as solid). Manufacturing a fake "critical" would be worse than useless: it would send you chasing a phantom while the real issues below go unfixed.

What I *did* find is **one genuinely important product-logic flaw in the AI trust boundary**, a **cluster of real unauthenticated denial-of-service issues sharing one root cause**, a set of **defense-in-depth gaps**, and **several stale dependencies with known CVEs**. These are real, verified, and worth fixing — rated at their true severity, not inflated.

| # | Severity | Verdict | Finding | Location |
|---|----------|---------|---------|----------|
| 1 | **HIGH** | CONFIRMED | HITL approval gate permanently exempts `write_file`, and the filesystem backend is rooted at `/` → an injected LLM/MCP can write any file with no human approval | `internal/multiagent/hitl_toolsearch_compat.go:19` |
| 2 | **HIGH** | CONFIRMED | Rate limiter bypassable via spoofed `X-Forwarded-For` (no trusted-proxy config) + no account lockout → unauth bcrypt CPU-exhaustion DoS & unthrottled guessing | `internal/security/ratelimit.go:72`, `internal/app/app.go:91` |
| 3 | **HIGH** | CONFIRMED | `golang.org/x/net v0.53.0` HTTP/2 server DoS cluster (GO-2026-6617/6612/6611/6603), unauth, when TLS is enabled | `internal/app/app.go:728` (`go.mod`) |
| 4 | MEDIUM | CONFIRMED | No anti-clickjacking / security headers; the auto-authenticating dashboard is framable | `internal/app/app.go:94` |
| 5 | MEDIUM | CONFIRMED | Main HTTP listener has no read/write/idle timeouts → Slowloris, unauth, default `0.0.0.0:8080` | `internal/app/app.go:723` |
| 6 | MEDIUM | PLAUSIBLE | SSRF via LLM connectivity-test endpoints (arbitrary `base_url`, no allowlist, response reflected) | `internal/handler/config.go:1296` |
| 7 | MEDIUM | PLAUSIBLE | `audit_agent` LLM-judge auto-approval is prompt-injectable via the arguments it judges | `internal/handler/hitl_audit_agent.go:145` |
| 8 | MEDIUM | PLAUSIBLE | Bundled SheetJS 0.18.5 parses untrusted uploads (CVE-2023-30533 proto-pollution, CVE-2024-22363 ReDoS) — client-side | `web/static/js/assets.js:272` |
| 9 | LOW | CONFIRMED | Username enumeration via login-response timing (bcrypt only runs for existing users) | `internal/security/auth_manager.go:133` |
| 10 | LOW | CONFIRMED | No request body-size limit; unauth `/api/auth/login` reads an unbounded JSON body | `internal/handler/auth.go:54` |
| 11 | LOW | PLAUSIBLE | Masked provider API-key exfiltration via `credential_scope` + arbitrary `base_url` (config:write-gated) | `internal/handler/config_secrets.go:146` |
| 12 | LOW | PLAUSIBLE | Argv/option injection via the tool `template` param (`strings.Fields` word-split) | `internal/security/executor.go:497` |
| 13 | LOW | PLAUSIBLE | Terminal/C2 WebSocket `CheckOrigin` returns `true` (dormant CSWSH; cookie auth not currently used) | `internal/handler/terminal_ws_unix.go:26` |
| 14 | LOW | PLAUSIBLE | Auto-update allows cleartext (`http://`/`git://`) sources & verifies no signature (admin-gated) | `internal/update/update.go:60` |
| 15 | LOW | PLAUSIBLE | Stale deps: `x/image` (2019), `modelcontextprotocol/go-sdk v1.3.1`, DOMPurify 3.0.8 | various |
| 16 | LOW | (unverified) | C2 HITL approval bridge fails **open** on a missing interrupt row (latent) | `internal/app/c2_hitl_bridge.go:119` |
| 17 | INFO | PLAUSIBLE | Dormant weak legacy SHA-256 password-verify branch (dead code) | `internal/security/rbac.go:106` |
| 18 | INFO | PLAUSIBLE | Fail-open asset/vuln list filter on empty `UserID` (not currently reachable) | `internal/database/vulnerability.go:99` |

**Refuted (correctly — reported by a scanner but *not* exploitable):** tool-argv option injection via `additional_args` (redundant with intended passthrough), external-MCP URL SSRF (gated by `mcp:write`+global scope), c2.js error-string XSS (server-controlled value), `x/text` infinite-loop CVE (loop not reachable), OpenTelemetry CVE cluster (dead code, no callers).

---

## 2. Detailed findings

### 🔴 #1 — HIGH — HITL approval gate permanently exempts `write_file` (the one that matters most)

**This is the most significant finding** because it defeats the platform's core promise — "governed execution, human oversight" — inside the exact scenario that promise exists for.

- `write_file` is hard-coded into `HitlExemptMetaTools` (`internal/multiagent/hitl_toolsearch_compat.go:19`) alongside genuine orchestration tools (`tool_search`, `task`, `exit`, …).
- That exempt list is **always** merged into the runtime sensitive-tools whitelist (`hitlRequestWithMergedConfigWhitelist`, `internal/handler/hitl.go:336-362`), so `shouldInterrupt` always takes the "not sensitive" branch for `write_file` and `waitHITLApproval` returns "approved" with **no human prompt and no `audit_agent` review** — *before* the reviewer branch runs.
- The filesystem backend is constructed with `localbk.NewBackend(ctx, &localbk.Config{})` — **no root jail, no command validator** (`internal/multiagent/eino_skills.go:36`); the eino-ext local `Write` only does `filepath.Clean` then `os.OpenFile` on any absolute path.
- Note the asymmetry: `edit_file` and `execute` **are** HITL-gated. Only `write_file` slips through — so an attacker-steered model simply prefers `write_file`.

**Attack path (`malicious MCP / prompt-injected LLM`):** With HITL enabled + a reviewer (the operator's explicit "review dangerous actions" posture) and `skills_dir` configured, untrusted content the platform is *designed* to ingest — a scanned target's HTTP banner, a malicious external-MCP tool result, or a prompt-injected model response — instructs the agent to call `write_file` instead of `execute`/`edit_file`. No approval is shown to the human **or** the audit agent, and the write lands anywhere the service user can write. Escalations as the service user: overwrite the app's own `config.yaml` to register a malicious stdio-MCP command or weaken HITL/toolguard for next restart; drop a payload into a served web root; append to `~/.ssh/authorized_keys`.

**Fix:** Remove `write_file` (and any other host-touching entry) from `HitlExemptMetaTools` — keep only true orchestration/meta tools. If an internal repair path needs scratch persistence, give it a *non-model-callable* write primitive scoped to a temp dir. Independently (defense-in-depth): construct the local backend with a jailed per-conversation/project workspace root + a path/command validator so `write_file`/`edit_file`/`execute` can never reach `~/.ssh`, `/etc`, web roots, or the app's own config even when approved.

---

### 🔴 #2 — HIGH — `X-Forwarded-For` rate-limit bypass + no account lockout → unauth DoS

Root cause: the router is `gin.Default()` (`app.go:91`) and **`SetTrustedProxies` / `ForwardedByClientIP` / `TrustedPlatform` are never configured anywhere in the repo.** Gin therefore trusts `0.0.0.0/0`, so `c.ClientIP()` (`ratelimit.go:72`) returns the attacker-supplied leftmost `X-Forwarded-For` value — verified against the gin v1.9.1 source. Rotating that header per request lands every request in a fresh bucket, defeating the 10/min login and 60/min robot limiters with a single host.

There is also **no per-account lockout** (`auth_manager.go:140` just returns an error; `handler/auth.go` only audit-logs). Because `Authenticate` runs `bcrypt.CompareHashAndPassword` (cost 10) for any enabled username (and `admin` always exists), an unauthenticated flood of `username=admin` forces unbounded concurrent bcrypt work → **CPU-exhaustion DoS**, with no concurrency cap.

> Online brute-force of the *default admin* specifically remains infeasible — the bootstrap password is a 24-char (~144-bit) `crypto/rand` secret. The real impact is the CPU DoS, the removal of the only anti-brute-force control (dangerous for any weak operator-set/secondary password; the change-password minimum is only 8 chars), and the fact that the same XFF trust undermines every other IP-keyed control.

**Fix:** `router.SetTrustedProxies(nil)` (or the real proxy CIDRs) so `ClientIP()` ignores `X-Forwarded-For`; add a per-**account** failed-attempt lockout/backoff; bound concurrent bcrypt verifications with a semaphore; use a constant-cost dummy bcrypt compare for unknown/disabled users (also fixes #9).

---

### 🔴 #3 — HIGH — `golang.org/x/net v0.53.0` HTTP/2 server DoS cluster

`go.mod` pins `golang.org/x/net v0.53.0`. When TLS is enabled, `app.go:728` installs `x/net/http2` as the ALPN h2 handler (`http2.ConfigureServer(srv, &http2.Server{})`), so HTTP/2 framing runs in `x/net`'s own `ServeConn` loop — **upstream of Gin and auth middleware.** `govulncheck` (run by the auditor) reports **symbol-level** reachability through that exact line for **GO-2026-6617** (process-crash), **GO-2026-6612**, **GO-2026-6611**, **GO-2026-6603** — all "Found in v0.53.0 / Fixed in v0.60.0."

**Reachability:** unauthenticated — the attacker only completes a TLS+h2 handshake and sends crafted HPACK/flow-control/SETTINGS/Trailer frames; application-layer rate-limiting sits *below* frame parsing and cannot mitigate it. Precondition: the main server runs over HTTPS (`tls_enabled`/`tls_auto_self_sign`/cert+key, or the `--https` bootstrap) — the documented production posture. Not reachable on plain-HTTP default (the x/net h2 handler isn't installed). Availability-only (no RCE/data exposure) → HIGH, not critical.

**Fix:** `go get golang.org/x/net@v0.60.0 && go mod tidy`; bump the Go toolchain to the patched minor; pass a configured `&http2.Server{}` with conservative limits (`MaxConcurrentStreams`, `MaxReadFrameSize`, `IdleTimeout`) instead of the zero value; add `govulncheck` to CI.

---

### 🟠 #4 — MEDIUM — No clickjacking / security headers; dashboard is framable and auto-authenticates

The only global middleware is `corsMiddleware` (`app.go:93-94`), which emits CORS headers only. Repo-wide, **`X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` are never set** and there's no client-side frame-busting. `GET /` serves the SPA ungated; the session token lives in same-origin `localStorage` and is auto-loaded on bootstrap. So the real app loaded inside an attacker's `<iframe src="https://victim-host/">` runs at `victim-host`'s origin, reads its `localStorage`, and **silently re-authenticates** — the attacker never needs to read the token. Impact is bounded by which controls are single-click (some destructive actions are `confirm()`-gated), hence MEDIUM.

**Fix:** a global header middleware setting `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) + `X-Frame-Options: DENY`, plus `X-Content-Type-Options: nosniff` and a `Referrer-Policy`. Optionally a frame-buster in the SPA bootstrap.

---

### 🟠 #5 — MEDIUM — Main HTTP listener has no timeouts (Slowloris)

`app.go:723` builds `&http.Server{Addr: addr, Handler: a.router}` with **no `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`** (these are set only on the redirect server and C2 listeners, never the main one). Default bind is `0.0.0.0:8080` plain HTTP. A trickle of partial-header connections holds goroutines/FDs indefinitely → unauth availability DoS, before any routing/auth. (Header *size* is capped by Go's 1 MB default; the gap is purely the timeouts.)

**Fix:** set `ReadHeaderTimeout` (~10s), `ReadTimeout`, `WriteTimeout`, `IdleTimeout` on the main `srv` (and the MCP server at `app.go:708`); carry non-zero timeouts into the TLS-sniffing per-connection server; optionally `netutil.LimitListener`.

---

### 🟠 #6 — MEDIUM (PLAUSIBLE) — SSRF via LLM connectivity-test endpoints

`config.go:1296` reads `base_url` with only `TrimSpace`/`TrimSuffix` — **no scheme/host/IP allowlist** — and uses `http.DefaultClient` (follows up to 10 redirects, no private-range block). The probes `POST base_url+/chat/completions` / `GET base_url+/models` and **echo the raw upstream body back** to the caller (`config.go:1367`, `:1440`, `:1527`) → a real partial read-SSRF to `169.254.169.254`, `127.0.0.1:<port>`, internal hosts.

**Precondition that bounds it:** routes require `config:write`, which by default **only `admin` holds** (`database/rbac.go:233` withholds `config:*` from operator/auditor/viewer). Admins already have full server control, so SSRF is an escalation only for a *deliberately delegated* non-admin config role. Still worth fixing because that role shouldn't imply network-pivot.

**Fix:** parse `base_url`, require http(s), reject loopback/link-local/RFC1918/metadata IPs; resolve DNS once and pin the dial (anti-rebind); re-validate redirects; stop reflecting the raw upstream body; apply the same guarded transport in `internal/openai` so all config-derived URLs are covered.

---

### 🟠 #7 — MEDIUM (PLAUSIBLE) — `audit_agent` LLM-judge is prompt-injectable

When an operator opts into `reviewer=audit_agent` (non-default; default is human), the human gate is replaced by an LLM verdict. `buildAuditAgentReviewInput` (`hitl_audit_agent.go:145-162`) copies attacker-influenceable fields (`arguments`/`command`/`thinking`/`planning`) into the judge prompt **with no data/instruction delimiting**, the verdict is scraped from free-text with lenient approve-synonyms, and the default `openai` backend has **no code-side hard floor** (only the TypeSafe/JEV path enforces one). So injected text in tool arguments can steer the judge to approve a destructive call. PLAUSIBLE (not CONFIRMED) because it's opt-in, non-deterministic, and the default policy already approves most offensive tooling by design (only the "must-reject" destructive class matters).

**Fix:** fence untrusted fields as data-only; use a structured verdict channel instead of JSON-scraping; add a code-side hard floor for the destructive class regardless of LLM verdict; disallow LLM-supplied `editedArguments` or re-validate them; default-reject on parse ambiguity.

---

### 🟡 #8–#15 — Lower-severity & dependency items (summary)

- **#8 SheetJS 0.18.5** (`assets.js:272`, `XLSX.read` on untrusted uploads): CVE-2023-30533 (proto-pollution), CVE-2024-22363 (ReDoS). **Client-side only** — bytes never reach the server; impact confined to the importing user's own tab (preview path escapes all cell values). **Fix:** upgrade to SheetJS ≥ 0.20.2 from the official CDN, or replace with a minimal CSV parser.
- **#9 Username enumeration** (`auth_manager.go:133`): a non-existent user returns immediately; an existing enabled user runs cost-10 bcrypt — a large, measurable timing oracle. Recon-only → LOW. **Fix:** constant-time dummy bcrypt on the not-found/disabled path.
- **#10 Unbounded login body** (`auth.go:54`): unauth `/api/auth/login` `ShouldBindJSON` with no `http.MaxBytesReader`; ~10 multi-GB bodies within the rate budget can OOM. **Fix:** global `MaxBytesReader` (1–4 MB) + the #5 timeouts + fix #2's XFF.
- **#11 Masked API-key exfil** (`config_secrets.go:146`): the `credential_scope`/`channel_id` branches return the real stored key without the URL-equality guard the unscoped branch applies, then send it as `Authorization: Bearer` to an attacker-chosen `base_url`. `config:write`-gated, and that role can already relocate `base_url` via `PUT /config`, so marginal → LOW. **Fix:** apply the URL-equality guard to all branches + the #6 SSRF allowlist.
- **#12 Template/option injection** (`executor.go:497`): the `template` param is substituted then `strings.Fields`-split, letting one value fan out into extra flags (argv injection, not shell). Largely redundant with the intended `additional_args`/`scan_type` passthrough, and reachable only via a tool-arg-controlling prompt injection. **Fix:** substitute into a single pre-tokenized argv element; per-param pattern validation; a `--` end-of-options separator; make HITL argument-aware (not tool-name-only) for free-form flag passthrough.
- **#13 WebSocket `CheckOrigin==true`** (`terminal_ws_unix.go:26`): **dormant** — the shipped app returns the token in the login JSON body and uses `?token=`/`localStorage`, never an `auth_token` cookie, so a cross-origin WS carries no credential and is 401'd by auth middleware before the handler. Becomes live only if a future/proxy config sets an `auth_token` cookie. **Fix:** replace with an Origin allowlist regardless (it's a shell endpoint); never honor an ambient cookie on upgrade.
- **#14 Auto-update** (`update.go:60`): scheme allowlist permits `http://`/`git://` and no commit/tag signature is verified before `go build` + binary swap. Admin-gated (`update:apply`+global scope), and such an actor is already code-swap-capable, so not an escalation — but it's a privileged code path that should use TLS + signatures. **Fix:** restrict to `https://`/`ssh://`; verify signed tags/commits (or a pinned checksum) before merge.
- **#15 Stale deps** (hygiene bumps; each verified real-version-but-bounded-impact): `golang.org/x/image` 2019 pin (TIFF/BMP OOM reachable from the authenticated, default-off vision feature — panics are recovered, so DoS is memory-only) → bump to ≥ v0.43.0; `modelcontextprotocol/go-sdk v1.3.1` (GO-2026-4770 null-Unicode JSON parse on a malicious-external-MCP path) → ≥ v1.4.1; DOMPurify 3.0.8 (CVE-2024-47875 mXSS — not exploitable under the current tight allowlist + `isHeavyRawHtml` escaping, but update anyway) → ≥ 3.2.4.

### 🔵 #16–#18 — Latent / info (fix cheaply, no current exploit)

- **#16 C2 HITL bridge fail-open** (`c2_hitl_bridge.go:119`, *verification was cut short by the content filter — treat as unconfirmed but plausible*): on `sql.ErrNoRows` the approval poll returns `nil`, which callers read as **approved**. Every sibling branch fails closed (reject). No current code path deletes a pending row, so it's latent — but the safe default for "approval record vanished" must be **reject**. **Fix:** return a reject error on `ErrNoRows`.
- **#17 Dormant weak hash branch** (`rbac.go:106`): a legacy `sha256$salt$hash` (single-round) verify path exists but is **dead** — every write path emits bcrypt; grep for `sha256$` is empty. **Fix:** delete the branch, or re-hash to bcrypt on a successful legacy verify.
- **#18 Fail-open list filter** (`vulnerability.go:99`, `asset.go:289`): return the *unfiltered* query when `UserID==""`, unlike the `AND 1=0` fail-closed conversation/C2 filters. **Not currently reachable** (every live caller supplies a non-empty principal). **Fix:** append `AND 1=0` when scope≠all and `UserID` is empty, to match the siblings.

---

## 3. Root-cause themes (fix these, and many findings collapse)

1. **`gin.Default()` with no `SetTrustedProxies`** → attacker-controlled `X-Forwarded-For` undermines every IP-keyed control (drives #2, amplifies #10). *One line fixes the class.*
2. **No global hardening middleware** → missing security headers (#4), body-size cap (#10), and server timeouts (#5). *One middleware + one `http.Server` config block.*
3. **Stale dependencies** → #3, #8, #15 and the refuted-but-worth-bumping ones. *`go get -u` the flagged modules + refresh vendored JS + add `govulncheck` to CI.*
4. **The AI/tool trust boundary has gaps where untrusted model/MCP output meets host execution** → #1 (the serious one), #7, #12, #16. *Tighten what bypasses HITL and jail the filesystem backend.*

## 4. Suggested remediation order

1. **#1** — remove `write_file` from the HITL exempt list + jail the filesystem backend root. *(Highest value; defeats the core governance promise.)*
2. **#2 + root-cause #1** — `SetTrustedProxies(nil)`, per-account lockout, bcrypt concurrency cap.
3. **#3 / #8 / #15** — dependency bumps + `govulncheck` in CI.
4. **#4 + #5 + #10 (root-cause #2)** — one global middleware: security headers, body cap, server timeouts.
5. **#6 / #11** — SSRF allowlist on all config-derived outbound requests.
6. **#7, #9, #12, #13, #14, #16, #17, #18** — the defense-in-depth / latent items.

## 5. Caveats on coverage (full transparency)

- An automated content-safety classifier interrupted **2 of 11** finder agents (the *path-traversal* and *secrets/crypto/deserialization* sweeps) and a couple of verification agents. **I audited those two surfaces manually instead** and found them **clean**:
  - **Path traversal / zip-slip:** every file resolver (`chat_uploads.go`, `skillpackage/io.go` `SafeRelPath`, `workflow/package/inspector.go` `safeArchivePath`) does `Clean` → reject `..` → `Join` → `Abs` → explicit `HasPrefix(root+sep)` containment, and archive extraction rejects absolute/`..`/backslash/symlink entries with a 20 MB cap. Robust.
  - **Secrets / crypto:** all real secrets use `crypto/rand`; the only `InsecureSkipVerify` is the *intended* offensive webshell-proxy feature; the `sha1`/`md5`/`math/rand` uses are a WeChat-Work-mandated signature, a cache-key prefix, and beacon jitter — never security-critical. No hardcoded or logged secrets found.
- **SQL injection:** the dedicated agent traced the full `internal/database` + `internal/storage` surface and found **zero** — queries are parameterized with `?` placeholders throughout. Confirmed clean.

## 6. What I verified as *solid* (so you know where not to spend effort)

- **Auth:** session tokens are `crypto/rand` UUIDv4; passwords are bcrypt; the first-run admin password is a 24-char `crypto/rand` secret printed once — **no hardcoded/default/backdoor account**; sessions expire and are revoked on logout/role/user change; empty hashes always fail.
- **Authorization:** RBAC middleware is **fail-closed**; system roles correctly withhold `rbac/config/terminal/audit/storage` from non-admins; object-level checks (conversations, C2 tasks) enforce ownership; the one fail-open filter (#18) isn't reachable.
- **SQLi:** parameterized everywhere.
- **Path traversal / zip-slip:** strong containment everywhere (see §5).
- **XSS:** rich LLM/tool output funnels through a DOMPurify sanitizer with a tight allowlist + an `isHeavyRawHtml` pre-escape gate; the one unescaped sibling (`c2.js:2815`) isn't attacker-reachable.
- **CORS:** does not reflect arbitrary origins with credentials.
- **No** exposed pprof/expvar/debug/metrics endpoints; MCP listener defaults to `127.0.0.1`, disabled by default, bearer-gated.

---

*This report rates findings at their true severity. It intentionally reports no fabricated "critical 0-day," because none was found — and a false critical would be a disservice. The HIGH items (#1–#3) are real and worth prompt attention; the root-cause fixes in §3 are high-leverage.*
