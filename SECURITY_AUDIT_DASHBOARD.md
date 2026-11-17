# Dashboard security audit — hermes_cli/web_server.py + web/

**Scope:** Dashboard auth, PTY WebSocket, session tokens, CSRF, CORS, bind address, HTTP endpoints.  
**Threat model:** Network attacker (incl. browser XSS/CSRF when bound beyond localhost) → RCE via PTY / secret theft / session hijack.  
**Date:** 2026-11-17  
**Branch:** `cursor/vulnerability-findings-persistence-23fc`

## Verdict

**No high-confidence HIGH/CRITICAL exploitable vulnerabilities** with a complete attack chain against:

1. **Default** `hermes dashboard` (bind `127.0.0.1`), or  
2. **Gated** non-loopback bind **without** `--insecure` (OAuth / basic auth cookie gate).

The dashboard surface has already been hardened against DNS rebinding (GHSA-ppp5-vxwm-4cf7), plugin API path RCE (GHSA-5qr3-c538-wm9j), and the historical Docker auto-`--insecure` footgun. Remaining severe impact requires an **explicit operator opt-in** (`--insecure` / `HERMES_DASHBOARD_INSECURE`) that docs already label as fully exposing secrets.

---

## REAL findings (HIGH/CRITICAL)

*None meeting the bar of “network attacker → impact without relying on documented insecure opt-in or already-trusted local code execution.”*

---

## Discarded near-misses (and why)

### 1. `--insecure` + token-in-HTML ≈ unauthenticated (CRITICAL impact, not a defect)

| Item | Detail |
|------|--------|
| What | With `--host <non-loopback> --insecure`, `auth_required=False`, SPA injects `__HERMES_SESSION_TOKEN__` into publicly served `index.html`. Anyone who can `GET /` extracts the token and reaches `/api/pty`, `/api/env/reveal`, etc. On `0.0.0.0`/`::` binds, Host/Origin checks also accept any host. |
| Evidence | `hermes_cli/web_server.py:183`, `9016–9022`, `310–314`, `8355–8381`, `8530–8534`, `8710+` |
| Why discarded | Documented intentional escape hatch (`website/docs/user-guide/features/web-dashboard.md` danger callout; CLI `--insecure` help: “DANGEROUS: exposes API keys”). Equivalent to “no auth on a trusted LAN,” not a bypass of a claimed control. |

### 2. Default bind `0.0.0.0`

| Item | Detail |
|------|--------|
| What | Suspected unsafe default listen-all. |
| Why discarded | CLI/`start_server` default is `127.0.0.1` (`subcommands/dashboard.py:29`, `web_server.py:10042`). Docker s6 defaults `HERMES_DASHBOARD_HOST=0.0.0.0` but engages the OAuth gate (or fail-closed) unless `HERMES_DASHBOARD_INSECURE` is set (`docker/s6-rc.d/dashboard/run`). |

### 3. PTY WebSocket auth bypass

| Item | Detail |
|------|--------|
| What | Upgrade without credential / with legacy token under gate. |
| Why discarded | Loopback/`--insecure`: constant-time `?token=` vs `_SESSION_TOKEN`. Gated: only single-use `?ticket=` or process-internal `?internal=` (never injected into SPA). Legacy `?token=` rejected when gated (`_ws_auth_reason`, `8454–8535`). Peer + Host/Origin guards applied before accept (`8719–8745`). |

### 4. Command injection via `_spawn_hermes_action`

| Item | Detail |
|------|--------|
| What | User-controlled skills/MCP/backup/import args → RCE. |
| Why discarded | `subprocess.Popen([sys.executable, "-m", "hermes_cli.main", *subcommand], …)` — argv list, **no** `shell=True` (`1310–1341`). Metacharacters do not get a shell. Profile open-terminal names constrained by `_PROFILE_ID_RE` (`profiles.py:35`). |

### 5. CSRF against state-changing `/api/*`

| Item | Detail |
|------|--------|
| What | Cross-site form/fetch mutating env/config/PTY. |
| Why discarded | Loopback/`--insecure`: APIs require custom `X-Hermes-Session-Token` / Bearer (simple forms cannot set). Gated: `SameSite=Lax` HttpOnly cookies (`dashboard_auth/cookies.py:117–125`); cross-site POSTs do not send cookies. CORS allowlist is localhost-only (`web_server.py:203–207`) so evil sites cannot read responses. No complete CSRF→PTY chain without a prior XSS or token theft. |

### 6. XSS → steal token / drive PTY

| Item | Detail |
|------|--------|
| What | Markdown/theme/plugin sinks. |
| Why discarded | Markdown uses React text nodes; blocks `javascript:`/`data:` hrefs (`web/src/components/Markdown.tsx:327–334`). Theme `customCSS` applied via `style.textContent` (not `innerHTML`). No `dangerouslySetInnerHTML` in `web/src`. Gated cookies are HttpOnly (XSS cannot read them) but same-origin XSS could still call `/api/auth/ws-ticket` — **no high-confidence XSS entry point found** in first-party UI. Malicious **user-installed** dashboard plugin JS is trusted-code-by-install, not a network pre-auth bug. |

### 7. Path traversal (SPA / media / plugins)

| Item | Detail |
|------|--------|
| What | Read files outside intended roots. |
| Why discarded | SPA: `resolve().is_relative_to(WEB_DIST)` (`9078–9086`). Media: suffix allowlist + hermes home roots (`814–856`). Plugin assets: `is_relative_to` + browser-suffix allowlist (`9910–9946`). Plugin `api` paths validated (`9440–9474`); project plugin Python import blocked (`9973–9980`). |

### 8. Weak / predictable session tokens

| Item | Detail |
|------|--------|
| What | Guessable `_SESSION_TOKEN` or WS tickets. |
| Why discarded | `secrets.token_urlsafe(32)` for session + tickets + internal credential (`183`, `ws_tickets.py:69,125`). Empty env falls through to fresh random (`183`). |

### 9. Unauthenticated sensitive APIs

| Item | Detail |
|------|--------|
| What | Public allowlist over-broad. |
| Why discarded | Shared `PUBLIC_API_PATHS` is small and read-only (`dashboard_auth/public_paths.py:33–49`): status, config defaults/schema, model info, themes, plugin manifests. No env reveal, no PTY, no config write. `/api/status` leaks local paths (`hermes_home` etc.) — **info disclosure only (Low)**, not secret values. |

### 10. Password-login rate-limit bypass via `X-Forwarded-For`

| Item | Detail |
|------|--------|
| What | Gated mode sets `proxy_headers=True`; `_client_ip` trusts `X-Forwarded-For` → rotate spoofed IPs to bypass 10/min throttle. |
| Why discarded | Defense-in-depth only; does not alone yield RCE/secret theft without weak credentials. Severity ≤ Medium; no complete HIGH chain without guessing a password. |

### 11. `Origin: null` / `file://` allowed on WS

| Item | Detail |
|------|--------|
| What | Origin guard skips non-http(s) schemes for Electron desktop. |
| Why discarded | Credential remains mandatory; intentional (`test_dashboard_auth_ws_auth.py` TestWsHostOriginGuardOrigins). Sandboxed-iframe `null` Origin still cannot read the HTML token under CORS. |

### 12. `docker-compose.windows.yml` ships `--insecure`

| Item | Detail |
|------|--------|
| What | Dashboard command includes `--insecure` while binding container `0.0.0.0`. |
| Why discarded | Host publish is `127.0.0.1:9119:9119`. Compose services share the same `~/.hermes` volume — cross-container pivot to dashboard does not expand secret access beyond the shared mount. Still a footgun if port mapping is widened; not a default LAN exposure. |

### 13. DNS rebinding against loopback

| Item | Detail |
|------|--------|
| What | Classic localhost dashboard rebinding. |
| Why discarded | Host-header middleware rejects non-loopback Host when bound to loopback (`325–352`, `281–322`). Covered by GHSA-ppp5-vxwm-4cf7 tests. |

---

## Control summary (what actually blocks attackers)

| Mode | Auth | Token in HTML | PTY | Network attacker |
|------|------|---------------|-----|------------------|
| Default `127.0.0.1` | Ephemeral session token + loopback peer + Host check | Yes (local only) | `?token=` | Cannot reach socket from remote network |
| Non-loopback, no `--insecure` | OAuth/basic cookies; fail-closed if no provider | No | `?ticket=` (30s, single-use) | Needs valid login; CSRF/CORS/SameSite impede browser drive-by |
| Non-loopback + `--insecure` | Token in public HTML (theater) | Yes | `?token=` after scraping `/` | **Full compromise by design** |

---

## Suggested follow-ups (non-blocking / hardening)

1. Treat `--insecure` as “no auth” in UX (avoid implying the HTML token is a network boundary).  
2. Prefer rejecting spoofable `X-Forwarded-For` for password rate limits unless behind a configured trusted proxy CIDR.  
3. Add `frame-ancestors` / `X-Frame-Options` on gated deploys.  
4. Fix docs inconsistency: prose that lists `0.0.0.0` as not engaging the gate vs table/code where `0.0.0.0` **does** engage the gate (`should_require_auth("0.0.0.0", False) is True`).
