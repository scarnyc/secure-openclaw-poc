# Secure Your Cloud Server in 15 Steps

Reference checklist for infrastructure hardening. Mapping to Sentinel's architecture noted where applicable.

## Checklist

| # | Step | Command / Action | Sentinel Mapping |
|---|------|-----------------|-----------------|
| 01 | Never run as root | `adduser deploy && usermod -aG sudo deploy` | N/A — Cloudflare Workers are serverless |
| 02 | SSH keys only — kill passwords | `ssh-copy-id deploy@server`, `PasswordAuthentication no` in sshd_config | N/A — no SSH; Cloudflare Access JWT auth |
| 03 | Change default SSH port | `Port 2222` in sshd_config | N/A — no SSH |
| 04 | Firewall everything with UFW | `ufw default deny incoming && ufw allow 2222/tcp && ufw allow 443/tcp && ufw enable` | Cloudflare network handles this; Worker bindings are not publicly routable |
| 05 | Install Fail2Ban | `apt install fail2ban && systemctl enable fail2ban` | Cloudflare Access + rate limiting at the edge |
| 06 | Auto-update security patches | `apt install unattended-upgrades` | Container base image pinned (`sandbox:0.7.0`); update via Dockerfile rebuild |
| 07 | Force HTTPS | `certbot --nginx -d yourdomain.com` | Cloudflare enforces HTTPS by default |
| 08 | Disable root login over SSH | `PermitRootLogin no` in sshd_config | N/A — no SSH |
| 09 | VPN/Tailscale for internal services | Never expose admin panels or databases publicly | D1/KV/R2 only accessible via Worker bindings; `/_admin/` behind Cloudflare Access |
| 10 | Scan your own open ports | `nmap -sV your-server-ip` | Container exposes only port 18789 internally; no public ports |
| 11 | Isolate your database | DB only accepts connections from app's internal IP | D1/KV bound to Worker — no public endpoint; SQLite inside Durable Object |
| 12 | Set up log monitoring | `journalctl -f` at minimum | Invariant #2: all tool calls audited to D1; Cloudflare Observability MCP |
| 13 | Automate backups. Test restores. | Daily snapshots + off-site | R2 bucket (`MOLTBOT_BUCKET`) for persistence; Cloudflare manages D1 backups |
| 14 | Containerize with Docker | Each service isolated | Sandbox container isolates OpenClaw + claude-mem from the Worker |
| 15 | Monthly vulnerability scans | Trivy, OpenVAS, or Numasec | `/security-audit` skill validates 6 invariants; add Trivy to CI for container scans |

## Cloudflare Workers Security Checklist

Sourced from [CF Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/) and [CF Workers Security Model](https://developers.cloudflare.com/workers/reference/security-model/).

| # | Practice | Implementation | Sentinel Mapping |
|---|----------|---------------|-----------------|
| W1 | Timing-safe secret comparison | `crypto.subtle.timingSafeEqual()` — never short-circuit on length | Executor token validation, JWT verification, HMAC comparison |
| W2 | No `Math.random()` for security | Use `crypto.randomUUID()` / `crypto.getRandomValues()` | Already using `crypto.randomUUID()` for manifest IDs — audit for any `Math.random()` |
| W3 | Secrets via `wrangler secret put` | Never in wrangler.toml or source; access through `env` at runtime | Maps to Invariant #1; vault.enc replaces env vars locally |
| W4 | Avoid `passThroughOnException()` | Fail-open mechanism hides bugs — Sentinel must fail-closed | Executor rejects on any unhandled error; no fallback to origin |
| W5 | Freeze binding derivatives in global scope | Binding pollution persists across requests in same isolate | `Object.freeze(policy)` at startup — Invariant #6 (no hot-reload) |
| W6 | Environment separation | Separate Workers per env (`sentinel-dev`, `sentinel-prod`) | Use wrangler environments; separate D1/KV bindings per env |
| W7 | Binding-based auth (no network hop) | D1/KV/R2 bindings are in-process, no auth overhead | Executor uses bindings directly; agent never touches bindings |

## Replit Agent Security Lessons

Sourced from [Replit Security Checklist](https://docs.replit.com/tutorials/vibe-code-security-checklist), [Replit Snapshot Engine](https://blog.replit.com/inside-replits-snapshot-engine), and [Replit Decision-Time Guidance](https://blog.replit.com/securing-ai-generated-code).

| # | Practice | Sentinel Mapping |
|---|----------|-----------------|
| R1 | OS/process-level enforcement, not prompt-level | Core Sentinel principle — executor enforces at process boundary; agent cannot override |
| R2 | Pre-deploy SAST scanning (Semgrep ~200 rules) | Pre-CF Gate: Semgrep scan before migration; CI integration for ongoing |
| R3 | Snapshot engine for reversible agent actions | Audit log enables replay; rollback is future work (OpenSandbox snapshots) |
| R4 | Deterministic file blocking at sandbox level | Workspace scoping (Phase 1.5) — per-agent filesystem containment |
| R5 | Decision-time guidance over system-prompt-only | `classify()` runs at execution time, not generation time — correct layer |

### Replit Vibe Code Security Checklist (applicable items)

From [Replit Security Checklist](https://docs.replit.com/tutorials/vibe-code-security-checklist) and [16 Ways to Vibe Code Securely](https://blog.replit.com/16-ways-to-vibe-code-securely).

**MVP (executor API hardening):**

| # | Replit Check | Sentinel Application |
|---|-------------|---------------------|
| R-BE1 | SQL injection prevention — parameterized queries | Audit logger uses parameterized SQLite queries (already done); verify no string concat in any query path |
| R-BE2 | Authorization checks before every action | `classify()` gate runs before tool execution — never after |
| R-BE3 | Proper error handling — generic messages to users, log internally | Executor returns sanitized errors to agent; raw errors go to audit log only |
| R-BE4 | API endpoint protection — auth + CORS + rate limiting | MVP: localhost-only (no CORS needed); CF: JWT + CORS + rate limiting |
| R-ON1 | Keep dependencies updated — `npm audit` regularly | Add to Pre-CF Gate; `pnpm audit` in CI |
| R-ON2 | Rate limiting on all API endpoints | MVP: single-user local, low priority; CF: mandatory on `:3141` |

**CF deployment (Phase 2):**

| # | Replit Check | Sentinel Application |
|---|-------------|---------------------|
| R-FE1 | CSRF protection — anti-CSRF tokens on state-changing requests | Confirmation TUI runs on host (no browser); CF dashboard needs CSRF tokens |
| R-FE2 | Security headers — X-Frame-Options, CSP, HSTS | Executor API: add via Hono middleware in CF deployment |
| R-FE3 | Secure cookies — HttpOnly, Secure, SameSite | Session management for CF dashboard (not applicable to API-only MVP) |
| R-ON3 | File upload security — restrict types, scan, rename | MCP tool proxy may handle file uploads; validate at executor boundary |

## General Security Frameworks (Phase 2+)

| Framework | Scope | Reference |
|-----------|-------|-----------|
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Systematic audit of executor API | Broken access control, injection, SSRF — partially covered by deny-list + credential filtering |
| [OWASP ASVS L2](https://owasp.org/www-project-application-security-verification-standard/) | Verification standard for security-critical apps | Session mgmt, crypto storage, error handling — L2 is right target |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | AI-specific threat categories | Prompt injection, data poisoning, model manipulation — not covered by traditional frameworks |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) / [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Command injection hardening | Argument injection edge cases beyond bash parser |
| [CF Workers Security Model](https://developers.cloudflare.com/workers/reference/security-model/) | Spectre mitigation, isolate architecture | V8 isolate boundaries, per-request key derivation |

## Sources

### Cloudflare
- [CF Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/) — runtime security, secret handling, environment separation
- [CF Workers Security Model](https://developers.cloudflare.com/workers/reference/security-model/) — V8 isolate architecture, Spectre mitigation, per-request key derivation
- [CF Secrets Management](https://developers.cloudflare.com/workers/configuration/secrets/) — `wrangler secret put`, runtime access via `env`, no source code exposure

### Replit
- [Replit Security Checklist for Vibe Coding](https://docs.replit.com/tutorials/vibe-code-security-checklist) — front-end, back-end, and ongoing security checks
- [16 Ways to Vibe Code Securely](https://blog.replit.com/16-ways-to-vibe-code-securely) — practical security fundamentals for AI-assisted development
- [Replit Snapshot Engine](https://blog.replit.com/inside-replits-snapshot-engine) — filesystem forks, versioned databases, reversible agent actions
- [Replit Decision-Time Guidance](https://blog.replit.com/securing-ai-generated-code) — runtime enforcement over prompt-level instruction

### Standards & Frameworks
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — most critical web application security risks
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — application security verification standard (targeting L2)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) — AI risk management framework
- [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html) — improper neutralization of special elements in commands
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) — OS command injection via user-controlled input
