# GWS CLI Security Audit

**Date**: 2026-03-11
**Auditor**: Claude (automated review)
**Status**: Initial audit — external binary, not npm dependency

## Overview

The `gws` CLI is invoked by Sentinel's executor as an external subprocess via
`execa("gws", [...args])` in `packages/executor/src/tools/gws.ts`. It is NOT
an npm dependency — it's a standalone binary expected on `$PATH`.

## Credential Storage Mechanism

The GWS CLI stores OAuth2 tokens in the **OS keyring** (macOS Keychain,
Linux Secret Service, Windows Credential Manager). This is intentional —
credentials never enter Sentinel's vault or process.env.

**Keyring isolation**: The OS keyring is process-accessible to any process
running as the same user. In Docker, keyring access depends on volume mounts
and D-Bus socket forwarding. The current `docker-compose.yml` does NOT mount
keyring access into containers — GWS calls happen on the host.

## Sentinel Protections Applied

| Protection | Mechanism | File |
|-----------|-----------|------|
| Env stripping | `SENTINEL_*`, `ANTHROPIC_*`, etc. removed before spawn | `gws.ts:6-23` |
| `extendEnv: false` | Child process gets only cleaned env, not full `process.env` | `gws.ts:84` |
| Stderr suppression | Raw stderr never exposed (may contain tokens) | `gws.ts:89-95` |
| Error suppression | Generic "gws execution failed" on catch | `gws.ts:133-139` |
| Output scanning | Gmail read methods scanned for injection before agent sees output | `gws.ts:100-107` |
| Output truncation | Large output bounded before returning to agent | `gws.ts:109-110` |
| Timeout | 30s hard timeout with SIGKILL | `gws.ts:80-82` |
| Per-agent scoping | `GwsAgentScopes` restricts service access per-agent | `gws.ts:48-67` |

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| GWS CLI writes tokens to disk outside keyring | LOW | Audit CLI source; OS keyring is standard practice |
| CLI has undisclosed network behavior | LOW | `extendEnv: false` limits env leakage; timeout limits exposure |
| CLI version has known CVEs | MEDIUM | Pin version; monitor advisories |
| Keyring accessible to any same-user process | MEDIUM | Business account isolation (see plan) |
| CLI stdout contains sensitive data | LOW | Output scanning + truncation applied |

## Supply Chain Controls

Added in Wave 2.2c via `packages/executor/src/tools/gws-integrity.ts`. These
controls run once per process (cached) before any GWS CLI invocation.

### Binary Integrity Verification

SHA-256 hash of the resolved `gws` binary is compared against a known-good
value. Catches binary replacement, supply chain compromise, or unreviewed
updates.

```bash
# Obtain the expected hash
shasum -a 256 $(which gws)
# → e3b0c44298fc1c149afbf4c8996fb924...  /usr/local/bin/gws
```

**Config** (`GwsIntegrityConfig`):
- `verifyBinary: true` — enable hash verification
- `expectedSha256: "<64-char-hex>"` — the known-good SHA-256 hash

**Enforcement**: Hard block in Docker (`SENTINEL_DOCKER=true`), warn in local
dev. Hash mismatch returns `"Binary hash mismatch — gws binary may have been
tampered with or updated"`.

### Version Pinning

Parses `gws --version` output and compares against a configured pin. Two
policies available:

- `"exact"` — version must match exactly (for reproducible deployments)
- `"minimum"` — version must be `>=` the pin (allows patch updates)

**Config**:
- `pinnedVersion: "1.2.3"` — the version to enforce
- `pinnedVersionPolicy: "exact" | "minimum"` — comparison policy (default: `"minimum"`)

No external semver dependency — uses simple `major.minor.patch` numeric
comparison.

### CVE Version Blocklist

Blocks execution when the installed version matches a known-vulnerable version.
Maintained as a simple string array in config.

**Config**:
- `vulnerableVersions: ["1.0.0", "1.1.0"]` — versions with known CVEs

When a match is found: `"Running vulnerable gws version X.Y.Z — update the
binary before use"`.

### System-Wide OAuth Scope Cap

Maps GWS service names to Google OAuth scope URIs and blocks services whose
scope is not in the allow list. Sits ABOVE per-agent `GwsAgentScopes` —
provides a system-wide ceiling.

**Config**:
- `allowedOAuthScopes: ["https://www.googleapis.com/auth/gmail.modify", ...]`

**Service-to-scope mapping** (`GWS_SERVICE_SCOPE_MAP`):

| Service | OAuth Scope |
|---------|------------|
| gmail | `googleapis.com/auth/gmail.modify` |
| calendar | `googleapis.com/auth/calendar` |
| drive | `googleapis.com/auth/drive` |
| sheets | `googleapis.com/auth/spreadsheets` |
| docs | `googleapis.com/auth/documents` |
| slides | `googleapis.com/auth/presentations` |
| admin | `googleapis.com/auth/admin.directory.user` |
| people | `googleapis.com/auth/contacts` |
| tasks | `googleapis.com/auth/tasks` |

**Fail-closed**: Unknown services not in the map are always blocked when
`allowedOAuthScopes` is configured. No config = all services allowed (backward
compatible).

### Configuration Example

```typescript
const integrityConfig: GwsIntegrityConfig = {
  verifyBinary: true,
  expectedSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  pinnedVersion: "2.0.0",
  pinnedVersionPolicy: "minimum",
  vulnerableVersions: ["1.0.0", "1.1.0", "1.5.3"],
  allowedOAuthScopes: [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
  ],
};
```

### Enforcement Modes

| Environment | Integrity Failure | Scope Violation |
|-------------|-------------------|-----------------|
| Docker (`SENTINEL_DOCKER=true`) | Hard block — error returned | Hard block — error returned |
| Local dev | Warn via `console.warn` — execution continues | Hard block — error returned |

Scope violations are always hard blocks because they represent a configuration
mistake, not a development environment issue.

### Caching

The integrity check runs once per process and caches the result. Failed checks
clear the cache automatically, allowing retry (e.g., binary installed after
process start). Call `resetIntegrityCache()` in tests.

## Version Pinning (Manual)

The GWS CLI is not an npm dependency — it's installed separately. In addition
to the automated version pinning above, record the installed version here:

```bash
# Check installed version
gws --version

# Document the pinned version here after installation
# PINNED_VERSION: <not yet installed>
```

**Action item**: After installing the GWS CLI, record the exact version here
and in the project's setup documentation. Do not auto-update without review.

## Recommendations

1. **Use a dedicated business Google account** — reduces blast radius if CLI
   or keyring is compromised (see security evaluation plan)
2. **Pin CLI version** — configure `pinnedVersion` in `GwsIntegrityConfig` AND
   record exact version in this document; review changelogs before updates
3. **Enable binary hash verification** — set `verifyBinary: true` and
   `expectedSha256` in production deployments; update hash after each CLI update
4. **Maintain CVE blocklist** — add known-vulnerable versions to
   `vulnerableVersions` array; check npm advisories and GitHub issues
5. **Scope cap OAuth** — configure `allowedOAuthScopes` to only the services
   your agents actually need; principle of least privilege
6. **Audit CLI source** — verify keyring backend (keytar vs. native), check for
   plaintext fallback, confirm no credential disk writes outside keyring
7. **Docker keyring isolation** — current setup correctly does NOT mount keyring
   into containers; maintain this boundary

## OS Keyring Risk: Docker-Only Recommendation

**Risk**: Google OAuth tokens stored in the OS Keyring (macOS Keychain) are accessible
to any process running as the same user. Unlike Sentinel's encrypted vault (AES-256-GCM
with 600,000 PBKDF2 iterations), OS Keyring credentials are protected only by user-level
ACLs. On local dev (no Docker), any process the agent spawns inherits keyring access.

**Docker mitigates this**: The agent container runs with `internal: true` networking and
does NOT mount the host keyring. GWS CLI calls are executed by the executor (trusted
process), which has keyring access but never exposes raw tokens to the agent. The agent
container cannot reach the host keyring even if compromised.

**Recommendations by deployment mode**:

| Mode | Risk Level | Recommendation |
|------|-----------|---------------|
| Docker Compose (production) | LOW | Agent can't reach keyring; executor mediates all access |
| Local dev (no Docker) | MEDIUM | Use a test/sandbox Google account, not production credentials |
| Hybrid (executor in Docker, host agent) | HIGH | Not recommended — agent has direct keyring access |

**For production use**: Always deploy with Docker Compose. The two-container model
(executor + agent) is the security boundary. Running the agent on the bare host
eliminates the network isolation that prevents credential exfiltration.

## Open Questions

- [ ] What keyring library does the GWS CLI use internally? (keytar? native?)
- [ ] Does it have a plaintext fallback when keyring is unavailable?
- [ ] Are there known CVEs for the current version?
- [ ] Does it phone home or send telemetry?

These questions require manual source review of the GWS CLI codebase.
