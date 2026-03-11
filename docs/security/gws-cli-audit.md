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

## Version Pinning

The GWS CLI is not an npm dependency — it's installed separately. Version
pinning must be done at the system level:

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
2. **Pin CLI version** — record exact version; review changelogs before updates
3. **Audit CLI source** — verify keyring backend (keytar vs. native), check for
   plaintext fallback, confirm no credential disk writes outside keyring
4. **Monitor for CVEs** — check npm advisories and GitHub issues periodically
5. **Docker keyring isolation** — current setup correctly does NOT mount keyring
   into containers; maintain this boundary

## Open Questions

- [ ] What keyring library does the GWS CLI use internally? (keytar? native?)
- [ ] Does it have a plaintext fallback when keyring is unavailable?
- [ ] Are there known CVEs for the current version?
- [ ] Does it phone home or send telemetry?

These questions require manual source review of the GWS CLI codebase.
