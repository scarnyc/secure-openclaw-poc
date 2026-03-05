---
name: upstream-sync
description: Rebase on upstream moltworker, preserve SENTINEL blocks, and update UPSTREAM-DIFFS.md
disable-model-invocation: true
---

# Upstream Sync

Safely rebase Sentinel on the latest upstream moltworker while preserving all Sentinel modifications.

## Prerequisites

Ensure the upstream remote is configured:
```bash
git remote get-url upstream || git remote add upstream https://github.com/cloudflare/moltworker.git
```

## Workflow

### Step 1: Pre-Sync Snapshot

Before rebasing, capture current state:

```bash
# Record all SENTINEL comment locations
grep -rn "// SENTINEL:" src/ > /tmp/sentinel-markers-before.txt 2>/dev/null || true

# Ensure clean working tree
git status --porcelain
```

If working tree is dirty, abort and ask user to commit or stash first.

### Step 2: Fetch and Rebase

```bash
git fetch upstream
git rebase upstream/main
```

If conflicts occur:
1. For each conflicted file, check if it contains `// SENTINEL:` markers
2. **Always preserve SENTINEL blocks** — these are our modifications
3. Accept upstream changes for everything else
4. `git rebase --continue` after resolving each conflict

### Step 3: Verify SENTINEL Markers Survived

```bash
grep -rn "// SENTINEL:" src/ > /tmp/sentinel-markers-after.txt 2>/dev/null || true
diff /tmp/sentinel-markers-before.txt /tmp/sentinel-markers-after.txt
```

If any markers were lost, investigate and restore them before proceeding.

### Step 4: Update UPSTREAM-DIFFS.md

Regenerate the diff tracker:

```bash
git diff upstream/main..HEAD --name-only -- src/
```

For each modified upstream file, update `UPSTREAM-DIFFS.md` with:
- File path and line numbers
- Reason for modification (from `// SENTINEL:` comment)
- Whether the change is additive or a behavioral override

### Step 5: Verify Build

```bash
npm run typecheck && npm run lint && npm run test
```

All must pass before the sync is considered complete.
