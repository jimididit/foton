# Contributing to Foton

This project is designed so someone new can add a **collector**, **baseline provider**, **parser**, or **analysis rule** without rewriting the core.

## Before you write code

1. Read [AGENTS.md](../AGENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md), [USAGE.md](USAGE.md), [LAB.md](LAB.md), and **[COVERAGE.md](COVERAGE.md)** (in vs missing artifacts).
2. Live Collect/Baseline on an endpoint is the flatten script (`Foton-Collect_v*_schema*.ps1` / `Foton-Baseline_v*_schema*.ps1`, plus unversioned aliases). Do not add features by editing a frozen v1 script if one remains in git.
3. If the change is a large new capability (especially Carve/NTFS), propose it first.
4. Prefer filling a **P0/P1** row in COVERAGE.md over a novel ASEP. Map the operator UI to the real artifact before coding.

## Naming and files

- One public function per file; file name = function name (`New-FotonBaseline.ps1`).
- Add the function to `FunctionsToExport` in `Foton.psd1`.
- Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, and at least one `.EXAMPLE` that looks like a real engagement.
- Comments: forensic *why* (why this artifact, why this identity key) and extension *how* (where the next provider goes). Avoid narrating `foreach` line-by-line.

## Add a live collection task (after Collect exists)

1. Prefer a new `Invoke-Collection` / `Invoke-FotonCollection` call inside the right category file.
2. Emit facts (paths, hashes, registry values). Do not assign severity in Collect.
3. Fail into the manifest; never throw out of the orchestrator. If the task is admin-only, use `RequiresElevation` so unelevated runs skip it as a visibility gap.
4. PS 5.1 only in this layer.

## Add a baseline provider

Declare: record type, identity key, collect scriptblock, compared fields vs ignored fields (e.g. ignore service `State` and `ProcessId`; compare `PathName`, `StartMode`, `StartName`, binary hash). Put the file in `src/Private/Baseline/Providers/`. Bump `BaselineSchemaVersion`. Update `docs/COVERAGE.md`.

State likely false positives in the PR (e.g. software `DisplayName` churn from patch Tuesday; Settings startup toggles are `StartupApproved`, not `StartupFile`).

## Add an analysis rule

- Input: package data (or a mock in tests), never live WMI.
- Output: `Add-FotonFinding` with Tier, Artifact path, WhyItMatters (benign reading), optional NextStep.
- Tests: one record that must fire, one that must not.

## Add a parser

Pure function over a path or byte array. Commit a small fixture under `tests/Fixtures/`. No client data.

## Verification

```powershell
# Parse
$e=$null;$t=$null
[System.Management.Automation.Language.Parser]::ParseFile('.\src\Public\Get-FotonVersion.ps1',[ref]$t,[ref]$e) | Out-Null

# Tests
.\tests\Invoke-FotonTests.ps1
```

ScriptAnalyzer: see AGENTS.md accepted rule exceptions (`PSAvoidUsingWriteHost`, empty catch on best-effort collect, etc.).

HTML reports: include the shared search/nav chrome (`Get-FotonReportNavCss` and friends). No CDN.

## What we will not accept

- Remediation, process kill, quarantine, or “repair” switches.
- Analyze/Parse code that reads the live registry or network.
- Findings that assert compromise, attribution, or intent.
- Expanding LOLBin/RAT lists without noting false-positive sources.
