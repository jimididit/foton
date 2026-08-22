# Contributing to Foton

This project is designed so someone new can add a **collector**, **baseline provider**, **parser**, or **analysis rule** without rewriting the core.

## Before you write code

1. Read [AGENTS.md](../AGENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md), [USAGE.md](USAGE.md), and [LAB.md](LAB.md) (host vs VMware guest).
2. Live triage behavior lives in frozen `WinFoton.ps1` until Collect is extracted. Do not “fix” naming inside that file.
3. If the change is a large new capability (especially Carve/NTFS), propose it first.

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

Declare: record type, identity key, collect scriptblock, compared fields vs ignored fields (e.g. ignore service `State` and `ProcessId`; compare `PathName`, `StartMode`, `StartName`, binary hash).

State likely false positives in the PR (e.g. software `DisplayName` churn from patch Tuesday).

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

## What we will not accept

- Remediation, process kill, quarantine, or “repair” switches.
- Analyze/Parse code that reads the live registry or network.
- Findings that assert compromise, attribution, or intent.
- Expanding LOLBin/RAT lists without noting false-positive sources.
