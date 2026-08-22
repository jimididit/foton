# Foton — Development Handover

You are working on **Foton**, a Windows forensic, baseline-comparison, and security-audit toolkit written in PowerShell.

The product name is **Foton**. Older artifacts still say WinFoton:

- `WinFoton.ps1` is the **live triage collector** (do not rename strings inside that file). Standard-user coverage is supported; `-RequireAdministrator` opts into fail-fast.
- `WinFoton-sample-report.html` is a sample produced by that script.

New code, docs, module files, and the flattened collector use **Foton**. Public commands use the `Foton` noun (`Get-FotonVersion`, `Invoke-FotonTriage`, `New-FotonBaseline`, …).

Version 1.0.0 exists as a single ~3,270-line script (`WinFoton.ps1`) that does live triage collection and HTML reporting. That behavior is the Collect-layer reference. The repo is being restructured into a modular toolkit; **do not skip the migration steps** in `docs/MIGRATION.md`.

## What Foton is for

Streamline forensic analysis and security audits by capturing machine state into a hashed **package**, then composing later work on that package:

- Capture a **baseline**, then compare state days later (temporal) or against a role golden image (fleet).
- Collect live triage when you need volatile data and a first-pass HTML overview.
- Parse and (later) carve artifacts on an analyst workstation without touching the host again.
- Add collectors, baseline providers, parsers, and analysis rules as separate files so the toolkit can grow without editing a 3k-line script.

## Five capability layers (one core, one findings model, one report engine)

| Layer | Purpose | Runs where |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **Collect** | Live triage acquisition from a running endpoint (what `WinFoton.ps1` does today) | Target endpoint; **Administrator preferred**, standard user supported |
| **Baseline** | Capture a normalized known-state snapshot; diff two snapshots for added/removed/modified | Target endpoint (capture) / anywhere (diff) |
| **Parse** | Turn raw artifacts into structured records — prefetch, EVTX, LNK/jumplists, Amcache, shellbags, SRUM, browser databases, registry hives | Analyst workstation, against a collected package |
| **Carve** | Recover structured data from unallocated space, slack, deleted registry cells, and file remnants | Analyst workstation, against images/blobs |
| **Analyze** | Apply heuristics, IOC lists, and baseline diffs to produce tiered findings, then render the report | Anywhere, offline |

**Collect and Baseline (capture) are the only layers that touch a live host. Parse, Carve, and Analyze operate exclusively on already-collected data and must run fully offline.** That separation makes parsers testable against fixtures and keeps analysis reproducible.

## Extensibility (how someone else adds a feature)

Do not grow giant functions. Add a file:

| You want to… | Add |
|--------------|-----|
| A new live artifact category | `src/Public/Collect/<Name>.ps1` + manifest export + tests |
| A new stable config surface for diffs | `src/Public/Baseline` provider file (record type, identity key, compared fields) |
| A new file format parser | `src/Public/Parse/ConvertFrom-Foton*.ps1` + `tests/Fixtures/` + Pester |
| A new heuristic | `src/Public/Analyze` rule file: one mock that fires, one that must not |
| A new IOC source | feed `Invoke-FotonIocMatch` (when implemented); do not scrape the live host |
| Report styling | `src/Public/Report` only; escape with `ConvertTo-FotonSafeHtml` |

Register public functions in `Foton.psd1` `FunctionsToExport`. `Foton.psm1` dotsources by convention.

## Repository layout

```
Foton/
  WinFoton.ps1                 # FROZEN v1.0.0 live collector — do not rename internals
  Foton.psd1                   # module manifest (RootModule = Foton.psm1)
  Foton.psm1                   # dotsources Private/ then Public/, exports via manifest
  src/
    Private/
      Core/                    # Write-FotonStatus, Invoke-FotonCollection, Add-FotonFinding, …
      Patterns/                # command/path/RAT/hardening data, not code
      Schema/                  # package + baseline + findings schema versions
    Public/
      Collect/                 # one file per category
      Baseline/                # New-FotonBaseline, Compare-FotonBaseline, providers
      Parse/                   # ConvertFrom-FotonPrefetch, -FotonLnk, …
      Carve/                   # Invoke-FotonCarve + signature recognizers
      Analyze/                 # Invoke-FotonAnalysis, rules, Invoke-FotonIocMatch
      Report/                  # New-FotonReport, HTML/CSS/JS
  build/
    Build-Standalone.ps1       # flattens Collect + Core into dist/Foton-Collect.ps1
  dist/                        # generated endpoint script
  tests/
    Unit/
    Fixtures/
  docs/
```

## Deployment constraint

The collector runs on possibly compromised endpoints, often over a constrained channel, often via RMM, sometimes where you cannot install anything. **A module tree is not the Collect deployment format.**

Develop modular, ship flat. `build/Build-Standalone.ps1` concatenates Private/Core + Public/Collect + Public/Report + a generated entry point into `dist/Foton-Collect.ps1` with no `Import-Module`. Parse, Carve, and Analyze run as a normal imported module on the analyst box.

## Public command surface

```powershell
Get-FotonVersion       # module + schema versions (exists now)
Invoke-FotonTriage     # orchestrator: collect -> analyze -> report -> package (v1 behavior)
New-FotonBaseline      # capture a normalized state snapshot
Compare-FotonBaseline  # diff two snapshots into field-level change records + findings
Invoke-FotonParse      # parse raw artifacts in a package into structured records
Invoke-FotonCarve      # recover data from unallocated/slack/remnants
Invoke-FotonAnalysis   # run rules + IOC matching over collected/parsed/diff data
Invoke-FotonIocMatch   # match an IOC list against a package
New-FotonReport        # render HTML from findings + data
Get-FotonPackage       # open/validate a case package, verify hashes
```

Every command (except Version) works against a **package** (case folder or ZIP) as the unit of I/O so layers compose.

## Baseline layer — design guidance

A baseline is a normalized, deterministic snapshot of *stable* configuration — services, scheduled tasks, autoruns, local accounts and group membership, drivers, installed software, firewall rules, shares, listening ports, hardening registry values, certificate stores, and hashes of key system binaries. It is not a triage collection; it excludes volatile state (PIDs, active connections, uptime, sessions).

1. **Deterministic serialization.** Same machine state → same bytes: stable property order, sorted collections, no collection timestamps inside the compared payload (header block only), invariant culture. A baseline is only useful if its hash means something.
2. **Stable identity key per record type.** Service → `Name`. Task → `TaskPath` + `TaskName`. Autorun → `Hive` + `Key` + `ValueName`. Account → `SID`, never username. Driver → `Name`. Software → `DisplayName` + `Publisher`. Firewall → rule `Name` + direction. Certificate → `Thumbprint`. Document the key with each provider.
3. **Field-level diffs.** `{ RecordType, Identity, ChangeType (Added|Removed|Modified), Field, OldValue, NewValue }`.
4. **Provider model**, not one giant function.
5. **Schema versioning.** Stamp WinFoton-era packages as collect 1.0; Foton baselines carry BaselineSchemaVersion. Refuse incompatible diffs.
6. **Diffs feed findings.** The change itself is Tier 1; interpretation is Tier 2. Weight by what changed (new admin, new root CA, Winlogon change = High; software version bump = Info).
7. **Two modes.** Temporal (same host, two times) and fleet (host vs golden/role). Same engine, different report framing.
8. **Provenance caveat.** A baseline taken after intrusion is a picture of the compromised state. Diff proves change between observations — never when or who. Prefer capture at provisioning, hash, store off-host.

## Parse and Carve

- Parsers are pure functions over bytes. No live system, no case-folder logging inside the parser.
- Fixture + test in `tests/Fixtures/` before done. No client data.
- Version-aware; emit unsupported-format records instead of wrong fields.
- Locked files are copied, never read in place; record WAL/journal presence.
- Propose before building full NTFS carving.
- Carved data is Tier 3 until corroborated.

## Non-negotiable invariants

1. **Layer separation.** Collect and Baseline capture may touch a live host. Parse, Carve, Analyze never read live state, never hit the network, identical input → identical output.
2. **Collectors never interpret; analyzers never acquire.**
3. **Windows PowerShell 5.1** in Collect and Baseline — no ternaries, `??`, `-Parallel`, PS7-only cmdlets, external modules, or runtime internet. Parse/Carve/Analyze may require PS7 if stated in manifest and docs.
4. **Collect ships as one flat file** in `dist/`.
5. **Nothing is fatal.** Fail into the manifest and error list. Empty catch blocks in best-effort paths are intentional.
6. **Findings are observations, not conclusions.** Tier 1 fact, Tier 2 inference, Tier 3 hypothesis (carved/uncorroborated). Cite artifact; name benign explanation in WhyItMatters. Never assert compromise, attribution, intent, or causation.
7. **Absence is not evidence.** Missing telemetry → Info visibility-gap finding.
8. **Read-only against targets.** Only writes: output package, and optional `reg load`/`unload` of offline hives (always `finally`). No remediation.
9. **Methodology disclosure stays honest.** Update chain-of-custody and report limitations when the footprint changes.
10. **UTC everywhere**, `yyyy-MM-dd HH:mm:ss`, invariant culture.
11. **Everything is hashed.** SHA-256 on artifacts, packages, baselines, parser inputs; packages carry a verifiable manifest.

## Conventions

- Verb-Noun, approved verbs, `Foton` in the noun (`Get-FotonPackage`).
- One public function per file, filename matching the function.
- Comment-based help on every public function, with at least one realistic example.
- `$script:` module state; no `$global:`.
- Never shadow automatics: `$profile`, `$Event`, `$host`, `$input`, `$matches`, `$error`.
- Registry via `Get-FotonRegValue` / `Get-FotonRegValueList`; hashing `Get-FotonSafeHash`; per-user `Get-FotonUserProfile` / `Get-FotonUserHiveRoot` (names after extract).
- Report strings through `ConvertTo-FotonSafeHtml`. CSS/JS in `'@` here-strings, closer at column 0.
- Comments explain forensic *why* and, for contributors, *where to extend*.

## Verification loop

```powershell
# 1. Parse check every changed file
$e=$null;$t=$null
[System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$t,[ref]$e) | Out-Null
if ($e) { $e | ForEach-Object { "LINE $($_.Extent.StartLineNumber): $($_.Message)" } } else { 'PARSE OK' }

# 2. Static analysis — clean apart from accepted rules
Invoke-ScriptAnalyzer -Path .\src -Recurse -Severity Error,Warning |
  Where-Object RuleName -notin @(
    'PSAvoidUsingWriteHost',
    'PSReviewUnusedParameter',
    'PSUseSingularNouns',
    'PSAvoidUsingEmptyCatchBlock')

# 3. Pester
.\tests\Invoke-FotonTests.ps1

# 4. After Collect extract: build, then run dist/Foton-Collect.ps1 elevated on a VM
.\build\Build-Standalone.ps1
```

## Working style

- Plan before large refactors; focused edits otherwise. Don't reformat regions you aren't changing.
- When adding a heuristic or baseline provider, state expected false-positive sources, not just the rule.
- Bump module and schema versions on behavior or format changes; keep docs in sync.
- If a capability can't be done correctly in PowerShell, say so and propose the alternative. In forensics, a wrong answer is more expensive than a missing one.
