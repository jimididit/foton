# Architecture

Foton is built so **forensic triage**, **state comparison** (baseline now vs later, or host vs golden), and **security audits** share one package format, one findings model, and one report engine.

## Package as the unit of work

A **package** is a case folder or a ZIP of that folder: hashed artifacts, a manifest, and (after analysis) findings.

```
Collect (endpoint)  →  package  →  Parse / Baseline diff / Analyze / Report (workstation)
```

You should be able to collect on Monday, baseline-diff on Thursday, and re-render HTML without running anything on the target again.

Analyze reads the **package on disk** (`Get-FotonPackage`). Do not rely on an in-process collect cache.

## Layers

See `src/README.md` for folder mapping. Rule of thumb:

- **Collect / Baseline capture** - may use WMI, registry, files on a live OS. PowerShell 5.1. Ships flat.
- **Parse / Carve / Analyze / Report / Baseline diff** - bytes and JSON/CSV already in the package. Deterministic. No network.

## Findings

| Tier | Meaning |
|------|---------|
| 1 | Observed artifact, stated as fact |
| 2 | Supported inference; other readings possible |
| 3 | Hypothesis; carved or uncorroborated data only |

Severity (High/Medium/Low/Info) is attention, not “malware score.” WhyItMatters must include a plausible benign explanation.

## Privilege / coverage profiles

Collect does **not** require Administrator. A locked-down work PC is a valid target.

| Profile | When | What you get |
|---------|------|----------------|
| **Elevated** | Admin token | Full surfaces including Security log, Prefetch listing **and copies**, Amcache/SRUM copies, VSS, auditpol, other users (with `-LoadUserHives`) |
| **StandardUser** | Default if not elevated | Current user's processes, HKCU, readable HKLM, network snapshot, that profile's files, logs the token can read |

Tasks that cannot succeed without admin are **skipped** (`SkippedNotElevated` in the manifest), not failed. `collection_coverage.json` plus an Info finding state the gap. `-RequireAdministrator` exits instead of collecting thin.

Baseline capture is privilege-aware: record what could not be read (`coverage.json`) rather than inventing empty state. Per-user rows need a loaded hive.

## Coverage vs architecture

Layers say *where code runs*. [docs/COVERAGE.md](COVERAGE.md) says *which Windows artifacts* belong in Collect vs Baseline vs Parse, what is P0 next, and what Foton will not become (memory imager, EDR, CIS scorer).

## Later: in-report artifact viewer

See [docs/TODO.md](TODO.md). Findings-first HTML with search/nav is the current report; a full CSV/JSON artifact browser is a **consideration**, not scheduled.

## Command prefix

Public cmdlets: `Verb-FotonNoun` (e.g. `New-FotonBaseline`). Private helpers use the same prefix so the flattened collector has unique names.

## Standalone collect

`build/Build-Standalone.ps1` emits `dist/Foton-Collect.ps1`. Operators on an endpoint never `Import-Module Foton`. On a workstation clone, `Foton.cmd` wraps analyze/baseline/compare/parse/ioc/carve (`docs/USAGE.md`).
