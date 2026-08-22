# Architecture

Foton is built so **forensic triage**, **state comparison** (baseline now vs later, or host vs golden), and **security audits** share one package format, one findings model, and one report engine.

## Package as the unit of work

A **package** is a case folder or a ZIP of that folder: hashed artifacts, a manifest, and (after analysis) findings.

```
Collect (endpoint)  →  package  →  Parse / Baseline diff / Analyze / Report (workstation)
```

You should be able to collect on Monday, baseline-diff on Thursday, and re-render HTML without running anything on the target again.

v1 (`WinFoton.ps1`) still analyzes in the same process as collection using an in-memory cache. Extracting Analyze to read the package from disk is what makes that loop real.

## Layers

See `src/README.md` for folder mapping. Rule of thumb:

- **Collect / Baseline capture** — may use WMI, registry, files on a live OS. PowerShell 5.1. Ships flat.
- **Parse / Carve / Analyze / Report / Baseline diff** — bytes and JSON/CSV already in the package. Deterministic. No network.

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
| **Elevated** | Admin token | Full v1 surfaces including Security log, Prefetch, VSS, auditpol, other users (with `-LoadUserHives`) |
| **StandardUser** | Default if not elevated | Current user's processes, HKCU, readable HKLM, network snapshot, that profile's files, logs the token can read |

Tasks that cannot succeed without admin are **skipped** (`SkippedNotElevated` in the manifest), not failed. `collection_coverage.json` plus an Info finding state the gap. `-RequireAdministrator` exits instead of collecting thin.

Baseline capture of machine-wide services/drivers will be similarly privilege-aware when implemented: record what could not be read rather than inventing empty state.

## Later: in-report artifact viewer

See [docs/TODO.md](TODO.md). Findings-first HTML is the v1 report; a navigable CSV/JSON viewer inside the same package is a planned extension, not part of the Collect extract.

## Command prefix

Public cmdlets: `Verb-FotonNoun` (e.g. `New-FotonBaseline`). Private helpers: `Verb-FotonNoun` as well so the flattened collector has unique names.

The frozen file `WinFoton.ps1` keeps historical names (`Add-Finding`, `Get-SafeHash`).

## Standalone collect

`build/Build-Standalone.ps1` emits `dist/Foton-Collect.ps1`. Operators on an endpoint never `Import-Module Foton`. On a workstation clone, `Foton.cmd` wraps analyze/baseline/compare/parse/ioc/carve (`docs/USAGE.md`).
