# Public/Analyze

Heuristics, IOC lists, and baseline diffs → tiered findings. **Never acquire** live host
state. Identical package in → identical findings out.

`Invoke-FotonAnalysis` is the v1 findings engine, run after `Get-FotonPackage`.
Findings go to `analysis/findings.csv` (not `00_Collection/hashes.csv`).

One rule file per heuristic is the long-term shape. The first extract is a single
orchestrator matching `WinFoton.ps1` so titles and artifacts stay comparable.

Each rule: one mock that trips it, one that must not. Cite source artifact; name a
plausible benign explanation in WhyItMatters. Never assert compromise, attribution, or intent.

Missing telemetry is an Info finding (visibility gap), not a clean host.
