# Public/Analyze

Heuristics, IOC lists, and baseline diffs → tiered findings. **Never acquire** live host
state. Identical package in → identical findings out.

`Invoke-FotonAnalysis` is the v1 findings engine, run after `Get-FotonPackage`.
Findings go to `analysis/findings.csv` (not `00_Collection/hashes.csv`).
Compose CSV under `analysis/external/` is in scope: Hayabusa (Sigma bands +
collector-footprint exclusion), PECmd (Prefetch coverage + user-writable paths),
and EvtxECmd (coverage + high-attention EventIds + ExecutableInfo path/pattern
hits). Findings cite the tool. RECmd, Chainsaw, LECmd, JLECmd, and AmcacheParser
output is inventoried but not ingested yet.

One rule file per heuristic is the long-term shape. Today `Invoke-FotonAnalysis` is a
single orchestrator so finding titles stay stable across packages; shared rule helpers
live in `src/Private/Analyze/` (shipped in the Collect flatten, so PowerShell 5.1 only).
Operator-facing noise rules (per-user services, collection-window exclusion, transient
accounts, ServiceDll) are documented in [docs/USAGE.md](../../../docs/USAGE.md).

Each rule: one mock that trips it, one that must not. Cite source artifact; name a
plausible benign explanation in WhyItMatters. Never assert compromise, attribution, or intent.

Missing telemetry is an Info finding (visibility gap), not a clean host.
