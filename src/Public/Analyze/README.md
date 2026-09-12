# Public/Analyze

Heuristics, IOC lists, and baseline diffs → tiered findings. **Never acquire** live host
state. Identical package in → identical findings out.

`Invoke-FotonAnalysis` is the v1 findings engine, run after `Get-FotonPackage`.
Findings go to `analysis/findings.csv` (not `00_Collection/hashes.csv`).
Compose CSV under `analysis/external/` is in scope: Hayabusa (Sigma bands +
collector-footprint exclusion), PECmd (Prefetch coverage + user-writable paths),
and EvtxECmd (coverage + high-attention EventIds + ExecutableInfo path/pattern
hits). Findings cite the tool. Chainsaw ingest is still open.

One rule file per heuristic is the long-term shape. The first extract is a single
orchestrator so finding titles stay stable across packages.

Each rule: one mock that trips it, one that must not. Cite source artifact; name a
plausible benign explanation in WhyItMatters. Never assert compromise, attribution, or intent.

Missing telemetry is an Info finding (visibility gap), not a clean host.
