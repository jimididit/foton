# Public/Analyze

Heuristics, IOC lists, and baseline diffs → tiered findings. **Never acquire** live host
state. Identical package in → identical findings out.

One rule file per heuristic (or a small family). Each rule: one mock record that trips it,
one that must not. Cite source artifact; name a plausible benign explanation in WhyItMatters.
Never assert compromise, attribution, or intent.

Missing telemetry is an Info finding (visibility gap), not a clean host.
