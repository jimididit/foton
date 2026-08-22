# Private/Patterns

Heuristic **data**, not code (plain text/CSV so Core .ps1 files are not AMSI-flagged for LOLBin or RAT substrings).

| File | Used by |
|------|---------|
| `UserWritablePatterns.txt` | `Test-FotonUserWritablePath` — regex fragments; `ProgramData` is often not user-writable |
| `SuspiciousCommandPatterns.txt` | `Test-FotonSuspiciousCommand` — case-insensitive substrings; admin tools match too |
| `RemoteAccessToolNames.txt` | Software collect `remote_access_tool_indicators` — substring presence in installed software, processes, services |
| `HardeningRegistryChecks.csv` | Security collect `hardening_registry_settings` — Name, Path, Expected, Note |

Keep the two `.txt` command/path lists identical to the arrays in `WinFoton.ps1` until that script is retired. Hardening and RAT names are still **inline in `WinFoton.ps1`**; change both when you edit those lists.

The standalone collector build must **embed** these files (or their contents) — a module tree is not deployed to endpoints.

**False positives:** RAT names include legitimate RMM and file-transfer tools (PuTTY, WinSCP, FileZilla, AnyDesk, TeamViewer). Hardening “Expected” values are a common secure baseline, not a finding of compromise when they differ (home editions, domain GPO, older builds).

Adding a pattern: append a line (or CSV row), add a unit test that a benign mock does not match if you tighten a rule, note false positives in the PR.
