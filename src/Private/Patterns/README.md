# Private/Patterns

Heuristic **data**, not code (plain text so Core .ps1 files are not AMSI-flagged for LOLBin substrings).

| File | Used by |
|------|---------|
| `UserWritablePatterns.txt` | `Test-FotonUserWritablePath` — regex fragments; `ProgramData` is often not user-writable |
| `SuspiciousCommandPatterns.txt` | `Test-FotonSuspiciousCommand` — case-insensitive substrings; admin tools match too |

Keep these lists identical to the arrays in `WinFoton.ps1` until that script is retired.

The standalone collector build must **embed** these files (or their contents) — a module tree is not deployed to endpoints.

Adding a pattern: append a line, add a unit test that a benign mock does not match if you tighten a rule, note false positives in the PR.
