# Private/Patterns

Heuristic **data**, not code (plain text/CSV so Core .ps1 files are not AMSI-flagged for LOLBin or RAT substrings).

| File | Used by |
|------|---------|
| `UserWritablePatterns.txt` | `Test-FotonUserWritablePath` - regex fragments; `ProgramData` is often not user-writable |
| `SuspiciousCommandPatterns.txt` | `Test-FotonSuspiciousCommand` - case-insensitive substrings; admin tools match too. **Workstation only - not embedded in the flatten** |
| `RemoteAccessToolNames.txt` | Software collect `remote_access_tool_indicators` - substring presence in installed software, processes, services |
| `HardeningRegistryChecks.csv` | Security collect `hardening_registry_settings` - Name, Path, Expected, Note |

Edit these files in `src/Private/Patterns/` only. Historical v1 scripts, if present in git, may still contain inline copies - do not treat those as the source of truth.

The standalone collector build must **embed** these files (or their contents) - a module tree is not deployed to endpoints - with one exception.

## Why `SuspiciousCommandPatterns.txt` is not embedded

Keeping the strings in `.txt` protects the Core `.ps1` files, but the flatten build
used to inline them as a literal array, which put the protection back at square one.
Defender AMSI blocked the entire generated collector at load as
`Trojan:PowerShell/PSAttackTool.A`, severity Severe, and quarantined it. Isolation
testing confirmed that this one array is the trigger; `UserWritablePatterns`,
`RemoteAccessToolNames`, and `HardeningRegistryChecks` all load clean.

The list is a contiguous run of `invoke-mimikatz`, `sekurlsa`, `reg save hklm\sam`,
`comsvcs.dll`, `minidump`, and similar - indistinguishable from an offensive toolkit
to a content scanner, and reasonably so.

`build/Build-Standalone.ps1` therefore emits `SuspiciousCommandPatterns = @()`.
Matching is analysis rather than acquisition, so it now runs in
`Invoke-FotonAnalysis` on the workstation against the raw
`Command` / `Actions` / `CommandLine` columns, and a pattern-free session raises an
Info visibility-gap finding so the silence is not mistaken for a clean result.

**Do not restore the embed by encoding, splitting, or otherwise obfuscating the
strings.** Obfuscation is itself an antivirus signal, and an examiner must be able to
read what the collector does. `build/Test-FotonAmsiLoad.ps1` guards the regression;
the `[Parser]::ParseFile` check cannot, because it never invokes AMSI.

**False positives:** RAT names include legitimate RMM and file-transfer tools (PuTTY, WinSCP, FileZilla, AnyDesk, TeamViewer). Hardening “Expected” values are a common secure baseline, not a finding of compromise when they differ (home editions, domain GPO, older builds).

Adding a pattern: append a line (or CSV row), add a unit test that a benign mock does not match if you tighten a rule, note false positives in the PR.
