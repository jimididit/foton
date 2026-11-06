# Contributing to Foton

Thank you for contributing. Foton is structured so you can add a **collector**, **baseline provider**, **parser**, or **analysis rule** without rewriting the core.

## Ground rules

1. Read [USAGE.md](USAGE.md) so operator-facing behavior stays consistent.
2. Prefer **composing** specialist tools (EZ Tools, Hayabusa, KAPE/ORC) over reimplementing them in PowerShell. Native parsers only when PowerShell can emit *correct* fields.
3. Propose large new capabilities (especially NTFS carve) before building.
4. Update [USAGE.md](USAGE.md) in the same change when you add or change a public command, flatten switch, or `Foton.cmd` verb.

## Development setup

```powershell
git clone https://github.com/jimididit/foton.git
Set-Location foton
Set-ExecutionPolicy -Scope Process Bypass -Force
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
.\tests\Invoke-FotonTests.ps1
```

Rebuild endpoint scripts after Collect/Baseline source changes:

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

Use a throwaway Windows VM for live Collect/Baseline. Collection changes the host.

## Naming and layout

| Rule | Detail |
|------|--------|
| One public function per file | Filename = function name (`New-FotonBaseline.ps1`) |
| Export allow-list | Add the name to `FunctionsToExport` in `Foton.psd1` |
| Comment-based help | `.SYNOPSIS`, `.DESCRIPTION`, and at least one realistic `.EXAMPLE` |
| Placeholders in docs | `CASE-0001`, `D:\Cases`, `HOSTNAME` — no personal host names |
| Layer split | Collect/Baseline may touch a live host. Parse, Carve, and Analyze stay offline |

## Add a live collection task

1. Prefer a new `Invoke-FotonCollection` call in the right category under `src/Public/Collect/`.
2. Emit facts (paths, hashes, registry values). Do not assign severity in Collect.
3. Fail into the manifest; never throw out of the orchestrator. Admin-only work uses `RequiresElevation`.
4. PowerShell **5.1** only in Collect/Baseline (no ternaries, `??`, `-Parallel`, or runtime internet).

Do not embed long LOLBin / credential-theft string lists in Core or the Collect flatten — AMSI will block the script. Keep raw command text in the package; derive hits in Analyze on the workstation.

## Add a baseline provider

Place a provider under `src/Private/Baseline/Providers/`. Document:

- Record type and **stable identity key**
- Compared fields vs ignored (volatile) fields
- Likely false positives

Bump `BaselineSchemaVersion` in `Foton.psd1` when identity keys or compared fields change. Recapture golden/day0 baselines after a schema bump.

## Add an analysis rule

- Input: package data (or a test mock)—never live WMI or the network
- Output: `Add-FotonFinding` with Tier, Artifact, WhyItMatters (include a benign reading), optional NextStep
- Tests: one record that must fire, one that must not
- Never assert compromise, attribution, intent, or causation
- Shared rule helpers go under `src/Private/Analyze/`. Collect runs analysis at the end of a triage, so the Collect flatten includes those helpers: keep them PowerShell **5.1**-compatible and free of long attack-string lists (AMSI). `tests/Unit/Build.Tests.ps1` fails if a flatten calls a Foton function it does not define

## Add a parser

If EZ Tools or Hayabusa already parse the format correctly, prefer copying the artifact into the package and composing that tool on the workstation.

A native `ConvertFrom-Foton*` is appropriate only when PowerShell can be correct. Pure function over a path or bytes. Commit a small fixture under `tests/Fixtures/` (no client data). Unsupported formats get an explicit record—not guessed columns.

## Verification

```powershell
# Parse check a changed file
$e = $null; $t = $null
[System.Management.Automation.Language.Parser]::ParseFile('.\src\Public\Get-FotonVersion.ps1', [ref]$t, [ref]$e) | Out-Null
if ($e) { $e } else { 'PARSE OK' }

# Pester 5+
.\tests\Invoke-FotonTests.ps1

# After Collect/Baseline changes: rebuild + AMSI load check
.\build\Build-Standalone.ps1
.\build\Test-FotonAmsiLoad.ps1 -Path .\dist\Foton-Collect.ps1
```

Accepted ScriptAnalyzer exceptions in this repo include `PSAvoidUsingWriteHost`, empty catch on best-effort collect paths, and a few naming rules. HTML reports must include the offline search/nav chrome (`Get-FotonReportNavCss` and friends)—no CDN.

## Branches and pull requests

- Branch from current `main` (`feature/...`, `fix/...`, `chore/...`), push, and open a PR into `main`. Do not commit to `main` directly.
- The Pester CI check must pass before merge; `main` is protected. Merged branches are deleted automatically.
- Keep a PR to one change when practical. Bump `ModuleVersion`, `ReleaseDate`, and the schema version you changed in `Foton.psd1` for behavior or format changes, and add a `ReleaseNotes` entry.

## What we will not accept

- Remediation, process kill, quarantine, or “repair” switches
- Analyze/Parse/Carve that reads the live registry, filesystem state outside the package, or the network
- Findings that assert compromise, attribution, or intent
- Expanding LOLBin/RAT lists without noting false-positive sources
- Obfuscating the Collect flatten to evade antivirus

## License

By contributing, you agree that your contributions are licensed under the [MIT License](../LICENSE).
