# Contributing to Foton

Thank you for contributing. Foton is structured so you can add a **collection task**, **baseline provider**, **parser**, or **analysis rule** without rewriting the core.

Foton is C#: four single-file executables on the .NET Framework that ships with Windows (4.6.2+). The PowerShell 1.38.x line is final and unmaintained (see [SECURITY.md](../SECURITY.md)); all work targets `main`. Open an issue before starting a large feature.

## Development setup

Prerequisites: Windows and the .NET SDK pinned in [`global.json`](../global.json). The SDK only builds; the executables target `net462` and need nothing installed on endpoints.

```powershell
git clone https://github.com/jimididit/foton.git
Set-Location foton
dotnet build Foton.sln -c Release -warnaserror
dotnet test Foton.sln -c Release --no-build
.\cli\Foton.Collect.Cli\bin\Release\net462\foton-collect.exe -Version
```

Use a throwaway Windows VM for live Collect and Baseline runs. Collection changes the host.

## Layout

| Project | Layer | Touches the live host? |
|---------|-------|------------------------|
| `src/Foton.Core` | Session, task runner, CSV/JSON/text writers, hashing, custody, coverage | No (callers supply host facts) |
| `src/Foton.Win` | P/Invoke, WMI, COM, registry, and System32 tool helpers that read the host | Yes |
| `src/Foton.Win.Ui` | The console's appearance only: theme palettes, contrast math, and the two Windows calls for a dark title bar and scroll bars | No (UiRules: no registry, files, processes, WMI, or network) |
| `src/Foton.Collect` | Collect categories (`<Category>Collection.cs`) and the orchestrator | Yes |
| `src/Foton.Baseline.Capture` / `.Compare` | Baseline providers / offline diff | Capture yes, Compare no |
| `src/Foton.Analyze`, `Foton.Report` | Rules (`Rules/*.cs`), findings, HTML reports | No |
| `src/Foton.Parse`, `Foton.Carve`, `Foton.Package` | Parsers, carve, package open/verify | No |
| `src/Foton.Tools`, `Foton.Patterns` | Tool catalog / compose, workstation pattern lists | No (only `foton tools` downloads, on request) |
| `assets/brand` | The Foton mark (SVG masters) and `foton.ico`, which every executable carries (`cli/Directory.Build.targets`; IconRules) | No |
| `cli/*` | `foton-collect.exe`, `foton-baseline.exe`, `foton.exe`, `foton-console.exe` (`cli/Foton.Gui`). `foton.exe` and the console carry the two collectors as resources (`cli/EmbedCollectors.targets`) for `bundle` and the Collectors tab | Collect and baseline yes; `foton.exe` and the console no (they write the collectors into a bundle, never run them) |

| Rule | Enforced by |
|------|-------------|
| One `.exe` per role, no loose DLLs (project DLLs merged by ILRepack, `cli/ILRepack.targets`) | `tests/Foton.ArchitectureTests` (SingleFileRules) |
| Offline layers never reference `Foton.Win`, WMI, or HTTP | LayerRules |
| Endpoint executables never reference Parse, Carve, Tools, or Patterns | LayerRules |
| P/Invoke only in `src/Foton.Win`, with a size test per struct, and `src/Foton.Win.Ui`, limited to `DwmSetWindowAttribute` and `SetWindowTheme`; no `Assembly.Load(byte[])` | LayerRules, BinaryRules, UiRules, struct size tests |
| A console theme keeps WCAG contrast (4.5:1 text, 3:1 borders and accent) | PaletteTests |
| The carried collectors are build-order references only (never code references), and their bytes equal the published executables | EmbeddedCollectorRules |
| Runtime dependencies are in-box .NET Framework assemblies only; NuGet packages are build- or test-time | `Directory.Packages.props` review + vulnerable-package CI step |

Version and schema numbers live once in [`Directory.Build.props`](../Directory.Build.props) and are read at runtime (`FotonVersion`).

## Ground rules

1. Read [USAGE.md](USAGE.md) so operator-facing behavior stays consistent, and update it in the same PR when you add or change an executable switch, verb, or output.
2. Collect and Baseline capture may touch a live host. Parse, Carve, and Analyze read only the package: no live state, no network, identical input gives identical output.
3. Collectors record facts; analyzers interpret. Never assign severity in Collect.
4. Nothing is fatal: a task fails into the manifest and error list, never out of the run.
5. Read-only against the target. The only writes are the output package and the optional `-LoadUserHives` mount, always unloaded in `finally`.
6. A path read from the host is opened only when it is plainly local (`Hashing.IsLocalPath`), and a cloud-only placeholder is never read (`Hashing.IsCloudPlaceholder`).
7. UTC everywhere (`yyyy-MM-dd HH:mm:ss`, invariant culture), and SHA-256 on everything collected.
8. Prefer **composing** specialist tools (EZ Tools, Hayabusa, KAPE/ORC) over reimplementing them. Propose large capabilities (especially NTFS carving) before building.
9. Public docs never name personal hosts or guess where the reader keeps files. Write paths Foton creates literally (`C:\Foton\Cases`, `C:\Foton\Baselines`). For anything only the reader knows, use a quoted placeholder with no drive letter, ending in what it is: `"\path\to\folder"`, `"\path\to\case-folder"`, `"\path\to\Foton_case.zip"`. Never invent real-looking paths (`D:\Cases`, `Foton_HOSTNAME_...`), never put `<angle brackets>` in a command (PowerShell reads `<` as an operator), and do not hide steps in file-finding scripts; tell the reader what to point at. Prefer a plain GUI step (Extract All) over a script that does the same. Commands that ask a question get the switch that answers it (`-Force`), so a pasted block does not feed its next line in as the answer. Keep the README quick start to a few commands a beginner can read at a glance, including the one-line hash check before anything runs; the provenance check and multi-step flows belong in `docs/GETTING-STARTED.md`. Paste every changed command into Windows PowerShell 5.1 before merging.

## Add a collection task

Add a `Task(s, Cat, "<name>", "<description>", TaskFormat.Csv, () => ...)` call in the right `src/Foton.Collect/<Category>Collection.cs`, in the category's task order. Return rows (dictionaries or a row class). Use `elevated: true` for Administrator-only work, so a standard-user run records `SkippedNotElevated` instead of an empty success. Copy tasks return `CopyRow`s through `HostCopy`, so their manifest status reflects per-file failures. Add a unit or integration test in `tests/Foton.Tests/CollectTests.cs`.

Do not ship long LOLBin or credential-theft string lists in an endpoint executable. Keep raw command text in the package and derive hits in Analyze on the workstation (`Foton.Patterns`).

## Add a baseline provider

Add a `Provider` to the matching `src/Foton.Baseline.Capture/*Providers.cs` file and list it in `Providers.All`. Document:

- Record type and **stable identity key** (`IdentityFields`)
- Compared fields (`ComparedFields`) versus volatile fields left out
- Likely false positives (`FalsePositives`)

Bump `FotonBaselineSchemaVersion` when records change. If identity keys and compared fields stay the same, add the version and its change note to `BaselineSchema` in `src/Foton.Core/Baseline.cs` so Compare keeps accepting older baselines; otherwise Compare must refuse the old schema.

## Add an analysis rule

- Input: package data (or a test fixture), never live state or the network.
- Output: a finding with Tier, Artifact, WhyItMatters (name a benign reading), and an optional NextStep. Tier 1 is an observed fact, Tier 2 an inference, Tier 3 a hypothesis.
- Never assert compromise, attribution, intent, or causation. Absence of telemetry is an Info visibility-gap finding, not evidence.
- Tests: one package that must fire, one that must not.

## Add a parser

If EZ Tools or Hayabusa already parse the format correctly, prefer copying the artifact into the package and composing that tool on the workstation. A native parser in `src/Foton.Parse` is a pure function over bytes, wired into `ParseRunner`. Commit a small fixture under `testdata/` (no client data). Unsupported formats get an explicit record, not guessed columns.

## Reports

HTML goes through `Foton.Report`: escape every host value, and include the offline search and section navigation from `ReportChrome`. No CDN, no remote assets.

## Golden files

`testdata/golden/` holds expected outputs for fixture packages (findings, reports, IOC hits), compared byte for byte. Change them only for a deliberate difference, make the change exactly as large as the behavior change, and say why in the PR. `.gitattributes` keeps those bytes free of line-ending conversion.

## Branches and pull requests

- Branch from current `main` (`feat/...`, `fix/...`, `docs/...`), push, and open a PR into `main`. `main` is protected; do not commit to it directly.
- CI must pass before merge. Keep a PR to one change when practical.
- Behavior or format changes bump the version and schema numbers in `Directory.Build.props`, set `FotonReleaseDate`, and add a line to that version's section in [`CHANGELOG.md`](../CHANGELOG.md) (a test fails when the section is missing or its date differs).

## Releases

Maintainers release from `main` after the version PR merges: set `FotonVersion` (and `FotonPrerelease` for a prerelease) and `FotonReleaseDate` in `Directory.Build.props`, then push a matching `vX.Y.Z` tag (the workflow runs for `v2.*` and `v3.*` tags). `.github/workflows/release-v2.yml` refuses a mismatched tag or a version with no `CHANGELOG.md` section, builds and tests, writes `SHA256SUMS.txt`, attests build provenance, and creates the GitHub release (a prerelease when the tag has a suffix). Run the workflow manually for a dry run: the executables are uploaded as a workflow artifact and nothing is published.

## What we will not accept

- Remediation, process kill, quarantine, or "repair" switches
- Parse, Carve, or Analyze code that reads the live registry, filesystem state outside the package, or the network
- Findings that assert compromise, attribution, or intent
- Expanding LOLBin/RAT lists without noting false-positive sources
- Obfuscating or packing an executable to evade antivirus

## License

By contributing, you agree that your contributions are licensed under the [MIT License](../LICENSE).
