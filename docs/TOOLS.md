# External tool provisioning

**Status: implemented for Hayabusa in 1.28.0** (`Install-FotonTool` / `Foton.cmd tools`). Chainsaw and EZ Tools remain PATH-only until catalogued. Strategy: [LANDSCAPE.md](LANDSCAPE.md). Backlog: [TODO.md](TODO.md). Operator how-to: [USAGE.md](USAGE.md).

## Problem

Collect is already as easy as it gets: the target user runs one `.ps1` and hands back a zip plus hashes. The workstation side was not: compose resolved tools by `Get-Command` only, so a missing PATH looked like a clean host.

Goal: after a one-time setup command, compose just works, and the operator never thinks about `PATH`.

## Shape (shipped)

- `Install-FotonTool` (public), with a `Foton.cmd tools` wrapper.
- Lists supported tools (`-List`), states source URL + expected SHA-256 + destination, confirms (or `-Force`), unpacks to a Foton-owned tool root, writes `tools.json`.
- `compose` stays fully offline and never prompts. Hayabusa `NotOnPath` names `Install-FotonTool`.
- Resolution order: `-ToolPath` → `tools.json` → PATH. **PATH is never mutated.**
- Default tool root: `%LOCALAPPDATA%\Foton\tools` (`-ToolRoot` / `-ArchivePath` for offline).
- Catalog pin: `src/Private/Tools/FotonToolCatalog.json` (Hayabusa 4.0.0 + SHA-256).
- Inventory / report: `Version` and `RulesVersion` columns.

Helpers live under `src/Private/Tools/` so they load with the workstation module but are **not** concatenated into the Collect flatten.

### Why the install is not inside compose

1. **Layer separation.** Parse, Carve, and Analyze never hit the network and must give identical output for identical input (invariant 1). A compose run that can fetch a newer Hayabusa mid-case breaks both halves of that. Provisioning a toolbox is not analysis, so it does not live in an analysis command.
2. **Unattended runs.** An interactive prompt makes compose unscriptable. Running it across a directory of packages would hang on a keypress - the same failure as Hayabusa's wizard, which is why Foton passes `-w`.
3. **Blast radius.** Setup writes outside the case. Analysis writes inside it. Keeping those in separate commands keeps that boundary obvious.

### Why not `PATH`

`PATH` was the original sketch and is the wrong mechanism:

- It is persistent global state on someone else's workstation, and uninstalling Foton leaves it behind.
- It can shadow a tool the analyst already had at a different version.
- A user-level `setx`-style change does not affect the shell that made it, so the operator's *next* command still fails. This was observed in practice and cost real time.

Instead: a Foton-owned tool root plus a manifest, and a documented resolution order in `Invoke-FotonExternalParse`:

1. Explicit `-ToolPath` / per-tool override parameter.
2. Foton tool manifest (`tools.json`).
3. `PATH` via `Get-Command`, exactly as today.

Order matters: an analyst with their own EZ Tools layout keeps working untouched, because `PATH` is still honoured and nothing is overwritten. Default tool root `%LOCALAPPDATA%\Foton\tools`, overridable with `-ToolRoot`.

**Never install into a case folder.** Tools there would be swept into the evidence hash manifest.

## Provenance requirements

These are not polish. If Foton installs the tool, Foton is now part of the story of where a finding came from.

| Requirement | Why |
|---|---|
| Record tool **version** in the external parse inventory and the report's External Tool Passes section | The inventory currently carries `Tool, Status, DestRelative, SHA256, Note` and no version. "Hayabusa reported 60 medium hits" is not reproducible without knowing which Hayabusa and which rule set. |
| Pin versions in a repo catalog with expected SHA-256; refuse to install on mismatch | "Latest" means two analysts get different findings from the same package, and an upstream compromise would execute unchecked on a forensic workstation. |
| Record the **rule set** version/commit, not just the binary | Hayabusa findings are a product of the rules far more than the binary. |
| `tools.json` records tool, version, source URL, SHA-256, install date | Lets a report state how the toolbox was acquired, and lets a later run detect drift. |
| No rule updates during analysis | `update-rules` changes what fires. It stays a deliberate, recorded action. |

**Honesty limit to state in the setup output:** where upstream publishes no stable per-file hashes, Foton can only *record* the hash it observed, not verify it against an expected value. Do not print anything that implies verification happened when it did not. This applies to EZ Tools.

## Per-tool reality

| Tool | Acquisition | Assessment |
|---|---|---|
| **Hayabusa** | Versioned GitHub release zip, rules included, no runtime dependency | Clean. Proven end to end on a real package. Correct first target. |
| **Chainsaw** | Versioned GitHub release zip, ships rules/sigma | Straightforward, but the Foton compose path for it is still unverified against a real binary, so install support is worth little until that is tested. |
| **EZ Tools** | Official `Get-ZimmermanTools.ps1`; no published hashes; continuous releases; needs the **.NET 4.7.2** builds, not .NET 6, for a Windows PowerShell workstation | Awkward. The download host **failed TLS from a real workstation during development**, which is why compose still reports six `NotOnPath` rows there. Treat acquisition failure as an expected outcome with a clear manual fallback, never as a bug. |

Also required for isolated workstations: an **offline install path** that points at a folder of already-downloaded release archives. Many DFIR boxes have no direct internet, and that path is also how a lab pins a known-good toolbox.

## Consent and disclosure

- Print tool, version, source URL, expected hash, and destination *before* downloading; require explicit confirmation, with a `-Force`-style switch for automation.
- Write a setup log (outside any case folder).
- Show the upstream license and attribution. Do **not** vendor third-party binaries into this repo: Hayabusa and Chainsaw are GPL-family, and EZ Tools are free but not ours to redistribute. Having the operator acquire from upstream keeps that clean.

## Known risk

A PowerShell module that downloads and executes binaries is textbook malicious behaviour to an EDR, and 1.27.0 exists because Defender quarantined the collector over script content. This code runs on the workstation rather than the endpoint, so the exposure is lower, but expect corporate EDR on an analyst box to object, and do not respond by obfuscating the downloader.

## Maintenance cost

The real long-term cost is the pinned catalog going stale: a pinned release can disappear upstream. Needs a documented refresh path and a sane, *disclosed* fallback when a pin cannot be satisfied - failing loudly is better than silently installing something else.
