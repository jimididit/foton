# Lab setup — host editor, guest collector

Do **not** move Cursor or this git repo’s “main” editing into the VMware guest. Chat history lives with Cursor on the **host**. A new conversation on the host still has the repo: start it with `AGENTS.md`, `docs/MIGRATION.md`, and this file.

## Split of work

| Machine | Role |
|---------|------|
| **Host (this PC, Cursor)** | Edit source, commit, Pester that does not need a live Windows collect, docs |
| **Windows 11 VMware guest** | `Import-Module`, Defender/AMSI-sensitive loads, elevated or standard-user `.\WinFoton.ps1`, later `dist/Foton-Collect.ps1` |

The guest is a **target**, like an endpoint. Collection will change it (prefetch, event logs, optional `reg load`). Use a snapshot **before** the first collect so you can revert.

## Sync code: git, not a shared folder

VMware shared folders (`\\vmware-host\Shared Folders\...`) are the same bytes the **host** Defender scans. That is how AMSI/Defender on the host kept blocking Foton. Prefer:

1. Push from the host (`origin` GitHub/GitLab/local bare repo).
2. In the guest: `git clone` / `git pull` to a path **only the guest uses** (e.g. `C:\src\foton`).
3. In the **guest** only: Windows Security → Exclusions → that folder (optional but practical while pattern lists look like LOLBins).

If you have no remote yet, a USB stick, `scp`, or a one-way copy into the guest is fine. Avoid editing the same checkout from both sides at once.

## Guest first-time setup

- Snapshot: “clean, tools installed, Foton never run.”
- PowerShell 5.1 (inbox). Optional: PS 7, Pester 5 (`Install-Module Pester -Scope CurrentUser`), PSScriptAnalyzer.
- Clone, then:

```powershell
Set-Location C:\src\foton
Set-ExecutionPolicy -Scope Process Bypass -Force
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
.\WinFoton.ps1 -NoZip -OutputPath C:\FotonCases   # frozen v1
# After git pull of step 5:
.\build\Build-Standalone.ps1
.\dist\Foton-Collect.ps1 -NoZip -OutputPath C:\FotonCases
```

Compare **task names, file names, column sets, and finding titles** against a `WinFoton.ps1` package from the same snapshot — not PIDs or connection counts.

**Baseline schema 1.1.0:** after pulling this tree, recapture day0 (`New-FotonBaseline` or `Foton.cmd baseline`). Compare will refuse a 1.0.0 JSON against 1.1.0.

Workstation (host or guest) without memorizing cmdlets: `Foton.cmd help` — see `docs/USAGE.md`.

Revert the snapshot after noisy collect runs, or keep a second snapshot “dirty IR box.”

## Continuing after this chat is gone

On the **host**, open this repo in Cursor and tell the agent:

- Read `AGENTS.md` and `docs/MIGRATION.md`.
- Next: more parsers (EVTX, jumplists), richer IOC, shares/binary-hash baseline providers. Carve is **signature scan only** (`Invoke-FotonCarve`); no NTFS unallocated in PowerShell. Flatten after Core/Collect: `.\build\Build-Standalone.ps1`. Recapture baselines after schema bumps. Easy path: `Foton.cmd` / `docs/USAGE.md`. Public-release checklist: `docs/TODO.md`.
- Live collect is still `WinFoton.ps1`. Do not rename internals in that file.
- Product name is **Foton**. Lab policy is this file.

You do not need Cursor installed in the VM for that loop. Optional: install Cursor in the guest later for debugging a collect failure **in place**; treat that as a throwaway session, not the source of truth for chat or git.
