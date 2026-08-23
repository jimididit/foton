# Isolated Windows lab (contributors)

Use a **throwaway Windows VM** as the live target. Edit and commit on a workstation checkout; copy or `git pull` onto the VM. Do not treat a hypervisor shared folder as the only copy of the tree: some hosts scan those paths and will flag Foton pattern lists (LOLBin-like strings).

The VM is an **endpoint**. Collection changes it (Prefetch, event logs, optional `reg load`). Snapshot before the first collect if you want to revert.

## First run on the VM

PowerShell 5.1 (inbox). Optional: PowerShell 7, Pester 5, PSScriptAnalyzer.

```powershell
Set-Location C:\src\foton
Set-ExecutionPolicy -Scope Process Bypass -Force
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
.\dist\Foton-Collect.ps1 -NoZip -OutputPath C:\FotonCases
.\dist\Foton-Baseline.ps1 -NoZip -OutputPath C:\Baselines
```

Also exercise **standard-user** Collect (no admin): Security log and Prefetch copies should be `SkippedNotElevated`, not empty-success.

After a **BaselineSchemaVersion** bump, recapture day0. Compare refuses mismatched schemas. Workstation: `Foton.cmd help` ([USAGE.md](USAGE.md)).

Optional: Windows Security exclusion on the VM clone path while iterating.

This file is for **people building Foton**, not operators. Operators: [USAGE.md](USAGE.md).
