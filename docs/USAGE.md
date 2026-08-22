# Operator usage (keep this short)

Foton has two different machines in mind. Mixing them is what feels “too much PowerShell.”

## 1. The PC you are collecting from (endpoint)

You do **not** install a module. You do **not** run `Import-Module`.

1. On a trusted lab/workstation: `.\build\Build-Standalone.ps1`
2. Copy **only** `dist\Foton-Collect.ps1` to the target (USB, RMM, email — whatever you already use).
3. Right-click → Run with PowerShell, or:
   `powershell -ExecutionPolicy Bypass -File .\Foton-Collect.ps1`
4. Open **`Foton_Report.html` inside the new case folder**. That is the whole collect loop.

Optional: `-NoZip`, `-RequireAdministrator`, same switches as `WinFoton.ps1`.

## 2. The PC you analyze on (workstation, this repo)

Double-click **`Foton.cmd`** or:

```
Foton.cmd analyze   D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd baseline  D:\Baselines\this-pc.json
Foton.cmd compare   D:\Baselines\day0.json D:\Baselines\day1.json
Foton.cmd parse     D:\file.lnk
Foton.cmd ioc       D:\Cases\Foton_...Z D:\intel\iocs.txt
Foton.cmd carve     D:\blob.bin
Foton.cmd help
```

`Foton.cmd` is a wrapper. PowerShell cmdlets remain for people who already live in a shell.

## What we will not hide

- Live collect **changes the host**. The report says so.
- Findings are **observations**. The wrapper will not say “infected.”
- A baseline taken after an incident is a picture of that state. Recapture after provider/schema changes (see BaselineSchemaVersion).

## Gaps before a public release (testing / UX)

See `docs/TODO.md` section “Public-release bar.” Until those are ticked, treat Foton as a lab/internal tool.
