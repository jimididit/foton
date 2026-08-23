# Operator usage (keep this short)

Foton has two different machines. Mixing them is what feels like “too much PowerShell.”

## 1. Endpoint (collect / baseline capture)

You do **not** install a module. You do **not** run `Import-Module`.

On a trusted workstation:

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

Copy **only** `dist\Foton-Collect.ps1` and/or `dist\Foton-Baseline.ps1` to the target (USB, RMM, email).

```
powershell -ExecutionPolicy Bypass -File .\Foton-Collect.ps1
powershell -ExecutionPolicy Bypass -File .\Foton-Baseline.ps1
```

Default output is the current user’s **Desktop**. Open `Foton_Report.html` or `Foton_Baseline.html` **inside** the new folder.

Send the **ZIP + `*_PACKAGE_HASH.txt`** (or the whole folder). HTML alone is not the package.

Useful switches: `-NoZip`, `-RequireAdministrator`, `-OutputPath D:\Cases`, `-CaseNumber CASE-0001`, `-EventLogDays 14`. Same collect switches as the flatten entry point (see root `README.md`).

`Foton.cmd baseline D:\Baselines` on a workstation writes a package. `Foton.cmd baseline D:\x.json` still writes a bare JSON. Compare accepts a folder that contains `baseline.json` and writes **`Foton_BaselineCompare.html`** next to the second JSON.

## 2. Workstation (this repo)

```
Foton.cmd analyze   D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd baseline  D:\Baselines
Foton.cmd compare   D:\Baselines\day0.json D:\Baselines\day1.json
Foton.cmd parse     D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd ioc       D:\Cases\Foton_...Z D:\intel\iocs.txt
Foton.cmd carve     D:\blob.bin
Foton.cmd help
```

Parse → `analysis\Foton_Parse.html` + `parsed_records.csv`. Analyze → `Foton_Report.html` + `analysis\findings.csv`. Different products.

## What we will not hide

- Live collect **changes the host**.
- Findings are **observations**, not “infected.”
- A baseline taken after an incident is a picture of that state. Schema **1.12.0** cannot compare against older baseline JSON.

Until the public-release bar in [TODO.md](TODO.md) is mostly green, treat Foton as a lab/internal tool.
