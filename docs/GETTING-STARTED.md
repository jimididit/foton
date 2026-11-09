# Getting started

This guide takes you from nothing to an analyzed collection. Every command block can be pasted as it is. Where a block needs something only you know, it says so in the text above the block, never inside a path you might paste by accident.

Foton uses **two machines**:

- The **endpoint** is the computer you are examining. You run `foton-collect.exe` (or `foton-baseline.exe`) there. It writes a case folder and a ZIP.
- The **workstation** is your own analysis computer. You copy the ZIP there and run `foton.exe` on it. `foton.exe` never touches the endpoint.

To try Foton out, one computer can play both roles; [step 4](#4-move-the-package-to-the-workstation) shows the shortcut.

## Before you start

- Windows 10, Windows 11, or Windows Server 2016 or newer. Nothing to install: the executables use the .NET Framework that ships with Windows.
- All commands are for **PowerShell**. A PowerShell window shows `PS` at the start of the prompt (`PS C:\Users\you>`). If you are in Command Prompt (`C:\Users\you>`), type `powershell` and press Enter first.
- **Administrator** gives a complete collection. To open PowerShell as Administrator: open the Start menu, type `PowerShell`, right-click **Windows PowerShell**, and choose **Run as administrator**. Without it, Foton still runs and records what it could not read as a visibility gap.

## 1. Download and verify

Paste this block into PowerShell. It creates a `Foton` folder in your user profile, downloads the latest release into it, and checks each file against the published `SHA256SUMS.txt`:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
$foton = Join-Path $env:USERPROFILE 'Foton'
New-Item -ItemType Directory -Path $foton -Force | Out-Null
Set-Location $foton
$exes = 'foton-collect.exe', 'foton-baseline.exe', 'foton.exe'
foreach ($f in $exes + 'SHA256SUMS.txt') {
    Invoke-WebRequest "https://github.com/jimididit/foton/releases/latest/download/$f" -OutFile $f -UseBasicParsing
}
$sums = @{}
Get-Content .\SHA256SUMS.txt | ForEach-Object { $hash, $name = $_ -split '\s+', 2; $sums[($name.Trim() -replace '^\*?(\./)?', '')] = $hash }
foreach ($f in $exes) {
    if ($sums[$f] -and (Get-FileHash $f -Algorithm SHA256).Hash -eq $sums[$f]) { "OK    $f" }
    else { Remove-Item $f; "FAIL  $f  (deleted: it does not match SHA256SUMS.txt; run this block again)" }
}
```

You should see three `OK` lines. A file that does not match is deleted, so it cannot be run by mistake; run the block again. The folder is in your own profile, so other accounts on the computer cannot replace the executables. When you open a new PowerShell window later, go back to it first:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Foton')
```

**What the hash check proves, and what it does not.** It proves each file matches the `SHA256SUMS.txt` published with the same release, so a corrupted or swapped download is caught. It cannot catch someone who replaced both the files and `SHA256SUMS.txt` on the release page, because both come from the same place.

**Prove the build came from this repository (recommended for casework).** The build provenance attestation is signed by GitHub and names the repository, workflow, and commit that built each file. Checking it needs the [GitHub CLI](https://cli.github.com/) (`gh`), signed in with `gh auth login`:

```powershell
Get-ChildItem *.exe | ForEach-Object { gh attestation verify $_.Name --repo jimididit/foton }
```

Each file should report a successful verification. If you cannot install `gh`, Foton still runs; record in your case notes that only the hash was checked.

**Windows SmartScreen or antivirus.** The executables are not code-signed yet, so Windows may warn when one runs from File Explorer; running them from PowerShell as shown here avoids that prompt. Security products sometimes flag forensic tools, because they read the same places attackers do. See [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector); never modify the executable to get past a scanner.

## 2. Collect on the endpoint

In PowerShell **as Administrator**, in the `Foton` folder:

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "Your Name"
```

Use your own case number and name, or leave them as they are for a test. A collection takes a few minutes. When it finishes it prints the case folder, the report, and the ZIP. They are under `C:\Foton\Cases` (on the drive Windows is installed on), in a folder named `Foton_<computer name>_<date and time in UTC>Z`.

`C:\Foton\Cases` is created so that only SYSTEM, Administrators, and the account that ran the collection can read it. To write somewhere else, add `-OutputPath` with a folder of your choice, for example `-OutputPath E:\Cases` for a USB drive mounted as `E:`.

Live collection changes the computer a little (it starts processes and writes the output). If your case needs a memory or disk image, take it **before** collecting.

## 3. Open the report

```powershell
$case = Get-ChildItem C:\Foton\Cases -Directory -Filter 'Foton_*' | Sort-Object LastWriteTime | Select-Object -Last 1
Invoke-Item (Join-Path $case.FullName 'Foton_Report.html')
```

The report lists **observations**, each with the artifact it came from. It does not say whether the computer is compromised, and an empty list does not mean it is clean.

## 4. Move the package to the workstation

Copy two files from `C:\Foton\Cases` on the endpoint: the ZIP and the `_PACKAGE_HASH.txt` beside it. The HTML report alone is not the package.

On the workstation, download Foton the same way ([step 1](#1-download-and-verify)), then make a `Cases` folder and open it in File Explorer:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Foton')
New-Item -ItemType Directory -Path .\Cases -Force | Out-Null
explorer (Resolve-Path .\Cases).Path
```

Copy the ZIP and its `_PACKAGE_HASH.txt` into the window that opened. Then verify the ZIP and extract it:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Foton')
$zip = Get-ChildItem .\Cases -Filter 'Foton_*.zip' | Sort-Object LastWriteTime | Select-Object -Last 1
.\foton.exe package $zip.FullName
if ($LASTEXITCODE -eq 0) {
    Expand-Archive $zip.FullName -DestinationPath .\Cases -Force
    $case = Join-Path (Resolve-Path .\Cases) $zip.BaseName
} else { $case = $null; "Not extracted: the package check above reported a problem." }
```

`foton package` re-hashes every file against the list made at collection time and reports anything changed or missing. The ZIP is extracted only when every file matches. If it reports a problem, copy the package from the endpoint again; if it still fails, record that in your case notes, because the package changed after collection.

**Trying Foton on one computer?** Skip the copy and point `$case` at the case folder Foton just wrote (run this in the same Administrator window you collected from):

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Foton')
$case = (Get-ChildItem C:\Foton\Cases -Directory -Filter 'Foton_*' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

## 5. Analyze on the workstation

With `$case` set by step 4:

```powershell
.\foton.exe parse $case
.\foton.exe compose $case
.\foton.exe analyze $case
Invoke-Item (Join-Path $case 'Foton_Report.html')
```

- `parse` reads the copied Prefetch, shortcuts, jump lists, event logs, and Amcache.
- `compose` runs specialist tools (Hayabusa, Chainsaw, Eric Zimmerman's tools) over the copied files, if you installed them (next section). Tools that are missing are listed, not errors.
- `analyze` runs last and rebuilds the report with everything above.

### Optional: install the specialist tools

Hayabusa and Chainsaw install with one command each. Foton downloads the release it is pinned to, checks its SHA-256, and installs it under `%LOCALAPPDATA%\Foton\tools`. Without `-Force` it asks first; `-Force` answers yes, so the block can be pasted in one go:

```powershell
.\foton.exe tools Hayabusa -Force
.\foton.exe tools Chainsaw -Force
.\foton.exe tools
```

The last command lists what Foton can find. For Eric Zimmerman's tools (PECmd, EvtxECmd, RECmd, LECmd, JLECmd, AmcacheParser), download `Get-ZimmermanTools` from [ericzimmerman.github.io](https://ericzimmerman.github.io/), run it into a folder, and register that folder with `.\foton.exe tools EZTools` followed by the folder's path in quotes. Then run `compose` and `analyze` again.

## Baselines: compare a computer with itself later

A baseline records stable configuration (services, scheduled tasks, autoruns, accounts, drivers, certificates, firewall rules, and more) so you can see what changed. Take one at a known-good moment, keep a copy off the computer, and take another later:

```powershell
.\foton-baseline.exe
```

Baselines go to `C:\Foton\Baselines`. To compare the two newest on the same computer:

```powershell
$b = Get-ChildItem C:\Foton\Baselines -Directory -Filter 'FotonBaseline_*' | Sort-Object LastWriteTime
.\foton.exe compare $b[-2].FullName $b[-1].FullName
```

The comparison shows what changed between the two snapshots. It does not show when, or who made the change. For comparing a computer against a golden image of its role, see [Baseline compare](USAGE.md#baseline-compare).

## When something does not work

| You see | What it means and what to do |
|---------|------------------------------|
| `The term '.\foton-collect.exe' is not recognized` | PowerShell is in a different folder. Run `Set-Location (Join-Path $env:USERPROFILE 'Foton')` and try again. |
| `Invoke-WebRequest` fails with a TLS or connection error | Run the whole download block again, including its first line. On a network without internet access, download the files on another computer and copy them over. |
| A line says `FAIL` | That file does not match the published hash. Delete it and download again; do not run it. |
| `Cannot create the default output folder C:\Foton\Cases` | This account may not create folders there (or another account already created it). Add `-OutputPath` with a folder you can write to. |
| `Access to the path ... is denied` when opening `C:\Foton\Cases` | The case was collected by a different account. Open PowerShell as Administrator, or as that account. |
| The report says "Standard user - reduced coverage" | PowerShell was not running as Administrator. Collect again from an Administrator window for full coverage. |
| `gh` is not recognized | The GitHub CLI is not installed. Install it from [cli.github.com](https://cli.github.com/) and run `gh auth login`, or skip the attestation check and note in your case notes that only the hash was checked. |
| Antivirus quarantined `foton-collect.exe` | See [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector). |

Every switch, verb, and output is in [USAGE.md](USAGE.md).
