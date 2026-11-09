# Getting started

This guide takes you from nothing to an analyzed collection. Commands are short and can be pasted as they are; where one needs something only you know, the text above it says so.

Foton uses **two machines**:

- The **endpoint** is the computer you are examining. You run `foton-collect.exe` (or `foton-baseline.exe`) there. It writes a case folder and a ZIP.
- The **workstation** is your own analysis computer. You copy the ZIP there and run `foton.exe` on it. `foton.exe` never touches the endpoint.

To try Foton out, one computer can play both roles; [step 5](#5-move-the-package-to-the-workstation) shows the shortcut.

## Before you start

- Windows 10, Windows 11, or Windows Server 2016 or newer. Nothing to install: the executables use the .NET Framework that ships with Windows.
- Commands are for **PowerShell**. A PowerShell window shows `PS` at the start of the prompt (`PS C:\Users\you>`). If you are in Command Prompt (`C:\Users\you>`), type `powershell` and press Enter first.
- **Administrator** gives a complete collection. To open PowerShell as Administrator: open the Start menu, type `PowerShell`, right-click **Windows PowerShell**, and choose **Run as administrator**. Without it, Foton still runs and records what it could not read as a visibility gap.

## 1. Download

Download the files you need from the latest release. Your browser saves them to your **Downloads** folder.

- On the endpoint: [foton-collect.exe](https://github.com/jimididit/foton/releases/latest/download/foton-collect.exe) (and [foton-baseline.exe](https://github.com/jimididit/foton/releases/latest/download/foton-baseline.exe) for baselines).
- On the workstation: [foton.exe](https://github.com/jimididit/foton/releases/latest/download/foton.exe).
- For verification: [SHA256SUMS.txt](https://github.com/jimididit/foton/releases/latest/download/SHA256SUMS.txt).

If the browser says the file "isn't commonly downloaded", choose **Keep**. The executables are not code-signed yet; [step 2](#2-verify-your-download) is how you check them instead.

## 2. Verify your download

Recommended for any real case, and quick. In PowerShell:

```powershell
cd "$env:USERPROFILE\Downloads"
Get-FileHash .\foton-collect.exe -Algorithm SHA256
```

Open `SHA256SUMS.txt` (double-click it) and check that the long `Hash` value PowerShell printed matches the line for `foton-collect.exe` (upper or lower case does not matter). Do the same for any other `.exe` you downloaded. If a value does not match, delete the file and download it again.

That proves the file matches what the release published. Because `SHA256SUMS.txt` comes from the same release page, it does not prove who built it. The **build provenance attestation** does: GitHub signs it and it names the repository and commit that built the file. Checking it needs the [GitHub CLI](https://cli.github.com/) (`gh`), signed in once with `gh auth login`:

```powershell
gh attestation verify .\foton-collect.exe --repo jimididit/foton
```

It should report that verification succeeded. If you cannot install `gh`, Foton still runs; note in your case notes that only the hash was checked.

**Antivirus.** Security products sometimes flag forensic tools, because they read the same places attackers do. See [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector); never modify the executable to get past a scanner.

## 3. Collect on the endpoint

In PowerShell **as Administrator**:

```powershell
cd "$env:USERPROFILE\Downloads"
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "Your Name"
```

Use your own case number and name, or leave them as they are for a test. A collection takes a few minutes. When it finishes it prints the case folder, the report, and the ZIP. They are under `C:\Foton\Cases` (on the drive Windows is installed on), in a folder named `Foton_<computer name>_<date and time in UTC>Z`.

`C:\Foton\Cases` is created so that only SYSTEM, Administrators, and the account that ran the collection can read it. To write somewhere else, add `-OutputPath` and a folder of your choice, for example `-OutputPath E:\Cases` for a USB drive that shows up as `E:`.

Live collection changes the computer a little (it starts processes and writes the output). If your case needs a memory or disk image, take it **before** collecting.

## 4. Open the report

```powershell
explorer C:\Foton\Cases
```

Open the newest `Foton_...` folder and double-click `Foton_Report.html`. The report lists **observations**, each with the artifact it came from. It does not say whether the computer is compromised, and an empty list does not mean it is clean.

## 5. Move the package to the workstation

From `C:\Foton\Cases` on the endpoint, copy two files to the workstation's **Downloads** folder: the ZIP and the `_PACKAGE_HASH.txt` beside it. The HTML report alone is not the package.

On the workstation, with `foton.exe` downloaded (step 1), check the package and extract it:

```powershell
cd "$env:USERPROFILE\Downloads"
$zip = Get-ChildItem .\Foton_*.zip | Sort-Object LastWriteTime | Select-Object -Last 1
.\foton.exe package $zip.FullName
```

`foton package` re-hashes every file against the list made at collection time. When it reports no changed or missing files, extract the ZIP and remember the folder:

```powershell
Expand-Archive $zip.FullName -DestinationPath . -Force
$case = Join-Path $PWD $zip.BaseName
```

If `foton package` reports a problem, do not analyze that copy: copy the package from the endpoint again, and if it still fails, record in your case notes that the package changed after collection.

**Trying Foton on one computer?** Skip the copy. In the Administrator window you collected from, point `$case` at the newest case folder:

```powershell
cd "$env:USERPROFILE\Downloads"
$case = (Get-ChildItem C:\Foton\Cases -Directory -Filter 'Foton_*' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

## 6. Analyze on the workstation

With `$case` set by step 5:

```powershell
.\foton.exe parse $case
.\foton.exe compose $case
.\foton.exe analyze $case
```

Then open `Foton_Report.html` in the case folder again (`explorer $case`).

- `parse` reads the copied Prefetch, shortcuts, jump lists, event logs, and Amcache.
- `compose` runs specialist tools (Hayabusa, Chainsaw, Eric Zimmerman's tools) over the copied files, if you installed them (next section). Tools that are missing are listed, not errors.
- `analyze` runs last and rebuilds the report with everything above.

### Optional: install the specialist tools

Hayabusa and Chainsaw install with one command each. Foton downloads the release it is pinned to, checks its SHA-256, and installs it under `%LOCALAPPDATA%\Foton\tools`. `-Force` skips the "install?" question:

```powershell
.\foton.exe tools Hayabusa -Force
.\foton.exe tools Chainsaw -Force
```

`.\foton.exe tools` lists what Foton can find. For Eric Zimmerman's tools (PECmd, EvtxECmd, RECmd, LECmd, JLECmd, AmcacheParser), download `Get-ZimmermanTools` from [ericzimmerman.github.io](https://ericzimmerman.github.io/), run it into a folder, and register that folder with `.\foton.exe tools EZTools` followed by the folder's path in quotes. Then run `compose` and `analyze` again.

## Baselines: compare a computer with itself later

A baseline records stable configuration (services, scheduled tasks, autoruns, accounts, drivers, certificates, firewall rules, and more) so you can see what changed. Take one at a known-good moment, keep a copy off the computer, and take another later. In PowerShell as Administrator, in the folder with `foton-baseline.exe`:

```powershell
.\foton-baseline.exe
```

Baselines go to `C:\Foton\Baselines`. To compare the two newest on the same computer (with `foton.exe` in the same folder):

```powershell
$b = Get-ChildItem C:\Foton\Baselines -Directory -Filter 'FotonBaseline_*' | Sort-Object LastWriteTime
.\foton.exe compare $b[-2].FullName $b[-1].FullName
```

The comparison shows what changed between the two snapshots. It does not show when, or who made the change. For comparing a computer against a golden image of its role, see [Baseline compare](USAGE.md#baseline-compare).

## When something does not work

| You see | What it means and what to do |
|---------|------------------------------|
| `The term '.\foton-collect.exe' is not recognized` | PowerShell is in a different folder from the file. Run `cd "$env:USERPROFILE\Downloads"`. If you saved it elsewhere, `cd` to that folder (in File Explorer, click the address bar to copy the folder's path). An Administrator window opened with a different account has a different Downloads folder. |
| The browser blocked or removed the download | Choose **Keep** in the browser's download list. If antivirus removed it, see [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector). |
| Windows says Smart App Control blocked the app | Smart App Control blocks unsigned programs and cannot be bypassed per file. Run Foton on a computer where it is off, or wait for signed releases. |
| The hash does not match `SHA256SUMS.txt` | Delete the file and download it again; do not run it. |
| `Not writing to the default output folder C:\Foton\Cases` | That folder (or `C:\Foton`) already exists and is not private to SYSTEM, Administrators, and your account, or could not be created. The message names the reason. Add `-OutputPath` and a folder you can write to, or remove the folder it names and run again. |
| `Access to the path ... is denied` when opening `C:\Foton\Cases` | The case was collected by a different account. Open PowerShell as Administrator, or as that account. |
| The report says "Standard user - reduced coverage" | PowerShell was not running as Administrator. Collect again from an Administrator window for full coverage. |
| `gh` is not recognized | The GitHub CLI is not installed. Install it from [cli.github.com](https://cli.github.com/) and run `gh auth login`, or skip the attestation check and note in your case notes that only the hash was checked. |

Every switch, verb, and output is in [USAGE.md](USAGE.md).
