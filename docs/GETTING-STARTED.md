# Getting started

This guide takes you from download to an analyzed collection.

Foton uses **two computers**:

- The **endpoint** is the computer you are examining. You run `foton-collect.exe` (or `foton-baseline.exe`) there. It writes a case folder and a ZIP.
- The **workstation** is your own analysis computer. You copy the ZIP there and run `foton.exe` on it (or `foton-console.exe`, the same work in a window). Neither touches the endpoint.

To try Foton, one computer can play both roles.

## Before you start

- Windows 10, Windows 11, or Windows Server 2016 or newer. Nothing to install: the executables use the .NET Framework that ships with Windows.
- Commands are for **PowerShell**. The prompt starts with `PS` (`PS C:\>`). In Command Prompt, type `powershell` and press Enter first.
- **Administrator** gives a complete collection. To open PowerShell as Administrator: open the Start menu, type `PowerShell`, right-click **Windows PowerShell**, and choose **Run as administrator**. Without it, Foton still runs and records what it could not read.
- **Paths you must fill in** look like `"\path\to\folder"`. Replace the whole path with your own, keeping the quotes. Paths that start with `C:\Foton` are folders Foton creates; use them as written.

## 1. Download

From the [latest release](https://github.com/jimididit/foton/releases/latest), download `Foton-<version>-windows.zip`. It holds all four executables, their `SHA256SUMS.txt`, `LICENSE.txt`, and a `README.txt`:

- `foton-collect.exe` (and `foton-baseline.exe` for baselines) for the endpoint
- `foton.exe` and `foton-console.exe` for the workstation

The executables are also attached to the release on their own, with the release's `SHA256SUMS.txt`, for an RMM tool or a script that needs just one. Sending the collector to someone else? See [Send a collector to an endpoint](#send-a-collector-to-an-endpoint) after step 2.

If the browser warns that the file "isn't commonly downloaded", choose **Keep**: the executables are not code-signed yet, and step 2 is how you check them instead.

On a workstation with [Scoop](https://scoop.sh), `scoop bucket add foton https://github.com/jimididit/foton` and `scoop install foton/foton` download the same ZIP, check its SHA-256, and put the four executables on your PATH (`scoop update foton` later). For casework, still run the provenance check in step 2 on the installed files.

## 2. Check the download

In PowerShell, go to the folder holding the ZIP:

```powershell
cd "\path\to\folder"
```

Print its SHA-256 hash:

```powershell
Get-FileHash .\Foton-*-windows.zip
```

The `Hash` value must match the SHA-256 shown at the top of the release notes (upper and lower case do not matter). If it does not, delete the ZIP and download it again.

That check shows the file is the one the release published. For casework, also check **who built it**: the build provenance attestation is signed by GitHub and names the repository and commit that produced the file. It needs the [GitHub CLI](https://cli.github.com/) (`gh`), signed in once with `gh auth login`:

```powershell
gh attestation verify .\Foton-*-windows.zip --repo jimididit/foton
```

It should report that verification succeeded. If you cannot install `gh`, note in your case notes that only the hash was checked.

Then unblock the ZIP (so Windows does not warn about each file in it) and extract it:

```powershell
Unblock-File .\Foton-*-windows.zip
Expand-Archive .\Foton-*-windows.zip -DestinationPath .\Foton
cd .\Foton
```

A single executable downloaded on its own checks the same way: `Get-FileHash .\foton-collect.exe`, compared with its line in the release's `SHA256SUMS.txt`, and `gh attestation verify .\foton-collect.exe --repo jimididit/foton`.

Security products sometimes flag forensic tools, because they read the same places attackers do. See [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector). Never modify the executable to get past a scanner.

### Send a collector to an endpoint

`foton.exe` and `foton-console.exe` carry the collectors released with them, so you can build the endpoint's folder on your workstation instead of downloading the collector separately.

1. On the workstation, build the folder:

   ```powershell
   .\foton.exe bundle collect
   ```

   It prints the new folder's path (`Bundle: ...`) under `C:\Foton\Bundles`. In the console, use the **Collectors** tab instead. To collect only some categories, build a profile on the console's **Profile** tab and add `-Profile "\path\to\profile.json"`. For a baseline collector, use `bundle baseline`.
2. Copy the whole folder to the endpoint, or push it with your RMM tool. It holds the collector, `RUN.txt`, and `SHA256SUMS.txt`.
3. On the endpoint, check the collector against `SHA256SUMS.txt` as in step 2, then run the command in `RUN.txt` from that folder. Step 3 below explains what it does.

## 3. Collect on the endpoint

In PowerShell **as Administrator**, in the folder with `foton-collect.exe`:

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "Your Name"
```

Use your own case number and name. A collection takes a few minutes. When it finishes, it prints where everything went: a case folder named `Foton_<computer name>_<UTC date and time>Z` and a ZIP of it, both in `C:\Foton\Cases` (on the drive Windows is installed on).

Only SYSTEM, Administrators, and the account that ran the collection can open `C:\Foton\Cases`. To write somewhere else, add `-OutputPath` and a folder, for example a USB drive:

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -OutputPath "\path\to\folder"
```

Live collection changes the computer a little (it starts processes and writes the output). If your case needs a memory or disk image, take it **before** collecting.

## 4. Open the report

Open `C:\Foton\Cases` in File Explorer, open the new `Foton_...` folder, and double-click `Foton_Report.html`.

The report lists **observations**, each with the file it came from. It does not say whether the computer is compromised, and an empty list does not mean it is clean.

## 5. Move the package to the workstation

From `C:\Foton\Cases` on the endpoint, copy the ZIP and the `_PACKAGE_HASH.txt` file beside it to the workstation. The HTML report alone is not the package.

On the workstation, in PowerShell, in the folder with `foton.exe`, check the ZIP. Replace the path with the ZIP you copied:

```powershell
.\foton.exe package "\path\to\Foton_case.zip"
```

`foton package` re-hashes every file against the list made at collection time. If it reports changed or missing files, do not analyze that copy: copy the package from the endpoint again, and if it still fails, record in your case notes that the package changed after collection.

You do not need to extract the ZIP yourself. `foton package` extracted it into a new folder beside the ZIP, named like the ZIP with `-extracted` at the end, and the next steps reuse that folder.

**One computer only?** Skip the copy. In the next step, use the case folder in `C:\Foton\Cases` (the `Foton_...` folder that holds `00_Collection`) instead of the ZIP, from the same Administrator window you collected in.

## 6. Analyze on the workstation

Prefer a window? Start `foton-console.exe` and press **Work a case...** under **Start here**: it opens the ZIP (**ZIP...**), then verifies, parses, composes, and analyzes it one step at a time, and ends with the handoff. The commands below do the same.

Run these in order, with the same ZIP path as in step 5:

```powershell
.\foton.exe parse "\path\to\Foton_case.zip"
.\foton.exe compose "\path\to\Foton_case.zip"
.\foton.exe analyze "\path\to\Foton_case.zip"
```

Then open `Foton_Report.html` in the case folder inside the `-extracted` folder (`analyze` prints its full path).

- `parse` reads the copied Prefetch, shortcuts, jump lists, event logs, and Amcache.
- `compose` runs specialist tools (Hayabusa, Chainsaw, Eric Zimmerman's tools) over the copied files, if you installed them (below). Missing tools are listed, not errors.
- `analyze` runs last and rebuilds the report with everything above.

### Optional: install the specialist tools

Foton can install Hayabusa and Chainsaw for you. It downloads the release it is pinned to, checks its SHA-256, and installs it under `%LOCALAPPDATA%\Foton\tools`. `-Force` skips the "install?" question:

```powershell
.\foton.exe tools Hayabusa -Force
.\foton.exe tools Chainsaw -Force
```

For Eric Zimmerman's tools (PECmd, EvtxECmd, RECmd, LECmd, JLECmd, AmcacheParser, AppCompatCacheParser, SBECmd, SrumECmd, MFTECmd), download `Get-ZimmermanTools` from [ericzimmerman.github.io](https://ericzimmerman.github.io/), run it into a folder, and register that folder:

```powershell
.\foton.exe tools EZTools "\path\to\EZTools"
```

`.\foton.exe tools` lists what Foton can find. Run `compose` and `analyze` again after installing.

## Baselines: compare a computer with itself later

A baseline records stable configuration (services, scheduled tasks, autoruns, accounts, drivers, certificates, firewall rules, and more) so you can see what changed. Take one at a known-good moment, keep a copy off the computer, and take another later. In PowerShell as Administrator, in the folder with `foton-baseline.exe`:

```powershell
.\foton-baseline.exe
```

Each run adds a `FotonBaseline_...` folder to `C:\Foton\Baselines`. To compare two of them, give the earlier one first:

```powershell
.\foton.exe compare "\path\to\earlier-baseline-folder" "\path\to\later-baseline-folder"
```

The comparison shows what changed between the two snapshots. It does not show when, or who made the change. To compare a computer against a golden image of its role, see [Baseline compare](USAGE.md#baseline-compare).

## When something does not work

| You see | What it means and what to do |
|---------|------------------------------|
| `Cannot find path '...\path\to\...'` | A placeholder was pasted as is. Replace it with the real path. In File Explorer, click the address bar to copy a folder's path. |
| `The term '.\foton-collect.exe' is not recognized` | PowerShell is in a different folder from the file. `cd` to the folder that holds it. An Administrator window opened with a different account starts in a different folder. |
| The browser blocked or removed the download | Choose **Keep** in the browser's download list. If antivirus removed it, see [If antivirus blocks the collector](USAGE.md#if-antivirus-blocks-the-collector). |
| Windows says Smart App Control blocked the app | Smart App Control blocks unsigned programs and has no per-file exception. Run Foton on a computer where it is off, or wait for signed releases. |
| The hash does not match `SHA256SUMS.txt` | Delete the file and download it again. Do not run it. |
| `Not writing to the default output folder C:\Foton\Cases` | That folder (or `C:\Foton`) already exists and is not private to SYSTEM, Administrators, and your account, or could not be created. The message gives the reason. Add `-OutputPath` and a folder you can write to, or remove the folder it names and run again. |
| `Access to the path ... is denied` when opening `C:\Foton\Cases` | A different account ran the collection. Open PowerShell as Administrator, or as that account. |
| The report says "Standard user - reduced coverage" | PowerShell was not running as Administrator. Collect again from an Administrator window. |
| `gh` is not recognized | The GitHub CLI is not installed. Install it from [cli.github.com](https://cli.github.com/) and run `gh auth login`, or skip that check and note in your case notes that only the hash was checked. |

Every switch, verb, and output is in [USAGE.md](USAGE.md).
