# Public/Baseline

Normalized snapshots of **stable** configuration. Schema **1.1.0** (recapture day0 after this version; Compare refuses 1.0.0 vs 1.1.0).

| RecordType | Identity | Compared | False-positive notes |
|------------|----------|----------|----------------------|
| Service | `Name` | PathName, StartMode, StartName, DisplayName | Patch replaces binaries |
| LocalAccount | `SID` | Name, Enabled, PasswordRequired, PasswordExpires | Edition differences |
| LocalGroupMember | `Group` + `SID` | Member | Domain join, LAPS |
| HardeningRegistry | `Setting` | Value | GPO / edition |
| InstalledSoftware | `DisplayName` + `Publisher` | DisplayVersion, InstallLocation | Patch Tuesday |
| ScheduledTask | `TaskPath` + `TaskName` | Actions, RunAsUser, RunLevel, Triggers | GPO/MDM tasks; last-run is not compared |
| Autorun | `Key` + `ValueName` | Command | Installers and updaters; HKLM Run/RunOnce only |
| Driver | `Name` | PathName, StartMode, DisplayName | Driver updates; State is not compared |
| FirewallRule | `Name` + `Direction` | Action, Enabled, Profile | GPO/MDM; duplicate display names |
| Certificate | `Store` + `Thumbprint` | Subject, Issuer, NotAfter | Enterprise PKI, Windows Update roots |
| Listener | `Protocol` + `LocalAddress` + `LocalPort` | *(none - Added/Removed only)* | Services bind ports; PID is not stored |

Volatile fields (PID, service State, connection tuples beyond the listen tuple) are not captured.

`New-FotonBaseline` captures on a live host (`-Path` JSON, or `-OutputPath` package folder with HTML/hashes/ZIP). Flattened endpoint script: `dist/Foton-Baseline.ps1`. `Compare-FotonBaseline` is offline (JSON or package folder) and **refuses** a schema mismatch. Diffs are Tier 1 change facts; High attention for service/driver PathName, autorun Command, task Actions, WDigest/UAC/AlwaysInstallElevated, new Administrators members, and new LocalMachine Root certificates - still not a conclusion.
