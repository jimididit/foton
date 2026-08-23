# Public/Baseline

Normalized snapshots of **stable** configuration. Schema **1.5.0** (recapture day0 after this version; Compare refuses a mismatch).

| RecordType | Identity | Compared | False-positive notes |
|------------|----------|----------|----------------------|
| Service | `Name` | PathName, StartMode, StartName, DisplayName | Patch replaces binaries |
| LocalAccount | `SID` | Name, Enabled, PasswordRequired, PasswordExpires | Edition differences |
| LocalGroupMember | `Group` + `SID` | Member | Domain join, LAPS |
| HardeningRegistry | `Setting` | Value | GPO / edition |
| InstalledSoftware | `DisplayName` + `Publisher` | DisplayVersion, InstallLocation | Patch Tuesday |
| ScheduledTask | `TaskPath` + `TaskName` | Actions, RunAsUser, RunLevel, Triggers | GPO/MDM tasks; last-run is not compared |
| Autorun | `Key` + `ValueName` | Command | Installers and updaters; HKLM Run/RunOnce only |
| UserAutorun | `SID` + `Key` + `ValueName` | Command | HKCU Run on loaded hives; cloud-sync and chat apps |
| Driver | `Name` | PathName, StartMode, DisplayName | Driver updates; State is not compared |
| FirewallRule | `Name` + `Direction` | Action, Enabled, Profile | GPO/MDM; duplicate display names |
| Certificate | `Store` + `Thumbprint` | Subject, Issuer, NotAfter | Enterprise PKI, Windows Update roots |
| Listener | `Protocol` + `LocalAddress` + `LocalPort` | *(none - Added/Removed only)* | TCP Listen + UDP ports below 49152. Ephemeral UDP is omitted |
| NetworkShare | `Name` | Path, Type, Description | C$/ADMIN$/IPC$ and print shares |
| SystemBinary | `Name` | Sha256, Length | Patch Tuesday of System32 binaries |
| HostsEntry | `Address` + `Hostname` | *(Added/Removed)* | Lab DNS, ad-block lists |
| MachineEnvironment | `Name` | Value | Installers appending Path |
| WmiPermanentEvent | `Kind` + `Name` | Detail | SCCM/AV WMI consumers |
| StartupFile | `Scope` + `FileName` | Sha256, Length | Vendor .lnk updaters. Settings "Startup apps" are **not** this folder |
| StartupApproved | `Scope` + `Store` + `ValueName` | State | Task Manager / Settings enable-disable (REG_BINARY). Users toggling Teams/OneDrive |
| DefenderPreference | `Kind` + `Name` | Value | MpPreference switches and exclusion rows. Intune/GPO |
| RemoteAccessConfig | `Setting` | Value | RDP NLA/port/SecurityLayer/AllowRemoteRPC; WinRM *policy* Basic/unencrypted; LanmanServer SMB1. Helpdesk RDP and GPO WinRM. **RDP enable** is HardeningRegistry `fDenyTSConnections` |
| ImageFileExecution | `ImageName` | Debugger | App Verifier / GFlags |
| Winlogon | `Name` | Value | EDR/MFA Userinit/Shell |
| AppInitDll | `Key` + `Name` | Value | Legacy injectors |

Volatile fields (PID, service State, ephemeral UDP, connection tuples) are not captured. Planned providers: [docs/COVERAGE.md](../../../docs/COVERAGE.md).

`New-FotonBaseline` captures on a live host (`-Path` JSON, or `-OutputPath` package folder with HTML/hashes/ZIP). Flattened endpoint script: `dist/Foton-Baseline.ps1`. `Compare-FotonBaseline` is offline (JSON or package folder) and **refuses** a schema mismatch; it writes `Foton_BaselineCompare.html` beside the difference JSON unless `-NoHtml`. Diffs are Tier 1 change facts; High attention for persistence/trust surfaces (service/driver PathName, IFEO, Winlogon Userinit/Shell, RemoteAccessConfig, new shares, hosts adds, WMI consumers, System32 hash change) - still not a conclusion.
