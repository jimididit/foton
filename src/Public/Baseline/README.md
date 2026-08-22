# Public/Baseline

Normalized snapshots of **stable** configuration. First providers:

| RecordType | Identity | Compared | False-positive notes |
|------------|----------|----------|----------------------|
| Service | `Name` | PathName, StartMode, StartName, DisplayName | Patch replaces binaries |
| LocalAccount | `SID` | Name, Enabled, PasswordRequired, PasswordExpires | Edition differences |
| LocalGroupMember | `Group` + `SID` | Member | Domain join, LAPS |
| HardeningRegistry | `Setting` | Value | GPO / edition |
| InstalledSoftware | `DisplayName` + `Publisher` | DisplayVersion, InstallLocation | Patch Tuesday |

Volatile fields (PID, State, connections) are not captured.

`New-FotonBaseline` captures on a live host. `Compare-FotonBaseline` is offline and **refuses** a schema mismatch. Diffs are Tier 1 change facts; High attention for service PathName, WDigest/UAC/AlwaysInstallElevated, and new Administrators members — still not a conclusion.
