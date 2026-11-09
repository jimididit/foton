using System;
using System.Collections.Generic;

namespace Foton.Analyze
{
    /// <summary>
    /// Benign causes per baseline record type (Get-FotonBaselineFalsePositives), quoted when a baseline_diff.csv
    /// High-attention change is lifted into a finding. Same text as the capture providers; a test keeps them equal.
    /// </summary>
    public static class BaselineFalsePositives
    {
        public static readonly IReadOnlyDictionary<string, string> ByRecordType = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ActiveSetup"] = @"Office, browsers, and runtimes add GUIDs and bump Version. StubPath changing to a user-writable binary is the review item. HKCU once-per-user stamps are Collect-only.",
            ["AppInitDll"] = @"Legacy AV and some graphics injectors still use AppInit. LoadAppInit_DLLs=0 with an empty DLL list is the usual modern default.",
            ["Autorun"] = @"Installers add Run keys. Cloud-sync and updaters live here. Compare Command, not presence of a vendor Run value.",
            ["BitsJob"] = @"Windows Update and Store use BITS. Added/Removed JobIds between captures are common. A new or changed NotifyCmdLine (bitsadmin /SetNotifyCmdLine) is the usual review item, not BytesTransferred.",
            ["Certificate"] = @"Enterprise Root CA rollout and Intune add roots. A new Root thumbprint that is not Microsoft/your org CA is the usual review item. Renewal changes NotAfter for the same thumbprint only if the cert is reissued with the same key - often a new thumbprint (Added+Removed).",
            ["CmdAutoRun"] = @"IT shops set AutoRun for doskey, clink, or conda hooks. That is a Command change, not malware by itself. Empty HKCU is omitted so logon/logoff does not churn (not set) rows.",
            ["DefenderPreference"] = @"Intune, GPO, and tamper-protection UI change these. An exclusion add is a new row (Kind + path), not proof of compromise.",
            ["Driver"] = @"Windows Update replaces driver PathName. Catalog-signed drivers still show odd signature status in Collect; this snapshot does not include signature.",
            ["FirewallRule"] = @"Windows and vendor installers add allow rules. A new inbound Allow is worth review; a new outbound Allow is common.",
            ["HardeningRegistry"] = @"Domain GPO and Windows edition change defaults. Expected values in the Collect table are a common lab baseline, not proof of compromise when they differ.",
            ["HostsEntry"] = @"Local development (localhost, kubernetes.docker.internal), ad-block lists, and MDM-managed hosts files. IPv6 localhost (::1) is expected.",
            ["ImageFileExecution"] = @"Application Verifier, GFlags, and some debuggers set Debugger. SilentProcessExit is a separate RecordType.",
            ["InstalledSoftware"] = @"Patch Tuesday and in-place upgrades change DisplayVersion. Publisher string is not stable across all MSI packages.",
            ["KnownDll"] = @"Feature updates add KnownDLL entries. DllDirectory / DllDirectory32 follow SysWOW64 layout. A new Name or a MappedFile that is not a System32 DLL is the review item, not the stock ntdll/kernel32 list.",
            ["Listener"] = @"New TCP listeners from debug servers and WinRM. UDP above 49151 is omitted on purpose. Wildcard 0.0.0.0 vs a specific bind looks like remove+add.",
            ["LocalAccount"] = @"Built-in accounts differ by Windows edition. Enabled Guest is unusual; a renamed Administrator SID is still S-1-5-21-*-500.",
            ["LocalGroupMember"] = @"Domain join adds Domain Admins. Intune/LAPS may add a local admin. Compare to the role golden image, not a random workstation.",
            ["LsaPackage"] = @"Third-party MFA, VPN, and EDR often add a Security Package or Notification Package. Compare to the role image. A new unknown DLL name is the interesting case, not msv1_0/kerberos churn.",
            ["MachineEnvironment"] = @"Installers and Visual Studio/Java/Python append Path. TEMP/TMP and NUMBER_OF_PROCESSORS can differ by hardware or user TEMP policy.",
            ["NetshHelper"] = @"Inbox helpers (dhcpmon, fwmon, rasmontr, wshelper) are normal. VPN/EDR/third-party stacks add helpers. Wow6432Node is a separate Key.",
            ["NetworkShare"] = @"Print and scan shares, OneDrive/File History, and C$/ADMIN$/IPC$ are normal. Type is the Win32_Share numeric type, not a verdict.",
            ["PrintMonitor"] = @"Installing a printer or print server role adds Standard TCP/IP Port, WSD, and vendor monitors. A new Driver DLL under an unexpected Name is the review item, not Local Port.",
            ["ProxyConfig"] = @"Corporate PAC (AutoConfigURL) and WPAD change often. Explicit ProxyServer or WinHttpSettings pointing at an unexpected host is the usual review item. Per-user rows exist only when a proxy/PAC is set on a loaded hive.",
            ["RemoteAccessConfig"] = @"Helpdesk turning NLA off or changing the RDP port. Domain GPO for WinRM Basic/unencrypted. File servers that still have SMBv1. fDenyTSConnections is HardeningRegistry, not this type.",
            ["ScheduledTask"] = @"Vendor software registers tasks after install. Root-folder SYSTEM tasks are more interesting than nested Microsoft\Windows tasks, but still often legitimate.",
            ["Service"] = @"Patch Tuesday can replace PathName for the same service. Third-party updaters change StartMode. Compare against a provisioning snapshot, not a post-compromise one.",
            ["SessionManager"] = @"autocheck autochk * is the usual BootExecute. Disk tools and some imaging agents add tokens. AppCertDlls is empty on most hosts; AV/EDR may register a DLL. PendingFileRenameOperations is intentionally omitted.",
            ["SilentProcessExit"] = @"Procmon, Application Verifier, and crash-dump lab machines set MonitorProcess. ReportingMode/LocalDumpFolder changes without a new MonitorProcess are often debugging, not persistence.",
            ["StartupApproved"] = @"Users toggling Teams, OneDrive, chat, and vendor updaters in Settings is a common benign change. Only loaded user hives are visible without hive load.",
            ["StartupFile"] = @"Vendor updaters drop .lnk files here. Per-user rows follow who has a profile on disk, not who is logged on. desktop.ini is omitted.",
            ["SystemBinary"] = @"Patch Tuesday and servicing stack replace these binaries; PowerShell 7 updates replace pwsh.exe. Missing optional files (pwsh.exe) appear as Added when first installed, not as FileNotFound rows.",
            ["TimeProvider"] = @"NtpClient and NtpServer are the usual pair. Hyper-V VMICTimeProvider and domain NTP stacks are common. Enabled flips are often GPO; DllName changing to a user-writable path is the review item.",
            ["UserAutorun"] = @"Cloud-sync, chat, and updaters write HKCU Run. Only loaded user hives are visible. Fleet-compare is noisy; temporal on one host is the usual reading.",
            ["WdacApplockerPolicy"] = @"Windows Update and WDAC/AppLocker MDM refresh change PolicyHash without a local operator edit. Compare is change between snapshots, not who published the policy.",
            ["Winlogon"] = @"Some EDR and MFA packages change Userinit or Shell. Compare to the role image, not a busy analyst workstation.",
            ["WinsockLsp"] = @"VPN, filter, and endpoint-security products register LSPs and namespace providers. Stock Catalog_Entries are many (often mswsock.dll). A new LibraryPath outside System32 is the review item, not the numeric index itself.",
            ["WmiPermanentEvent"] = @"ConfigMgr, Defender, and backup agents register WMI consumers. Empty on many home images. Unelevated capture may return zero rows (visibility gap, not proof of absence).",
        };

        public static string Of(string recordType) => ByRecordType.TryGetValue(recordType, out var fp) ? fp : "";
    }
}