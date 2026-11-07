using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Win;
using static Foton.Baseline.Capture.R;

namespace Foton.Baseline.Capture
{
    /// <summary>Providers read from the registry. Paths, fields, and "(not set)" rules follow the 1.38.x provider files.</summary>
    static class RegistryProviders
    {
        public static Provider ActiveSetup => new Provider
        {
            RecordType = "ActiveSetup", IdentityFields = new[] { "Key", "Guid" }, ComparedFields = new[] { "StubPath", "Version", "IsInstalled" },
            FalsePositives = "Office, browsers, and runtimes add GUIDs and bump Version. StubPath changing to a user-writable binary is the review item. HKCU once-per-user stamps are Collect-only.",
            SortKeys = new[] { "Key", "Guid" },
            Collect = ctx => Each(new[]
            {
                @"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
                @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
            }, root => Reg.SubKeyNames(root).Where(g => g.Length > 0).Select(guid =>
            {
                var k = Reg.Join(root, guid);
                return Row("Key", root, "Guid", guid, "StubPath", NotSet(Reg.Value(k, "StubPath")), "Version", NotSet(Reg.Value(k, "Version")), "IsInstalled", NotSet(Reg.Value(k, "IsInstalled")));
            })),
        };

        public static Provider AppInitDll => new Provider
        {
            RecordType = "AppInitDll", IdentityFields = new[] { "Key", "Name" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Legacy AV and some graphics injectors still use AppInit. LoadAppInit_DLLs=0 with an empty DLL list is the usual modern default.",
            SortKeys = new[] { "Key", "Name" },
            Collect = ctx =>
                from k in new[] { @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" }
                from n in new[] { "AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs" }
                let v = Reg.Value(k, n)
                select Row("Key", k, "Name", n, "Value", v == null ? "(not set)" : S(v)),
        };

        public static Provider Autorun => new Provider
        {
            RecordType = "Autorun", IdentityFields = new[] { "Key", "ValueName" }, ComparedFields = new[] { "Command" },
            FalsePositives = "Installers add Run keys. Cloud-sync and updaters live here. Compare Command, not presence of a vendor Run value.",
            SortKeys = new[] { "Key", "ValueName" },
            Collect = ctx =>
                from k in new[]
                {
                    @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                }
                from v in Reg.ValueList(k)
                select Row("Key", v.Key, "ValueName", v.Name, "Command", v.Value),
        };

        public static Provider CmdAutoRun => new Provider
        {
            RecordType = "CmdAutoRun", IdentityFields = new[] { "Hive", "Key" }, ComparedFields = new[] { "Command" },
            FalsePositives = "IT shops set AutoRun for doskey, clink, or conda hooks. That is a Command change, not malware by itself. Empty HKCU is omitted so logon/logoff does not churn (not set) rows.",
            SortKeys = new[] { "Hive", "Key" },
            Collect = ctx =>
            {
                var rows = new List<Dictionary<string, object?>>();
                foreach (var rel in new[] { @"SOFTWARE\Microsoft\Command Processor", @"SOFTWARE\Wow6432Node\Microsoft\Command Processor" })
                {
                    if (rel.Contains("Wow6432Node") && !Reg.Exists(@"HKLM:\SOFTWARE\Wow6432Node")) continue;
                    rows.Add(Row("Hive", "HKLM", "Key", rel, "Command", NotSet(Reg.Value(@"HKLM:\" + rel, "AutoRun"))));
                }
                foreach (var h in ctx.Hives)
                    foreach (var rel in new[] { @"Software\Microsoft\Command Processor", @"Software\Wow6432Node\Microsoft\Command Processor" })
                    {
                        var v = Reg.Value(Reg.Join(h.Root, rel), "AutoRun");
                        if (v == null || S(v).Length == 0) continue;
                        rows.Add(Row("Hive", h.Sid, "Key", rel, "Command", S(v)));
                    }
                return rows;
            },
        };

        public static Provider HardeningRegistry => new Provider
        {
            RecordType = "HardeningRegistry", IdentityFields = new[] { "Setting" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Domain GPO and Windows edition change defaults. Expected values in the Collect table are a common lab baseline, not proof of compromise when they differ.",
            SortKeys = new[] { "Setting" },
            Collect = ctx => Foton.Core.HardeningChecks.All.Select(c =>
            {
                var v = Reg.Value(c.Path, c.Name);
                return Row("Setting", c.Name, "Key", c.Path, "Value", v == null ? "(not set)" : S(v));
            }),
        };

        public static Provider ImageFileExecution => new Provider
        {
            RecordType = "ImageFileExecution", IdentityFields = new[] { "ImageName" }, ComparedFields = new[] { "Debugger" },
            FalsePositives = "Application Verifier, GFlags, and some debuggers set Debugger. SilentProcessExit is a separate RecordType.",
            SortKeys = new[] { "ImageName" },
            Collect = ctx =>
            {
                const string root = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
                return from sub in Reg.SubKeyNames(root)
                       let d = Reg.Value(Reg.Join(root, sub), "Debugger")
                       where d != null && S(d).Length > 0
                       select Row("ImageName", sub, "Debugger", S(d));
            },
        };

        public static Provider InstalledSoftware => new Provider
        {
            RecordType = "InstalledSoftware", IdentityFields = new[] { "DisplayName", "Publisher" }, ComparedFields = new[] { "DisplayVersion", "InstallLocation" },
            FalsePositives = "Patch Tuesday and in-place upgrades change DisplayVersion. Publisher string is not stable across all MSI packages.",
            SortKeys = new[] { "DisplayName", "Publisher" },
            Collect = ctx =>
                from root in new[] { @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }
                from sub in Reg.SubKeyNames(root)
                let k = Reg.Join(root, sub)
                let name = Reg.Value(k, "DisplayName")
                where name != null && S(name).Length > 0
                select Row("DisplayName", S(name), "Publisher", S(Reg.Value(k, "Publisher")), "DisplayVersion", S(Reg.Value(k, "DisplayVersion")), "InstallLocation", S(Reg.Value(k, "InstallLocation"))),
        };

        public static Provider KnownDll => new Provider
        {
            RecordType = "KnownDll", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "MappedFile" },
            FalsePositives = "Feature updates add KnownDLL entries. DllDirectory / DllDirectory32 follow SysWOW64 layout. A new Name or a MappedFile that is not a System32 DLL is the review item, not the stock ntdll/kernel32 list.",
            SortKeys = new[] { "Name" },
            Collect = ctx => Reg.ValueList(@"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs").Select(v => Row("Name", v.Name, "MappedFile", v.Value)),
        };

        static readonly Regex LsaSplit = new Regex(@"[,;\s]+");

        public static Provider LsaPackage => new Provider
        {
            RecordType = "LsaPackage", IdentityFields = new[] { "Kind", "Package" }, ComparedFields = new string[0],
            FalsePositives = "Third-party MFA, VPN, and EDR often add a Security Package or Notification Package. Compare to the role image. A new unknown DLL name is the interesting case, not msv1_0/kerberos churn.",
            SortKeys = new[] { "Kind", "Package" },
            Collect = ctx =>
            {
                var rows = new List<Dictionary<string, object?>>();
                var seen = new HashSet<string>();
                void Add(string kind, object? val)
                {
                    if (val == null) return;
                    var parts = val is string[] arr ? arr : new[] { S(val) };
                    foreach (var part in parts.Where(p => p != null))
                        foreach (var tok in LsaSplit.Split(part).Select(t => t.Trim()).Where(t => t.Length > 0))
                            if (seen.Add((kind + "|" + tok).ToLowerInvariant())) rows.Add(Row("Kind", kind, "Package", tok));
                }
                const string lsa = @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
                foreach (var n in new[] { "Authentication Packages", "Notification Packages", "Security Packages" }) Add(n, Reg.Value(lsa, n));
                Add("OSConfig Authentication Packages", Reg.Value(Reg.Join(lsa, "OSConfig"), "Authentication Packages"));
                Add("SecurityProviders", Reg.Value(@"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders", "SecurityProviders"));
                return rows;
            },
        };

        public static Provider MachineEnvironment => new Provider
        {
            RecordType = "MachineEnvironment", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Installers and Visual Studio/Java/Python append Path. TEMP/TMP and NUMBER_OF_PROCESSORS can differ by hardware or user TEMP policy.",
            SortKeys = new[] { "Name" },
            Collect = ctx => Reg.ValueList(@"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").Select(v => Row("Name", v.Name, "Value", v.Value)),
        };

        public static Provider NetshHelper => new Provider
        {
            RecordType = "NetshHelper", IdentityFields = new[] { "Key", "Name" }, ComparedFields = new[] { "Dll" },
            FalsePositives = "Inbox helpers (dhcpmon, fwmon, rasmontr, wshelper) are normal. VPN/EDR/third-party stacks add helpers. Wow6432Node is a separate Key.",
            SortKeys = new[] { "Key", "Name" },
            Collect = ctx =>
                from root in new[] { @"HKLM:\SOFTWARE\Microsoft\NetSh", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh" }
                from v in Reg.ValueList(root)
                where v.Name.Length > 0 && v.Name != "(default)"
                select Row("Key", root, "Name", v.Name, "Dll", v.Value.Length > 0 ? v.Value : "(not set)"),
        };

        public static Provider PrintMonitor => new Provider
        {
            RecordType = "PrintMonitor", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "Driver" },
            FalsePositives = "Installing a printer or print server role adds Standard TCP/IP Port, WSD, and vendor monitors. A new Driver DLL under an unexpected Name is the review item, not Local Port.",
            SortKeys = new[] { "Name" },
            Collect = ctx =>
            {
                const string root = @"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors";
                return Reg.SubKeyNames(root).Where(n => n.Length > 0).Select(n => Row("Name", n, "Driver", NotSet(Reg.Value(Reg.Join(root, n), "Driver"))));
            },
        };

        /// <summary>
        /// Binary values as lowercase hex. 1.38.x meant the same, but its byte[] was unrolled by the pipeline and
        /// written as space-separated decimals; 1.15.0 writes the intended hex.
        /// </summary>
        static string ProxyShown(object? v)
        {
            if (v == null) return "(not set)";
            if (v is byte[] b) return b.Length == 0 ? "(not set)" : BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
            var s = S(v);
            return s.Length == 0 ? "(not set)" : s;
        }

        public static Provider ProxyConfig => new Provider
        {
            RecordType = "ProxyConfig", IdentityFields = new[] { "Scope", "Setting" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Corporate PAC (AutoConfigURL) and WPAD change often. Explicit ProxyServer or WinHttpSettings pointing at an unexpected host is the usual review item. Per-user rows exist only when a proxy/PAC is set on a loaded hive.",
            SortKeys = new[] { "Scope", "Setting" },
            Collect = ctx =>
            {
                var names = new[] { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL" };
                const string machine = @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
                const string pol = @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
                var rows = new List<Dictionary<string, object?>>();
                rows.AddRange(names.Select(n => Row("Scope", "Machine", "Setting", n, "Value", ProxyShown(Reg.Value(machine, n)))));
                rows.AddRange(names.Select(n => Row("Scope", "MachinePolicy", "Setting", n, "Value", ProxyShown(Reg.Value(pol, n)))));
                rows.Add(Row("Scope", "WinHttp", "Setting", "WinHttpSettings", "Value", ProxyShown(Reg.Value(Reg.Join(machine, "Connections"), "WinHttpSettings"))));
                foreach (var h in ctx.Hives)
                {
                    var ukey = Reg.Join(h.Root, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                    var vals = names.ToDictionary(n => n, n => ProxyShown(Reg.Value(ukey, n)));
                    bool interesting = vals["ProxyEnable"] == "1" || names.Where(n => n != "ProxyEnable").Any(n => vals[n] != "(not set)");
                    if (!interesting) continue;
                    rows.AddRange(names.Select(n => Row("Scope", h.Sid, "Setting", n, "Value", vals[n])));
                }
                return rows;
            },
        };

        public static Provider RemoteAccessConfig => new Provider
        {
            RecordType = "RemoteAccessConfig", IdentityFields = new[] { "Setting" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Helpdesk turning NLA off or changing the RDP port. Domain GPO for WinRM Basic/unencrypted. File servers that still have SMBv1. fDenyTSConnections is HardeningRegistry, not this type.",
            SortKeys = new[] { "Setting" },
            Collect = ctx =>
            {
                const string ts = @"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server";
                var rdp = Reg.Join(ts, @"WinStations\RDP-Tcp");
                const string winrm = @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
                const string smb = @"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
                return new[]
                {
                    Row("Setting", "RdpNla", "Value", NotSet(Reg.Value(rdp, "UserAuthentication"))),
                    Row("Setting", "RdpPort", "Value", NotSet(Reg.Value(rdp, "PortNumber"))),
                    Row("Setting", "RdpSecurityLayer", "Value", NotSet(Reg.Value(rdp, "SecurityLayer"))),
                    Row("Setting", "RdpAllowRemoteRPC", "Value", NotSet(Reg.Value(ts, "AllowRemoteRPC"))),
                    Row("Setting", "WinRmPolicyAllowUnencrypted", "Value", NotSet(Reg.Value(winrm, "AllowUnencrypted"))),
                    Row("Setting", "WinRmPolicyAllowBasic", "Value", NotSet(Reg.Value(winrm, "AllowBasic"))),
                    Row("Setting", "Smb1LanmanServer", "Value", NotSet(Reg.Value(smb, "SMB1"))),
                };
            },
        };

        public static Provider SessionManager => new Provider
        {
            RecordType = "SessionManager", IdentityFields = new[] { "Kind", "Name" }, ComparedFields = new[] { "Value" },
            FalsePositives = "autocheck autochk * is the usual BootExecute. Disk tools and some imaging agents add tokens. AppCertDlls is empty on most hosts; AV/EDR may register a DLL. PendingFileRenameOperations is intentionally omitted.",
            SortKeys = new[] { "Kind", "Name" },
            Collect = ctx =>
            {
                const string sm = @"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager";
                string Join(object? v)
                {
                    if (v == null) return "(not set)";
                    var parts = (v is string[] a ? a.Cast<object?>() : v is byte[] b ? b.Cast<object?>() : new[] { v }).Select(S).Where(s => s.Length > 0).ToList();
                    return parts.Count == 0 ? "(not set)" : string.Join(" ", parts);
                }
                var rows = new[] { "BootExecute", "BootExecuteNoPnpSync", "SetupExecute", "Execute", "S0InitialCommand" }
                    .Select(n => Row("Kind", "SessionValue", "Name", n, "Value", Join(Reg.Value(sm, n)))).ToList();
                rows.AddRange(Reg.ValueList(Reg.Join(sm, "AppCertDlls")).Select(v => Row("Kind", "AppCertDlls", "Name", v.Name, "Value", v.Value)));
                return rows;
            },
        };

        public static Provider SilentProcessExit => new Provider
        {
            RecordType = "SilentProcessExit", IdentityFields = new[] { "ImageName" }, ComparedFields = new[] { "MonitorProcess", "ReportingMode", "LocalDumpFolder" },
            FalsePositives = "Procmon, Application Verifier, and crash-dump lab machines set MonitorProcess. ReportingMode/LocalDumpFolder changes without a new MonitorProcess are often debugging, not persistence.",
            SortKeys = new[] { "ImageName" },
            Collect = ctx =>
            {
                const string root = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
                return Reg.SubKeyNames(root).Where(n => n.Length > 0).Select(n =>
                {
                    var k = Reg.Join(root, n);
                    return Row("ImageName", n, "MonitorProcess", NotSet(Reg.Value(k, "MonitorProcess")), "ReportingMode", NotSet(Reg.Value(k, "ReportingMode")), "LocalDumpFolder", NotSet(Reg.Value(k, "LocalDumpFolder")));
                });
            },
        };

        /// <summary>Settings / Task Manager "Startup apps" state from the StartupApproved REG_BINARY (byte 0).</summary>
        static string ApprovedState(object? v)
        {
            if (!(v is byte[] b) || b.Length < 1) return "Unknown";
            switch (b[0])
            {
                case 2: case 6: return "Enabled";
                case 3: case 7: return "Disabled";
                default: return "Other:" + b[0];
            }
        }

        public static Provider StartupApproved => new Provider
        {
            RecordType = "StartupApproved", IdentityFields = new[] { "Scope", "Store", "ValueName" }, ComparedFields = new[] { "State" },
            FalsePositives = "Users toggling Teams, OneDrive, chat, and vendor updaters in Settings is a common benign change. Only loaded user hives are visible without hive load.",
            SortKeys = new[] { "Scope", "Store", "ValueName" },
            Collect = ctx =>
            {
                const string rel = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
                var stores = new[] { "Run", "Run32", "StartupFolder" };
                var keys = stores.Select(s => new { Scope = "HKLM", Store = s, Path = @"HKLM:\" + rel + "\\" + s }).ToList();
                foreach (var h in ctx.Hives) keys.AddRange(stores.Select(s => new { Scope = h.Sid, Store = s, Path = h.Root + "\\" + rel + "\\" + s }));
                var rows = new List<Dictionary<string, object?>>();
                foreach (var k in keys)
                    using (var key = Reg.Open(k.Path))
                    {
                        if (key == null) continue;
                        try
                        {
                            foreach (var n in key.GetValueNames().Where(n => !string.IsNullOrWhiteSpace(n)))
                                rows.Add(Row("Scope", k.Scope, "Store", k.Store, "ValueName", n, "State", ApprovedState(key.GetValue(n))));
                        }
                        catch (Exception) { }
                    }
                return rows;
            },
        };

        public static Provider TimeProvider => new Provider
        {
            RecordType = "TimeProvider", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "DllName", "Enabled", "InputProvider" },
            FalsePositives = "NtpClient and NtpServer are the usual pair. Hyper-V VMICTimeProvider and domain NTP stacks are common. Enabled flips are often GPO; DllName changing to a user-writable path is the review item.",
            SortKeys = new[] { "Name" },
            Collect = ctx =>
            {
                const string root = @"HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";
                return Reg.SubKeyNames(root).Where(n => n.Length > 0).Select(n =>
                {
                    var k = Reg.Join(root, n);
                    return Row("Name", n, "DllName", NotSet(Reg.Value(k, "DllName")), "Enabled", NotSet(Reg.Value(k, "Enabled")), "InputProvider", NotSet(Reg.Value(k, "InputProvider")));
                });
            },
        };

        public static Provider UserAutorun => new Provider
        {
            RecordType = "UserAutorun", IdentityFields = new[] { "SID", "Key", "ValueName" }, ComparedFields = new[] { "Command" },
            FalsePositives = "Cloud-sync, chat, and updaters write HKCU Run. Only loaded user hives are visible. Fleet-compare is noisy; temporal on one host is the usual reading.",
            SortKeys = new[] { "SID", "Key", "ValueName" },
            Collect = ctx =>
                from h in ctx.Hives
                from sub in new[]
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                    @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                }
                from v in Reg.ValueList(Reg.Join(h.Root, sub))
                select Row("SID", h.Sid, "UserName", h.UserName, "Key", v.Key, "ValueName", v.Name, "Command", v.Value),
        };

        public static Provider Winlogon => new Provider
        {
            RecordType = "Winlogon", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Some EDR and MFA packages change Userinit or Shell. Compare to the role image, not a busy analyst workstation.",
            SortKeys = new[] { "Name" },
            Collect = ctx => new[] { "Userinit", "Shell", "System", "UIHost", "GinaDLL", "Taskman", "ShellInfrastructure", "VmApplet", "AutoRestartShell" }
                .Select(n => Row("Name", n, "Value", NotSet(Reg.Value(@"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", n)))),
        };

        /// <summary>DLL path from a Winsock PackedCatalogItem: ANSI MAX_PATH on current Windows, UTF-16 on older layouts.</summary>
        internal static string WinsockPackedPath(object? v)
        {
            if (!(v is byte[] b) || b.Length < 4) return "(not set)";
            int lim = Math.Min(260, b.Length);
            bool ascii = true;
            for (int i = 0; i < lim; i++)
            {
                if (b[i] == 0) break;
                if (b[i] < 32 || b[i] > 126) { ascii = false; break; }
            }
            string s;
            if (ascii) s = Encoding.ASCII.GetString(b, 0, lim);
            else
            {
                int n = Math.Min(520, b.Length);
                if (n % 2 == 1) n--;
                s = Encoding.Unicode.GetString(b, 0, n);
            }
            int z = s.IndexOf('\0');
            if (z >= 0) s = s.Substring(0, z);
            s = s.Trim();
            return s.Length == 0 ? "(not set)" : s;
        }

        public static Provider WinsockLsp => new Provider
        {
            RecordType = "WinsockLsp", IdentityFields = new[] { "Kind", "Entry" }, ComparedFields = new[] { "LibraryPath" },
            FalsePositives = "VPN, filter, and endpoint-security products register LSPs and namespace providers. Stock Catalog_Entries are many (often mswsock.dll). A new LibraryPath outside System32 is the review item, not the numeric index itself.",
            SortKeys = new[] { "Kind", "Entry" },
            Collect = ctx =>
            {
                const string proto = @"HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9";
                const string ns = @"HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries";
                var rows = new List<Dictionary<string, object?>>();
                foreach (var leaf in new[] { "Catalog_Entries", "Catalog_Entries64" })
                {
                    var root = Reg.Join(proto, leaf);
                    var kind = leaf == "Catalog_Entries64" ? "Protocol64" : "Protocol";
                    rows.AddRange(Reg.SubKeyNames(root).Select(e => Row("Kind", kind, "Entry", e, "LibraryPath", WinsockPackedPath(Reg.Value(Reg.Join(root, e), "PackedCatalogItem")))));
                }
                rows.AddRange(Reg.SubKeyNames(ns).Select(e => Row("Kind", "Namespace", "Entry", e, "LibraryPath", NotSet(Reg.Value(Reg.Join(ns, e), "LibraryPath")))));
                return rows;
            },
        };

        static IEnumerable<Dictionary<string, object?>> Each(IEnumerable<string> roots, Func<string, IEnumerable<Dictionary<string, object?>>> read) =>
            roots.SelectMany(r => Safe(() => read(r)));
    }
}
