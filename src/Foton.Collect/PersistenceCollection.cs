using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>
    /// Autoruns, tasks, services, WMI subscriptions, and the other autostart extensibility points
    /// (Invoke-FotonPersistenceCollection). Live facts only; Analyze interprets them on the workstation.
    /// </summary>
    public static class PersistenceCollection
    {
        const string Cat = "Persistence", Cimv2 = @"root\cimv2";
        const string Ifeo = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string SessionManager = @"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting persistence mechanisms (autoruns, tasks, services, WMI)", StatusLevel.Step);
            var hives = HostInfo.HiveRoots(s.IsElevated);
            Task(s, Cat, "autorun_registry_keys", "Run/RunOnce and policy autostart keys, machine and per-user", TaskFormat.Csv, () => Autoruns(hives));
            Task(s, Cat, "startup_folder_items", "Files in machine and per-user Startup folders", TaskFormat.Csv, () => StartupFolders(s));
            Task(s, Cat, "startup_approved", "Task Manager / Settings StartupApproved enable-disable bits (not the Startup folder)", TaskFormat.Csv, () => StartupApproved(hives));
            Task(s, Cat, "scheduled_tasks", "Scheduled tasks with actions, principals, and last run state", TaskFormat.Csv, () => ScheduledTasks(s));
            Task(s, Cat, "scheduled_task_files", "Task XML files on disk with timestamps (creation-time pivot)", TaskFormat.Csv, TaskFiles);
            Task(s, Cat, "services", "All services with binary path, signature, hash, unquoted-path flag, and ServiceDll for svchost-hosted services", TaskFormat.Csv, () => Services(s));
            Task(s, Cat, "wmi_event_subscriptions", "WMI filters, consumers, and bindings (fileless persistence)", TaskFormat.Txt, WmiSubscriptions);
            Task(s, Cat, "winlogon_lsa_and_dll_hijacks", "Winlogon Shell/Userinit, AppInit_DLLs, LSA packages, IFEO debuggers", TaskFormat.Csv, () => WinlogonAndHijacks(hives));
            Task(s, Cat, "accessibility_binary_integrity", "Sticky-keys style backdoor check on accessibility binaries", TaskFormat.Csv, () => Accessibility(s));
            Task(s, Cat, "cmd_autorun", "cmd.exe Command Processor AutoRun (HKLM and loaded HKCU)", TaskFormat.Csv, () => CmdAutoRun(hives));
            Task(s, Cat, "session_manager_boot", "Session Manager BootExecute family (includes PFRO as a live fact)", TaskFormat.Csv, SessionManagerBoot);
            Task(s, Cat, "known_dlls", "Session Manager KnownDLLs search-order map", TaskFormat.Csv, () =>
                Reg.ValueList(SessionManager + @"\KnownDLLs").Select(v => new Dictionary<string, object?> { ["Name"] = v.Name, ["MappedFile"] = v.Value }).ToList());
            Task(s, Cat, "winsock_lsp", "Winsock protocol and namespace catalog LibraryPath", TaskFormat.Csv, WinsockLsp);
            Task(s, Cat, "active_setup", "HKLM Active Setup Installed Components StubPath", TaskFormat.Csv, ActiveSetup);
            Task(s, Cat, "silent_process_exit", "SilentProcessExit MonitorProcess/ReportingMode (and IFEO GlobalFlag when present)", TaskFormat.Csv, SilentProcessExit);
            Task(s, Cat, "netsh_helpers", "Netsh helper DLL registrations (HKLM NetSh)", TaskFormat.Csv, () =>
                new[] { @"HKLM:\SOFTWARE\Microsoft\NetSh", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh" }
                    .SelectMany(root => Reg.ValueList(root).Where(v => v.Name.Length > 0 && v.Name != "(default)")
                        .Select(v => new Dictionary<string, object?> { ["Key"] = root, ["Name"] = v.Name, ["Dll"] = v.Value })).ToList());
            Task(s, Cat, "time_providers", "W32Time TimeProviders DllName (not NTP peer churn)", TaskFormat.Csv, TimeProviders);
            Task(s, Cat, "screensaver", "Screensaver executable from Desktop and policy keys (loaded hives). User churn; not a baseline.", TaskFormat.Csv, () => Screensaver(hives));
            Task(s, Cat, "com_hijack_candidates", "Per-user COM CLSID overrides pointing to user-writable DLLs", TaskFormat.Csv, () => ComHijack(hives));
            Task(s, Cat, "bits_jobs", "Background Intelligent Transfer jobs (download persistence)", TaskFormat.Txt, BitsJobs);
            Task(s, Cat, "office_addins_and_templates", "Office add-ins and startup template locations", TaskFormat.Csv, () => OfficeAddins(s, hives));
        }

        /// <summary>A registry value as PowerShell [string] rendered it, or (not set) when null or empty.</summary>
        static string NotSet(object? v)
        {
            var text = v == null ? "" : BaselineDocument.PsString(v);
            return text.Length == 0 ? "(not set)" : text;
        }

        static string Leaf(string key) => key.Substring(key.LastIndexOf('\\') + 1);

        /// <summary>A key path as a full registry name (HKEY_LOCAL_MACHINE\..., HKEY_USERS\...), as Get-ChildItem's Name gave it.</summary>
        static string FullName(string key) => key.Replace("Registry::", "").Replace(@"HKLM:\", @"HKEY_LOCAL_MACHINE\");

        static readonly string[] MachineRunKeys =
        {
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            @"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
        };

        static readonly string[] UserRunKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\RunServices",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        static object Autoruns(List<UserHive> hives)
        {
            Dictionary<string, object?> Row(string scope, string user, RegValue v) => new Dictionary<string, object?>
            {
                ["Scope"] = scope, ["User"] = user, ["Key"] = v.Key, ["ValueName"] = v.Name, ["Command"] = v.Value,
                // Analyze derives the hits from Command on the workstation; the pattern list never ships to endpoints.
                ["SuspiciousHits"] = "", ["UserWritableTarget"] = UserWritable(v.Value),
            };
            var rows = MachineRunKeys.SelectMany(k => Reg.ValueList(k)).Select(v => Row("Machine", "N/A", v)).ToList();
            foreach (var h in hives)
                foreach (var sub in UserRunKeys)
                    rows.AddRange(Reg.ValueList(Reg.Join(h.Root, sub)).Select(v => Row("User", h.UserName, v)));
            return rows;
        }

        static object StartupFolders(FotonSession s)
        {
            var paths = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp") };
            paths.AddRange(HostInfo.Profiles(s.IsElevated).Select(p => Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")));
            var rows = new List<Dictionary<string, object?>>();
            foreach (var p in paths.Where(HostInfo.Accessible))
            {
                FileSystemInfo[] items;
                try { items = new DirectoryInfo(p).GetFileSystemInfos(); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var f in items.Where(f => !string.Equals(f.Name, "desktop.ini", StringComparison.OrdinalIgnoreCase)))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["StartupFolder"] = p, ["Name"] = f.Name, ["FullName"] = f.FullName, ["SizeBytes"] = f is FileInfo fi ? fi.Length : (long?)null,
                        ["CreatedUtc"] = FotonTime.Format(f.CreationTimeUtc), ["ModifiedUtc"] = FotonTime.Format(f.LastWriteTimeUtc),
                        ["SignatureStatus"] = Authenticode.Check(f.FullName).Status, ["SHA256"] = Hashing.SafeHash(f.FullName, s.Options.SkipHashing),
                    });
            }
            return rows;
        }

        static object StartupApproved(List<UserHive> hives)
        {
            const string rel = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
            var stores = new[] { "Run", "Run32", "StartupFolder" };
            var keys = stores.Select(st => new { Scope = "HKLM", Store = st, Path = @"HKLM:\" + rel + "\\" + st }).ToList();
            foreach (var h in hives) keys.AddRange(stores.Select(st => new { Scope = h.Sid, Store = st, Path = h.Root + "\\" + rel + "\\" + st }));
            var rows = new List<Dictionary<string, object?>>();
            foreach (var k in keys)
                using (var key = Reg.Open(k.Path))
                {
                    if (key == null) continue;
                    try
                    {
                        foreach (var n in key.GetValueNames().Where(n => !string.IsNullOrWhiteSpace(n)))
                            rows.Add(new Dictionary<string, object?> { ["Scope"] = k.Scope, ["Store"] = k.Store, ["ValueName"] = n, ["State"] = RegDecode.StartupApprovedState(key.GetValue(n)) });
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException) { }
                }
            return rows.OrderBy(r => (string)r["Scope"]!, StringComparer.InvariantCultureIgnoreCase).ThenBy(r => (string)r["Store"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["ValueName"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        static readonly string[] TaskStates = { "Unknown", "Disabled", "Queued", "Ready", "Running" };
        static readonly string[] RunLevels = { "Limited", "Highest" };

        /// <summary>
        /// Task definitions from MSFT_ScheduledTask (Get-ScheduledTask's class) and run times from the Task Scheduler
        /// service; Get-ScheduledTaskInfo made one WMI method call per task for the same three values.
        /// </summary>
        static object ScheduledTasks(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, TaskRunInfo> runs;
            try { runs = TaskSchedulerInfo.All(); }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException || ex is UnauthorizedAccessException || ex is System.Reflection.TargetInvocationException)
            {
                runs = new Dictionary<string, TaskRunInfo>();
            }
            try
            {
                foreach (var t in Wmi.Query(@"root\Microsoft\Windows\TaskScheduler", "SELECT TaskPath, TaskName, State, Author, Description, Principal, Actions, Triggers FROM MSFT_ScheduledTask"))
                {
                    var actions = Raw(t, "Actions") as ManagementBaseObject[] ?? new ManagementBaseObject[0];
                    var actionTexts = new List<string>();
                    foreach (var a in actions)
                    {
                        var exe = Wmi.Str(a, "Execute");
                        if (exe.Length > 0) actionTexts.Add(exe + " " + Wmi.Str(a, "Arguments"));
                        else if (Wmi.Str(a, "ClassId") is var cls && cls.Length > 0) actionTexts.Add("COM:" + cls);
                    }
                    var actionText = string.Join(" | ", actionTexts);
                    var first = actions.Length > 0 ? Wmi.Str(actions[0], "Execute") : "";
                    var exePath = first.Length > 0 ? Environment.ExpandEnvironmentVariables(first.Trim('"')) : "";
                    // Probe Execute, the action text, arguments, and working directory: an interpreter-only check misses
                    // powershell.exe -File C:\Temp\... (a user-writable payload).
                    var probes = new List<string> { exePath, actionText };
                    foreach (var a in actions) { probes.Add(Wmi.Str(a, "Arguments")); probes.Add(Wmi.Str(a, "WorkingDirectory")); }
                    var principal = Raw(t, "Principal") as ManagementBaseObject;
                    var runLevel = principal != null && Raw(principal, "RunLevel") is object rl ? Named(RunLevels, rl) : "";
                    var taskPath = Wmi.Str(t, "TaskPath");
                    var taskName = Wmi.Str(t, "TaskName");
                    runs.TryGetValue(taskPath + taskName, out var run);
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["TaskPath"] = taskPath, ["TaskName"] = taskName, ["State"] = Raw(t, "State") is object st ? Named(TaskStates, st) : "",
                        ["Author"] = Wmi.Str(t, "Author"), ["RunAsUser"] = principal != null ? Wmi.Str(principal, "UserId") : "", ["RunLevel"] = runLevel,
                        ["Triggers"] = string.Join(", ", (Raw(t, "Triggers") as ManagementBaseObject[] ?? new ManagementBaseObject[0]).Where(x => x != null).Select(x => x.ClassPath.ClassName)),
                        ["Actions"] = actionText,
                        ["LastRunTime"] = run?.LastRunUtc is DateTime last ? FotonTime.Format(last) : "",
                        ["LastResult"] = run != null ? (object)run.LastResult : "",
                        ["NextRunTime"] = run?.NextRunUtc is DateTime next ? FotonTime.Format(next) : "",
                        ["Description"] = Wmi.Str(t, "Description"),
                        ["SuspiciousHits"] = "",
                        ["UserWritableTarget"] = probes.Any(UserWritable),
                        ["SHA256"] = Hashing.SafeHash(exePath, s.Options.SkipHashing),
                    });
                }
            }
            catch (Exception ex) when (WmiFailed(ex))
            {
                rows.Add(new Dictionary<string, object?>
                {
                    ["TaskPath"] = "ERROR", ["TaskName"] = ex.Message, ["State"] = "", ["Author"] = "", ["RunAsUser"] = "", ["RunLevel"] = "", ["Triggers"] = "", ["Actions"] = "",
                    ["LastRunTime"] = "", ["LastResult"] = "", ["NextRunTime"] = "", ["Description"] = "", ["SuspiciousHits"] = "", ["UserWritableTarget"] = false, ["SHA256"] = "",
                });
            }
            return rows;
        }

        static string Named(string[] names, object v)
        {
            var i = Convert.ToInt32(v, CultureInfo.InvariantCulture);
            return i >= 0 && i < names.Length ? names[i] : i.ToString(CultureInfo.InvariantCulture);
        }

        static object TaskFiles()
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            if (!Directory.Exists(root)) return new object[0];
            var rows = new List<Dictionary<string, object?>>();
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                var dir = pending.Pop();
                try
                {
                    foreach (var f in new DirectoryInfo(dir).GetFiles())
                        rows.Add(new Dictionary<string, object?>
                        {
                            ["FullName"] = f.FullName, ["CreatedUtc"] = FotonTime.Format(f.CreationTimeUtc), ["ModifiedUtc"] = FotonTime.Format(f.LastWriteTimeUtc), ["Length"] = f.Length,
                        });
                    foreach (var d in Directory.GetDirectories(dir)) pending.Push(d);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
            return rows.OrderByDescending(r => (string)r["ModifiedUtc"]!, StringComparer.Ordinal).ThenBy(r => (string)r["FullName"]!, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static readonly Regex ExeInPath = new Regex(@"^(.*?\.exe)(?=\s|$)", RegexOptions.IgnoreCase);
        static readonly Regex PerUserInstance = new Regex("^(?<base>.+)_[0-9a-fA-F]{4,8}$");
        const string ServicesKey = @"HKLM:\SYSTEM\CurrentControlSet\Services\";

        /// <summary>The executable a service ImagePath launches: the quoted part, else up to the first ".exe", else the first word.</summary>
        internal static string ServiceExe(string pathName)
        {
            if (pathName.Length == 0) return "";
            string exe;
            if (pathName.StartsWith("\"", StringComparison.Ordinal)) exe = pathName.Split('"')[1];
            else
            {
                var m = ExeInPath.Match(pathName);
                exe = m.Success ? m.Groups[1].Value : pathName.Split(' ')[0];
            }
            return Environment.ExpandEnvironmentVariables(exe);
        }

        static object Services(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var svc in Wmi.QueryReadable(Cimv2, "SELECT Name, DisplayName, State, StartMode, StartName, ProcessId, PathName, ServiceType, Description FROM Win32_Service", out _))
            {
                var name = Wmi.Str(svc, "Name");
                var pathName = Wmi.Str(svc, "PathName");
                var exe = ServiceExe(pathName);
                bool unquoted = pathName.Length > 0 && !pathName.StartsWith("\"", StringComparison.Ordinal) && pathName.Contains(" ") && exe.Contains(" ");
                var exeFile = Authenticode.Openable(exe);
                var sig = Authenticode.Check(exeFile);
                // svchost-hosted services share one image; the code that runs is the ServiceDll under Parameters (older
                // services set it on the service key). Per-user instances (Name_<hex>) use their template's ServiceDll.
                string dll = "", dllSource = "", dllHash = "";
                var dllSig = new SignatureInfo { Status = "" };
                if (Regex.IsMatch(exe, @"\\svchost\.exe$", RegexOptions.IgnoreCase))
                {
                    dll = BaselineDocument.PsString(Reg.Value(ServicesKey + name + @"\Parameters", "ServiceDll"));
                    if (dll.Length > 0) dllSource = "Parameters";
                    else
                    {
                        dll = BaselineDocument.PsString(Reg.Value(ServicesKey + name, "ServiceDll"));
                        if (dll.Length > 0) dllSource = "ServiceKey";
                    }
                    var inst = PerUserInstance.Match(name);
                    if (dll.Length == 0 && inst.Success)
                    {
                        var template = inst.Groups["base"].Value;
                        dll = BaselineDocument.PsString(Reg.Value(ServicesKey + template + @"\Parameters", "ServiceDll"));
                        if (dll.Length == 0) dll = BaselineDocument.PsString(Reg.Value(ServicesKey + template, "ServiceDll"));
                        if (dll.Length > 0) dllSource = "Template:" + template;
                    }
                    if (dll.Length > 0)
                    {
                        dll = Environment.ExpandEnvironmentVariables(dll);
                        dllSig = Authenticode.Check(Authenticode.Openable(dll));
                        dllHash = Hashing.SafeHash(Authenticode.Openable(dll), s.Options.SkipHashing);
                    }
                }
                rows.Add(new Dictionary<string, object?>
                {
                    ["Name"] = name, ["DisplayName"] = Raw(svc, "DisplayName"), ["State"] = Raw(svc, "State"), ["StartMode"] = Raw(svc, "StartMode"),
                    ["StartName"] = Raw(svc, "StartName"), ["ProcessId"] = Raw(svc, "ProcessId"), ["PathName"] = pathName, ["ResolvedExe"] = exe,
                    ["ServiceType"] = Raw(svc, "ServiceType"), ["UnquotedPath"] = unquoted, ["UserWritablePath"] = UserWritable(exe),
                    ["SignatureStatus"] = sig.Status, ["Signer"] = sig.Signer, ["SHA256"] = Hashing.SafeHash(exeFile, s.Options.SkipHashing),
                    ["ServiceDll"] = dll, ["ServiceDllSource"] = dllSource, ["ServiceDllUserWritablePath"] = dll.Length > 0 && UserWritable(dll),
                    ["ServiceDllSignatureStatus"] = dllSig.Status, ["ServiceDllSigner"] = dllSig.Signer, ["ServiceDllSHA256"] = dllHash,
                    ["Description"] = Raw(svc, "Description"),
                });
            }
            return rows.OrderBy(r => (string)r["Name"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        static object WmiSubscriptions()
        {
            var lines = new List<string>();
            foreach (var cls in new[] { "__EventFilter", "__EventConsumer", "__FilterToConsumerBinding" })
            {
                lines.Add($"=== {cls} ===");
                try
                {
                    var items = Wmi.Query(@"root\subscription", "SELECT * FROM " + cls);
                    if (items.Count == 0) lines.Add("(none)");
                    foreach (var item in items)
                    {
                        lines.Add("__CLASS : " + item.ClassPath.ClassName);
                        lines.AddRange(PropertyList(item));
                    }
                }
                catch (Exception ex) when (WmiFailed(ex)) { lines.Add("Error: " + ex.Message); }
            }
            return lines;
        }

        static object WinlogonAndHijacks(List<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            void Add(string mechanism, string location, string name, string value) =>
                rows.Add(new Dictionary<string, object?> { ["Mechanism"] = mechanism, ["Location"] = location, ["Name"] = name, ["Value"] = value });

            const string winlogon = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            foreach (var n in new[] { "Shell", "Userinit", "Taskman", "AppSetup", "GinaDLL", "UserInitMprLogonScript" })
                if (Reg.Value(winlogon, n) is object v && Truthy(v)) Add("Winlogon", winlogon, n, BaselineDocument.PsString(v));
            foreach (var k in new[] { @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
                foreach (var n in new[] { "AppInit_DLLs", "LoadAppInit_DLLs", "Load", "Run", "IconServiceLib" })
                    if (Reg.Value(k, n) is object v && BaselineDocument.PsString(v).Length > 0) Add("AppInit/Windows", k, n, BaselineDocument.PsString(v));
            const string lsa = @"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            foreach (var n in new[] { "Authentication Packages", "Notification Packages", "Security Packages" })
                if (Reg.Value(lsa, n) is object v && Truthy(v)) Add("LSA Package", lsa, n, v is string[] a ? string.Join(", ", a) : BaselineDocument.PsString(v));
            const string sp = @"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders";
            if (Reg.Value(sp, "SecurityProviders") is object spv && Truthy(spv)) Add("SecurityProviders", sp, "SecurityProviders", BaselineDocument.PsString(spv));
            foreach (var sub in Reg.SubKeyNames(Ifeo))
            {
                var key = Reg.Join(Ifeo, sub);
                foreach (var n in new[] { "Debugger", "GlobalFlag", "MonitorProcess" })
                    if (Reg.Value(key, n) is object v && Truthy(v)) Add("IFEO", FullName(key), n, BaselineDocument.PsString(v));
            }
            foreach (var v in Reg.ValueList(SessionManager + @"\AppCertDlls")) Add("AppCertDlls", v.Key, v.Name, v.Value);
            var smNames = new[] { "BootExecute", "SetupExecute", "Execute", "S0InitialCommand", "PendingFileRenameOperations" };
            foreach (var v in Reg.ValueList(SessionManager).Where(v => smNames.Contains(v.Name, StringComparer.OrdinalIgnoreCase))) Add("SessionManager", v.Key, v.Name, v.Value);
            // Each monitor is a subkey whose Driver DLL the spooler loads as SYSTEM.
            const string monitors = @"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors";
            foreach (var sub in Reg.SubKeyNames(monitors))
                Add("PrintMonitor", Reg.Join(monitors, sub), sub, Reg.Value(Reg.Join(monitors, sub), "Driver") is object d ? BaselineDocument.PsString(d) : "");
            foreach (var v in Reg.ValueList(@"HKLM:\SOFTWARE\Microsoft\Netsh")) Add("NetshHelper", v.Key, v.Name, v.Value);
            foreach (var h in hives)
            {
                var env = Reg.Join(h.Root, "Environment");
                if (Reg.Value(env, "UserInitMprLogonScript") is object v && Truthy(v)) Add("LogonScript", $"{h.UserName}: {env}", "UserInitMprLogonScript", BaselineDocument.PsString(v));
            }
            return rows;
        }

        static object Accessibility(FotonSession s)
        {
            // %SystemRoot%\System32, as 1.38.x spelled it (GetFolderPath returns a lowercase "system32").
            var sys = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? HostInfo.WindowsDir, "System32");
            var rows = new List<Dictionary<string, object?>>();
            foreach (var t in new[] { "sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe", "AtBroker.exe" })
            {
                var p = Path.Combine(sys, t);
                if (!File.Exists(p)) continue;
                var fi = new FileInfo(p);
                var sig = Authenticode.Check(p);
                rows.Add(new Dictionary<string, object?>
                {
                    ["Binary"] = t, ["Path"] = p, ["SizeBytes"] = fi.Length, ["ModifiedUtc"] = FotonTime.Format(fi.LastWriteTimeUtc),
                    ["SignatureStatus"] = sig.Status, ["IsOSBinary"] = sig.IsOSBinary,
                    ["IFEODebugger"] = BaselineDocument.PsString(Reg.Value(Reg.Join(Ifeo, t), "Debugger")),
                    ["SHA256"] = Hashing.SafeHash(p, s.Options.SkipHashing),
                });
            }
            return rows;
        }

        static object CmdAutoRun(List<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var rel in new[] { @"SOFTWARE\Microsoft\Command Processor", @"SOFTWARE\Wow6432Node\Microsoft\Command Processor" })
            {
                if (rel.Contains("Wow6432Node") && !Reg.Exists(@"HKLM:\SOFTWARE\Wow6432Node")) continue;
                rows.Add(new Dictionary<string, object?> { ["Scope"] = "HKLM", ["Key"] = rel, ["Command"] = NotSet(Reg.Value(@"HKLM:\" + rel, "AutoRun")) });
            }
            foreach (var h in hives)
                foreach (var rel in new[] { @"Software\Microsoft\Command Processor", @"Software\Wow6432Node\Microsoft\Command Processor" })
                {
                    var v = Reg.Value(Reg.Join(h.Root, rel), "AutoRun");
                    if (v == null || BaselineDocument.PsString(v).Length == 0) continue;
                    rows.Add(new Dictionary<string, object?> { ["Scope"] = h.UserName, ["Key"] = rel, ["Command"] = BaselineDocument.PsString(v) });
                }
            return rows;
        }

        static object SessionManagerBoot() =>
            new[] { "BootExecute", "BootExecuteNoPnpSync", "SetupExecute", "Execute", "S0InitialCommand", "PendingFileRenameOperations" }.Select(n =>
            {
                var v = Reg.Value(SessionManager, n);
                var parts = v == null ? new string[0]
                    : (v is string[] a ? a : new[] { BaselineDocument.PsString(v) }).Where(x => !string.IsNullOrEmpty(x)).ToArray();
                return new Dictionary<string, object?> { ["Name"] = n, ["Value"] = parts.Length == 0 ? "(not set)" : string.Join(" ", parts) };
            }).ToList();

        static object WinsockLsp()
        {
            const string proto = @"HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9";
            const string ns = @"HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5";
            var rows = new List<Dictionary<string, object?>>();
            foreach (var leaf in new[] { "Catalog_Entries", "Catalog_Entries64" })
            {
                var root = Reg.Join(proto, leaf);
                if (!Reg.Exists(root)) continue;
                var kind = leaf == "Catalog_Entries64" ? "Protocol64" : "Protocol";
                rows.AddRange(Reg.SubKeyNames(root).Select(e => new Dictionary<string, object?>
                {
                    ["Kind"] = kind, ["Entry"] = e, ["LibraryPath"] = RegDecode.WinsockPackedPath(Reg.Value(Reg.Join(root, e), "PackedCatalogItem")),
                }));
            }
            foreach (var leaf in new[] { "Catalog_Entries", "Catalog_Entries64" })
            {
                var root = Reg.Join(ns, leaf);
                var kind = leaf == "Catalog_Entries64" ? "Namespace64" : "Namespace";
                rows.AddRange(Reg.SubKeyNames(root).Select(e => new Dictionary<string, object?>
                {
                    ["Kind"] = kind, ["Entry"] = e, ["LibraryPath"] = NotSet(Reg.Value(Reg.Join(root, e), "LibraryPath")),
                }));
            }
            return rows;
        }

        static object ActiveSetup()
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var root in new[] { @"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components", @"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" })
            {
                if (!Reg.Exists(root)) continue;
                foreach (var guid in Reg.SubKeyNames(root))
                {
                    var key = Reg.Join(root, guid);
                    rows.Add(new Dictionary<string, object?> { ["Key"] = root, ["Guid"] = guid, ["StubPath"] = NotSet(Reg.Value(key, "StubPath")), ["Version"] = NotSet(Reg.Value(key, "Version")) });
                }
            }
            return rows;
        }

        static object SilentProcessExit()
        {
            const string root = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
            return Reg.SubKeyNames(root).Select(name =>
            {
                var key = Reg.Join(root, name);
                return new Dictionary<string, object?>
                {
                    ["ImageName"] = name, ["MonitorProcess"] = NotSet(Reg.Value(key, "MonitorProcess")), ["ReportingMode"] = NotSet(Reg.Value(key, "ReportingMode")),
                    ["LocalDumpFolder"] = NotSet(Reg.Value(key, "LocalDumpFolder")), ["IfeoGlobalFlag"] = NotSet(Reg.Value(Reg.Join(Ifeo, name), "GlobalFlag")),
                };
            }).ToList();
        }

        static object TimeProviders()
        {
            const string root = @"HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";
            return Reg.SubKeyNames(root).Select(name =>
            {
                var key = Reg.Join(root, name);
                return new Dictionary<string, object?>
                {
                    ["Name"] = name, ["DllName"] = NotSet(Reg.Value(key, "DllName")), ["Enabled"] = NotSet(Reg.Value(key, "Enabled")), ["InputProvider"] = NotSet(Reg.Value(key, "InputProvider")),
                };
            }).ToList();
        }

        static object Screensaver(List<UserHive> hives)
        {
            var names = new[] { "SCRNSAVE.EXE", "ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut" };
            var rows = new List<Dictionary<string, object?>>();
            void Emit(string scope, string user, string source, string key)
            {
                if (!Reg.Exists(key)) return;
                foreach (var n in names)
                {
                    var v = Reg.Value(key, n);
                    if (v == null || BaselineDocument.PsString(v).Length == 0) continue;
                    rows.Add(new Dictionary<string, object?> { ["Scope"] = scope, ["User"] = user, ["Source"] = source, ["ValueName"] = n, ["Value"] = BaselineDocument.PsString(v) });
                }
            }
            Emit("Machine", "N/A", "Policy", @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop");
            foreach (var h in hives)
            {
                Emit("User", h.UserName, "Desktop", Reg.Join(h.Root, @"Control Panel\Desktop"));
                Emit("User", h.UserName, "Policy", Reg.Join(h.Root, @"Software\Policies\Microsoft\Windows\Control Panel\Desktop"));
            }
            return rows;
        }

        static object ComHijack(List<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var h in hives)
            {
                var root = Reg.Join(h.Root, @"Software\Classes\CLSID");
                foreach (var clsid in Reg.SubKeyNames(root))
                    foreach (var server in new[] { "InprocServer32", "LocalServer32", "InprocHandler32" })
                    {
                        var target = Reg.Value(Reg.Join(Reg.Join(root, clsid), server), "");
                        if (!Truthy(target)) continue;
                        var text = BaselineDocument.PsString(target);
                        rows.Add(new Dictionary<string, object?> { ["User"] = h.UserName, ["CLSID"] = clsid, ["ServerType"] = server, ["Target"] = text, ["UserWritableTarget"] = UserWritable(text) });
                    }
            }
            return rows;
        }

        static object BitsJobs()
        {
            var lines = new List<string>();
            try
            {
                var jobs = Bits.Jobs();
                if (jobs.Count == 0) lines.Add("(no BITS jobs)");
                foreach (var j in jobs)
                {
                    var fields = new[]
                    {
                        new[] { "JobId", j.JobId }, new[] { "DisplayName", j.DisplayName }, new[] { "JobState", j.JobState }, new[] { "OwnerAccount", j.OwnerAccount },
                        new[] { "TransferType", j.TransferType }, new[] { "CreationTime", j.CreationTimeUtc.HasValue ? FotonTime.Format(j.CreationTimeUtc.Value) + " UTC" : "" },
                        new[] { "FileList", "{" + string.Join(", ", j.Files) + "}" },
                    };
                    lines.Add("");
                    lines.AddRange(fields.Select(f => f[0].PadRight(12) + " : " + TextFile.OneLine(f[1])));
                }
                lines.Add("");
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException || ex is UnauthorizedAccessException || ex is InvalidCastException)
            {
                lines.Add("BITS jobs unavailable: " + ex.Message);
            }
            lines.Add("--- bitsadmin /list /allusers /verbose ---");
            lines.Add(Exec.System32("bitsadmin.exe", "/list /allusers /verbose"));
            return lines;
        }

        static readonly Regex OfficeKey = new Regex(@"Addins|Resiliency|Security\\Trusted Locations", RegexOptions.IgnoreCase);

        static object OfficeAddins(FotonSession s, List<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var h in hives)
            {
                var office = Reg.Join(h.Root, @"Software\Microsoft\Office");
                if (!Reg.Exists(office)) continue;
                // Every subkey under Office (Get-ChildItem -Recurse order), depth-capped against a pathological tree.
                var pending = new Stack<KeyValuePair<string, int>>();
                foreach (var sub in Reg.SubKeyNames(office).Reverse()) pending.Push(new KeyValuePair<string, int>(Reg.Join(office, sub), 1));
                while (pending.Count > 0)
                {
                    var item = pending.Pop();
                    if (OfficeKey.IsMatch(FullName(item.Key)))
                        rows.AddRange(Reg.ValueList(item.Key).Select(v => new Dictionary<string, object?> { ["User"] = h.UserName, ["Key"] = FullName(v.Key), ["Name"] = v.Name, ["Value"] = v.Value }));
                    if (item.Value >= 16) continue;
                    foreach (var sub in Reg.SubKeyNames(item.Key).Reverse()) pending.Push(new KeyValuePair<string, int>(Reg.Join(item.Key, sub), item.Value + 1));
                }
            }
            foreach (var p in HostInfo.Profiles(s.IsElevated))
            {
                var startup = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Word\STARTUP");
                if (!HostInfo.Accessible(startup)) continue;
                try
                {
                    foreach (var f in new DirectoryInfo(startup).GetFileSystemInfos())
                        rows.Add(new Dictionary<string, object?> { ["User"] = p.UserName, ["Key"] = "Word STARTUP folder", ["Name"] = f.Name, ["Value"] = f.FullName });
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
            return rows;
        }
    }
}
