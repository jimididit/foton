using System.Linq;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>Autostart, tasks, services, Winlogon/IFEO, accessibility binaries, COM, Startup folder; network state.</summary>
    static class PersistenceRules
    {
        static string S(object? row, string name) => Str(Get(row, name));

        // Explorer\Shell Folders holds folder locations (Desktop, Documents, Start Menu), not commands; Collect lists the
        // key for its Startup value. Only that value is a persistence point, and only when it no longer names the
        // default Startup folder (a redirect makes Explorer run whatever sits in the new folder at logon).
        static bool ShellFolder(object? a) => S(a, "Key").EndsWith(@"\Explorer\Shell Folders", System.StringComparison.OrdinalIgnoreCase);
        static bool StartupFolderValue(object? a) => In(S(a, "ValueName"), "Common Startup", "Startup");
        static bool RedirectedStartup(object? a) => StartupFolderValue(a)
            && !S(a, "Command").TrimEnd('\\').EndsWith(@"\Microsoft\Windows\Start Menu\Programs\Startup", System.StringComparison.OrdinalIgnoreCase);

        // Defender's platform folder is under ProgramData, which the user-writable list matches, but only SYSTEM,
        // Administrators, and TrustedInstaller can write it. Exempt only Microsoft-signed binaries there, so a planted
        // file under a look-alike path still flags.
        static readonly System.Text.RegularExpressions.Regex DefenderPlatformPath = new System.Text.RegularExpressions.Regex(
            @"^[a-z]:\\ProgramData\\Microsoft\\Windows Defender( Advanced Threat Protection)?\\Platform\\[^\\]+\\[^\\]+\.exe$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        static bool DefenderPlatform(object? s) => DefenderPlatformPath.IsMatch(S(s, "ResolvedExe"))
            && Eq(Get(s, "SignatureStatus"), "Valid") && S(s, "Signer").IndexOf("O=Microsoft Corporation", System.StringComparison.OrdinalIgnoreCase) >= 0;

        public static void Persistence(AnalysisContext c)
        {
            var autoruns = c.Data["autorun_registry_keys"];
            if (IsTrue(autoruns))
            {
                var entries = Items(autoruns).Where(a => !ShellFolder(a) || StartupFolderValue(a)).ToList();
                var bad = entries.Where(a => ShellFolder(a) ? RedirectedStartup(a)
                    : Eq(Get(a, "UserWritableTarget"), true) || (a is PsRow r && c.ResolveHits(r, "SuspiciousHits", "Command").Length > 0)).ToList();
                if (bad.Count > 0)
                    c.Add("High", "Persistence", 2, "Autostart entries point to user-writable locations or contain risky patterns",
                        F("{0} of {1} autostart entries flagged. Sample: {2}.", bad.Count, entries.Count, Sample(bad.Select(a => (object?)$"{S(a, "ValueName")} = {S(a, "Command")}"), 4)),
                        "Run keys are the most common persistence mechanism. Entries executing from AppData or Temp, or invoking script interpreters, deserve individual verification.",
                        AnalysisContext.Artifact("Persistence", "autorun_registry_keys", "csv"),
                        "For each flagged entry, hash the target binary, check its signature, and determine the registry key write time from a registry hive if available.");
            }

            var tasks = c.Data["scheduled_tasks"];
            if (IsTrue(tasks))
            {
                var art = AnalysisContext.Artifact("Persistence", "scheduled_tasks", "csv");
                // Actions text is probed too, so older packages (Execute-only UserWritableTarget) still flag on re-analysis.
                var bad = Items(tasks).Where(t => Eq(Get(t, "UserWritableTarget"), true) || c.UserWritablePath(Get(t, "Actions"))
                    || (t is PsRow r && c.ResolveHits(r, "SuspiciousHits", "Actions").Length > 0)).ToList();
                if (bad.Count > 0)
                    c.Add("High", "Persistence", 2, "Scheduled tasks reference user-writable paths or risky commands",
                        F("{0} task(s) flagged. Sample: {1}.", bad.Count, Sample(bad.Select(t => (object?)$"{S(t, "TaskPath")}{S(t, "TaskName")}: {S(t, "Actions")}"), 4)),
                        "Scheduled tasks provide reliable, privileged persistence and are frequently created with innocuous names in the root task folder.",
                        art, "Compare against scheduled_task_files.csv creation timestamps to identify tasks created inside the incident window.");
                var sys = Items(tasks).Where(t => Match(Get(t, "RunAsUser"), "SYSTEM") && Eq(Get(t, "TaskPath"), "\\")).ToList();
                if (sys.Count > 0)
                    c.Add("Low", "Persistence", 1, "SYSTEM-level tasks exist in the root task folder",
                        F("{0} task(s): {1}.", sys.Count, Sample(Each(sys, t => Get(t, "TaskName")))),
                        @"Microsoft tasks are normally nested under \Microsoft\Windows\. Root-folder SYSTEM tasks are more often third-party software, but this is also where attacker-created tasks tend to land.",
                        art);
            }

            var svcs = c.Data["services"];
            if (IsTrue(svcs))
            {
                var art = AnalysisContext.Artifact("Persistence", "services", "csv");
                var userPath = Items(svcs).Where(s => Eq(Get(s, "UserWritablePath"), true) && IsTrue(Get(s, "ResolvedExe")) && !DefenderPlatform(s)).ToList();
                // ServiceDll columns exist from collect schema 1.13.0; older packages lack them.
                var userDll = Items(svcs).Where(s => s is PsRow r && r.Has("ServiceDllUserWritablePath") && Eq(r["ServiceDllUserWritablePath"], true) && IsTrue(r["ServiceDll"])).ToList();
                if (userPath.Count > 0 || userDll.Count > 0)
                {
                    var items = userPath.Select(s => (object?)$"{S(s, "Name")} -> {S(s, "PathName")}").Concat(userDll.Select(s => (object?)$"{S(s, "Name")} -> ServiceDll {S(s, "ServiceDll")}")).ToList();
                    c.Add("High", "Persistence", 2, "Services execute binaries from user-writable paths",
                        F("{0} service(s): {1}.", items.Count, Sample(items, 4)),
                        "A service binary or svchost ServiceDll in a user-writable directory can be replaced by a non-administrative user, and is also a common location for attacker-installed services.",
                        art);
                }
                var badDll = Items(svcs).Where(s => s is PsRow r && r.Has("ServiceDllSignatureStatus") && IsTrue(r["ServiceDll"]) && In(Str(r["ServiceDllSignatureStatus"]), "NotSigned", "HashMismatch")).ToList();
                if (badDll.Count > 0)
                    c.Add("Medium", "Persistence", 2, "svchost services load an unsigned or tampered ServiceDll",
                        F("{0} service(s): {1}.", badDll.Count, Sample(badDll.Select(s => (object?)$"{S(s, "Name")} -> {S(s, "ServiceDll")} [{S(s, "ServiceDllSignatureStatus")}]"), 4)),
                        "svchost.exe is always a signed Windows binary, so the ServiceDll is the code that actually runs. Windows service DLLs are signed; an unsigned one is usually third-party or in-house software, and HashMismatch means the file changed after signing. ServiceDll hijacking is a known way to hide persistence behind a normal-looking svchost process.",
                        art, "Check the DLL's publisher, install date, and the ServiceDllSHA256 against known-good copies of the software that owns the service.");
                var unquoted = Items(svcs).Where(s => Eq(Get(s, "UnquotedPath"), true)).ToList();
                if (unquoted.Count > 0)
                    c.Add("Medium", "Persistence", 1, "Services configured with unquoted paths containing spaces",
                        F("{0} service(s): {1}.", unquoted.Count, Sample(Each(unquoted, s => Get(s, "Name")))),
                        "Unquoted service paths are a privilege escalation vector if any parent directory is writable by a non-administrative user. This is a misconfiguration, not evidence of compromise.",
                        art);
                var unsigned = Items(svcs).Where(s => IsTrue(Get(s, "ResolvedExe")) && !In(Get(s, "SignatureStatus"), "Valid", "FileNotFound", "NotHashed") && Eq(Get(s, "State"), "Running")).ToList();
                if (unsigned.Count > 0)
                    c.Add("Medium", "Persistence", 2, "Running services with unsigned or invalid-signature binaries",
                        F("{0} service(s): {1}.", unsigned.Count, Sample(unsigned.Select(s => (object?)$"{S(s, "Name")} [{S(s, "SignatureStatus")}]"))),
                        "Unsigned service binaries are common in older or in-house software, so this is a prioritization signal rather than a detection.",
                        art);
            }

            var winlogon = c.Data["winlogon_lsa_and_dll_hijacks"];
            if (IsTrue(winlogon))
            {
                var art = AnalysisContext.Artifact("Persistence", "winlogon_lsa_and_dll_hijacks", "csv");
                var ifeo = Items(winlogon).Where(w => Eq(Get(w, "Mechanism"), "IFEO") && Eq(Get(w, "Name"), "Debugger")).ToList();
                if (ifeo.Count > 0)
                    c.Add("High", "Persistence", 2, "Image File Execution Options debugger entries present",
                        F("{0} entry/entries: {1}.", ifeo.Count, Sample(ifeo.Select(w => (object?)$"{S(w, "Location")} -> {S(w, "Value")}"), 4)),
                        "An IFEO Debugger value causes the named program to be replaced at launch by the specified binary. Legitimate uses exist (debuggers, some AV), but this is the mechanism behind sticky-keys style backdoors.",
                        art);
                var appInit = Items(winlogon).Where(w => Eq(Get(w, "Name"), "AppInit_DLLs") && IsTrue(Get(w, "Value"))).ToList();
                if (appInit.Count > 0)
                    c.Add("High", "Persistence", 2, "AppInit_DLLs is populated",
                        F("Value(s): {0}.", Sample(Each(appInit, w => Get(w, "Value")))),
                        "DLLs listed here load into most user-mode processes that link user32.dll, giving broad code injection with a single registry write.",
                        art);
                var shell = Items(winlogon).Where(w => Eq(Get(w, "Mechanism"), "Winlogon") && Eq(Get(w, "Name"), "Shell") && Ne(Get(w, "Value"), "explorer.exe")).ToList();
                var userinit = Items(winlogon).Where(w => Eq(Get(w, "Mechanism"), "Winlogon") && Eq(Get(w, "Name"), "Userinit") && !Match(Get(w, "Value"), @"^C:\\Windows\\system32\\userinit\.exe,?$")).ToList();
                if (shell.Count > 0 || userinit.Count > 0)
                    c.Add("High", "Persistence", 2, "Winlogon Shell or Userinit value is non-default",
                        F("Shell: {0}. Userinit: {1}.", Sample(Each(shell, w => Get(w, "Value"))), Sample(Each(userinit, w => Get(w, "Value")))),
                        "These values control what launches at interactive logon. Appended commands here execute for every logon with the user's privileges.",
                        art);
            }

            var access = c.Data["accessibility_binary_integrity"];
            if (IsTrue(access))
            {
                var tampered = Items(access).Where(a => IsTrue(Get(a, "IFEODebugger")) || (Ne(Get(a, "SignatureStatus"), "Valid") && Ne(Get(a, "SignatureStatus"), "NotHashed"))).ToList();
                if (tampered.Count > 0)
                    c.Add("High", "Persistence", 2, "Accessibility binaries show signs of replacement or hijack",
                        F("Affected: {0}.", Sample(tampered.Select(a => (object?)$"{S(a, "Binary")} sig={S(a, "SignatureStatus")} debugger={S(a, "IFEODebugger")}"))),
                        "Replacing sethc.exe or utilman.exe, or attaching a debugger to them, yields a SYSTEM shell from the pre-authentication logon screen.",
                        AnalysisContext.Artifact("Persistence", "accessibility_binary_integrity", "csv"),
                        "Compare file hash and modification time against a known-good build of the same Windows version.");
            }

            var com = c.Data["com_hijack_candidates"];
            if (IsTrue(com))
            {
                var bad = Items(com).Where(x => Eq(Get(x, "UserWritableTarget"), true)).ToList();
                if (bad.Count > 0)
                    c.Add("Medium", "Persistence", 2, "Per-user COM registrations target user-writable files",
                        F("{0} CLSID override(s): {1}.", bad.Count, Sample(bad.Select(x => (object?)$"{S(x, "User")} {S(x, "CLSID")} -> {S(x, "Target")}"), 4)),
                        "HKCU COM registrations take precedence over HKLM, so a per-user CLSID override pointing at a user-writable DLL can hijack legitimate component loads.",
                        AnalysisContext.Artifact("Persistence", "com_hijack_candidates", "csv"));
            }

            var startup = c.Data["startup_folder_items"];
            if (IsTrue(startup))
            {
                var unsigned = Items(startup).Where(s => !In(Get(s, "SignatureStatus"), "Valid", "NotHashed")).ToList();
                if (unsigned.Count > 0)
                    c.Add("Medium", "Persistence", 2, "Startup folder contains unsigned items",
                        F("{0} item(s): {1}.", unsigned.Count, Sample(Each(unsigned, s => Get(s, "FullName")), 4)),
                        "Startup folder placement requires no registry access and survives reboot. Shortcut (.lnk) items should be examined for their target and arguments.",
                        AnalysisContext.Artifact("Persistence", "startup_folder_items", "csv"));
            }
        }

        public static void Network(AnalysisContext c)
        {
            var conns = c.Data["active_connections"];
            if (IsTrue(conns))
            {
                var art = AnalysisContext.Artifact("Network", "active_connections", "csv");
                string Conn(object? x) => $"{S(x, "ProcessName")} -> {S(x, "RemoteAddress")}:{S(x, "RemotePort")}";
                var suspect = Items(conns).Where(x => Eq(Get(x, "RemoteIsExternal"), true) && Eq(Get(x, "UserWritablePath"), true)).ToList();
                if (suspect.Count > 0)
                    c.Add("High", "Network", 2, "External connections from binaries in user-writable paths",
                        F("{0} connection(s): {1}.", suspect.Count, Sample(suspect.Select(x => (object?)Conn(x)), 5)),
                        "This pairing - a binary outside standard install locations holding an outbound session - is a common command-and-control pattern, and also a common pattern for legitimate portable applications.",
                        art, "Resolve and enrich the remote addresses, and confirm the process hash against threat intelligence before treating this as C2.");
                var ext = Items(conns).Where(x => Eq(Get(x, "RemoteIsExternal"), true) && Eq(Get(x, "State"), "Established")).ToList();
                if (ext.Count > 0)
                    c.Add("Info", "Network", 1, "Established external connections at collection time",
                        F("{0} established external session(s). Sample: {1}.", ext.Count, Sample(ext.Select(x => (object?)Conn(x)), 6)),
                        "This is a point-in-time snapshot. Sessions that opened and closed before collection are not represented here.",
                        art);
            }

            var hosts = c.Data["hosts_file"];
            if (IsTrue(hosts))
            {
                var entries = Items(hosts).Where(h => IsTrue(h) && Str(h).Trim().Length > 0 && !Str(h).Trim().StartsWith("#", System.StringComparison.Ordinal)).ToList();
                if (entries.Count > 0)
                    c.Add("Medium", "Network", 1, "hosts file contains active entries",
                        F("{0} non-comment line(s): {1}.", entries.Count, Sample(entries, 5)),
                        "hosts entries override DNS. They are used both to block security vendor domains and to redirect traffic, and are also common in development environments.",
                        AnalysisContext.Artifact("Network", "hosts_file", "txt"));
            }
        }
    }
}
