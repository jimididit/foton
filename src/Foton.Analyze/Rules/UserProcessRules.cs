using System.Linq;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>Local accounts and groups, running processes, PowerShell console history.</summary>
    static class UserProcessRules
    {
        static bool Enabled(object? row) => Eq(Get(row, "Enabled"), true) || Eq(Get(row, "Enabled"), "True");

        public static void Accounts(AnalysisContext c)
        {
            var users = c.Data["local_users"];
            if (IsTrue(users))
            {
                var art = AnalysisContext.Artifact("Users", "local_users", "csv");
                if (Items(users).Any(u => Eq(Get(u, "Name"), "Guest") && Enabled(u)))
                    c.Add("Medium", "Users", 1, "Guest account is enabled", "The built-in Guest account is enabled.",
                        "The Guest account is disabled by default. Enabling it creates an unauthenticated access path and is occasionally used to maintain low-visibility access.", art);
                var noPw = Items(users).Where(u => Eq(Get(u, "PasswordRequired"), false) && Enabled(u)).ToList();
                if (noPw.Count > 0)
                    c.Add("Medium", "Users", 1, "Enabled accounts do not require a password",
                        F("Account(s): {0}.", Sample(Each(noPw, u => Get(u, "Name")))),
                        "Accounts without a password requirement can be used for local logon and, depending on policy, remote authentication.", art);
            }

            var groups = c.Data["local_group_membership"];
            if (IsTrue(groups))
            {
                var admins = Items(groups).Where(g => Eq(Get(g, "Group"), "Administrators") && Ne(Get(g, "Member"), "(none)")).ToList();
                if (admins.Count > 0)
                    c.Add(admins.Count > 5 ? "Low" : "Info", "Users", 1, "Local Administrators group membership",
                        F("{0} member(s): {1}.", admins.Count, Sample(Each(admins, a => Get(a, "Member")), 8)),
                        "Membership should be compared against the organization's expected baseline. Unexpected members, especially local (non-domain) accounts, warrant follow-up.",
                        AnalysisContext.Artifact("Users", "local_group_membership", "csv"),
                        "Cross-reference with security_account_management.csv (event 4732) to see whether any member was added inside the collection window.");
            }
        }

        static readonly string[] OfficeParents = { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "visio.exe" };
        static readonly string[] ChildShells = { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe" };

        public static void Processes(AnalysisContext c)
        {
            var procs = c.Data["running_processes"];
            if (IsTrue(procs))
            {
                var art = AnalysisContext.Artifact("Processes", "running_processes", "csv");
                var unsigned = Items(procs).Where(p => Eq(Get(p, "UserWritablePath"), true) && Ne(Get(p, "SignatureStatus"), "Valid") && IsTrue(Get(p, "Path"))).ToList();
                if (unsigned.Count > 0)
                    c.Add("High", "Processes", 2, "Unsigned processes running from user-writable paths",
                        F("{0} process(es): {1}.", unsigned.Count, Sample(unsigned.Select(p => (object?)$"{Str(Get(p, "Name"))} [PID {Str(Get(p, "PID"))}] {Str(Get(p, "Path"))}"))),
                        "Legitimate software is normally installed under Program Files and signed. Unsigned executables running from AppData, Temp, or ProgramData match common malware staging behavior, but also match some legitimate updaters and developer tooling.",
                        art, "Submit the SHA-256 values in the artifact to threat intelligence, and check parent process and creation time for each.");

                var susp = Rows(procs).Select(p => new { Name = p["Name"], Hits = c.ResolveHits(p, "SuspiciousCmdHits", "CommandLine") })
                    .Where(x => x.Hits.Length > 0).ToList();
                if (susp.Count > 0)
                    c.Add("High", "Processes", 2, "Running process command lines contain high-risk patterns",
                        F("{0} process(es) matched: {1}.", susp.Count, Sample(susp.Select(x => (object?)$"{Str(x.Name)} [{x.Hits}]"))),
                        "Patterns such as encoded commands, in-memory download-and-execute, and shadow copy deletion are heavily used in intrusions. They also appear in legitimate management tooling, so each match needs to be read in context.",
                        art, "Decode any base64 command lines and review the full CommandLine column in the artifact before drawing conclusions.");

                var odd = Items(procs).Where(p => IsTrue(Get(p, "ParentName")) && IsTrue(Get(p, "Name"))
                    && In(Str(Get(p, "ParentName")).ToLower(), OfficeParents) && In(Str(Get(p, "Name")).ToLower(), ChildShells)).ToList();
                if (odd.Count > 0)
                    c.Add("High", "Processes", 2, "Office application spawned a scripting or shell process",
                        F("Observed: {0}.", Sample(odd.Select(p => (object?)$"{Str(Get(p, "ParentName"))} -> {Str(Get(p, "Name"))} [PID {Str(Get(p, "PID"))}]"))),
                        "Office applications spawning shells or script hosts is a classic macro or exploit execution chain. Some add-ins do this legitimately, so confirm the command line and the originating document.",
                        AnalysisContext.Artifact("Processes", "process_tree", "txt"));
            }

            var hist = c.Data["powershell_console_history"];
            if (IsTrue(hist))
            {
                var flagged = Rows(hist).Where(h => c.ResolveHits(h, "SuspiciousHits", "Command").Length > 0).ToList();
                if (flagged.Count > 0)
                    c.Add("High", "Processes", 2, "PowerShell console history contains high-risk commands",
                        F("{0} matching line(s) across profiles. Sample: {1}.", flagged.Count, Sample(flagged.Select(h => (object?)$"{Str(h["User"])}: {Str(h["Command"])}"), 4)),
                        "PSReadLine history persists across reboots and is not covered by event log retention, so it often preserves activity that logging missed. Note that history files are user-editable and carry no timestamps.",
                        AnalysisContext.Artifact("Processes", "powershell_console_history", "csv"),
                        "Correlate each command with PowerShell operational events (4104) and process creation events (4688) to establish execution and timing.");
            }
        }
    }
}
