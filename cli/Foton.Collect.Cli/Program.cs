using System;
using System.Globalization;
using System.IO;
using System.Linq;
using Foton.Collect;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect.Cli
{
    /// <summary>
    /// foton-collect.exe: live triage collection into a hashed case package (the 1.38.x Collect flatten). Same switches
    /// as the flatten. Administrator preferred; a standard token collects what it can read and records the gaps.
    /// </summary>
    static class Program
    {
        static int Main(string[] args)
        {
            var o = new SessionOptions
            {
                OutputPath = OutputFolder.Default("Cases"),
                Examiner = Environment.UserName,
            };
            bool defaultOutput = true;
            string? profilePath = null, categories = null;
            // Switches given here win over the same option in a profile.
            var explicitSwitches = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i];
                bool Is(string name)
                {
                    if (!string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return false;
                    explicitSwitches.Add(name.TrimStart('-'));
                    return true;
                }
                // A following switch is never taken as a value ("-OutputPath -NoZip" is a missing folder, not a folder named -NoZip).
                string? Next() => i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal) ? args[++i] : null;
                if (Is("-Version") || Is("--version") || Is("version"))
                {
                    foreach (var line in FotonVersion.Describe("foton-collect")) Console.WriteLine(line);
                    return 0;
                }
                if (Is("-OutputPath")) { var v = Next(); if (v == null) return Usage("-OutputPath needs a folder."); o.OutputPath = v; defaultOutput = false; }
                else if (Is("-CaseNumber")) { var v = Next(); if (v == null) return Usage("-CaseNumber needs a value."); o.CaseNumber = v; }
                else if (Is("-Examiner")) { var v = Next(); if (v == null) return Usage("-Examiner needs a value."); o.Examiner = v; }
                else if (Is("-EventLogDays")) { if (!Int(Next(), out var n)) return Usage("-EventLogDays needs a whole number of days."); o.EventLogDays = n; }
                else if (Is("-MaxEventsPerLog")) { if (!Int(Next(), out var n)) return Usage("-MaxEventsPerLog needs a whole number."); o.MaxEventsPerLog = n; }
                else if (Is("-SkipEvtxExport")) o.SkipEvtxExport = true;
                else if (Is("-SkipHashing")) o.SkipHashing = true;
                else if (Is("-LoadUserHives")) o.LoadUserHives = true;
                else if (Is("-IncludeFileTimeline")) o.IncludeFileTimeline = true;
                else if (Is("-IncludeUsnJournal")) o.IncludeUsnJournal = true;
                else if (Is("-Deep")) o.Deep = true;
                else if (Is("-NoZip")) o.NoZip = true;
                else if (Is("-RequireAdministrator")) o.RequireAdministrator = true;
                else if (Is("-Profile")) { profilePath = Next(); if (profilePath == null) return Usage("-Profile needs a profile file."); }
                else if (Is("-Category"))
                {
                    // PowerShell passes "-Category A,B" to a native program as separate values, so take every value up to the next switch.
                    var parts = new System.Collections.Generic.List<string>();
                    for (var v = Next(); v != null; v = Next()) parts.Add(v);
                    if (parts.Count == 0) return Usage("-Category needs one or more category names.");
                    categories = string.Join(",", parts);
                }
                else return Usage("Unknown argument: " + a);
            }
            if (profilePath != null || categories != null)
            {
                CollectionProfile profile;
                try
                {
                    profile = profilePath != null ? CollectionProfile.Load(profilePath) : CollectionProfile.FromCategories(categories!);
                    if (profilePath != null && categories != null) profile = profile.WithCategories(categories);
                }
                catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
                {
                    return Usage("Collection profile not used: " + ex.Message);
                }
                var unknown = Categories.UnknownTaskNames(profile.ExcludeTasks);
                if (unknown.Length > 0)
                    return Usage($"Collection profile not used: ExcludeTasks names no Collect task: {string.Join(", ", unknown)}. Task names are the Task column of collection_manifest.csv, or {CollectionProfile.EvtxExport}.");
                profile.ApplyTo(o, explicitSwitches);
            }
            // -Deep turns on the depth switches; they still work alone without it.
            if (o.Deep) { o.IncludeFileTimeline = true; o.IncludeUsnJournal = true; }

            var log = new StatusLog();
            var s = CollectRun.NewSession(o, log);
            Banner.Write(log, Banner.Kind.Collect);
            if (o.RequireAdministrator && !s.IsElevated)
            {
                log.Write("-RequireAdministrator was set, but this process is not elevated.", StatusLevel.Error);
                log.WriteConsole("      Re-run from an elevated prompt, or omit -RequireAdministrator to collect with standard-user coverage.", ConsoleColor.Red);
                return 1;
            }
            if (defaultOutput && !OutputFolder.Prepare(o.OutputPath, log)) return 1;
            if (!s.IsElevated)
            {
                log.WriteConsole("  [!] Standard-user coverage (not Administrator).", ConsoleColor.Yellow);
                log.WriteConsole("      Still collected: this user's processes, readable network state,", ConsoleColor.Yellow);
                log.WriteConsole("      HKCU persistence, profile files, and any logs the token can read.", ConsoleColor.Yellow);
                log.WriteConsole("      Skipped: Security log, Prefetch copies, Amcache, SRUM, VSS, auditpol/secedit, other users.", ConsoleColor.Yellow);
                log.WriteConsole("");
            }

            CollectResult r;
            try { r = CollectRun.Run(s); }
            catch (Exception ex)
            {
                // Tasks and categories record their own failures; this is the output path or package writing failing.
                log.Write("Collection stopped: " + ex.Message, StatusLevel.Error);
                if (s.CaseRoot != null) log.Write("Partial case folder (not hashed): " + s.CaseRoot, StatusLevel.Warn);
                return 1;
            }
            Summary(log, r);
            return 0;
        }

        static void Summary(StatusLog log, CollectResult r)
        {
            var s = r.Session;
            int Sev(string sev) => s.Findings.Count(f => f.Severity == sev);
            log.WriteConsole("");
            log.WriteConsole("  ============================================================", ConsoleColor.Cyan);
            log.WriteConsole("   COLLECTION COMPLETE", ConsoleColor.Cyan);
            log.WriteConsole("  ============================================================", ConsoleColor.Cyan);
            log.WriteConsole($"   Artifacts collected : {r.ArtifactCount} files across {CaseCategories.All.Count} categories", ConsoleColor.White);
            log.WriteConsole($"   Collection errors   : {s.Errors.Count}", ConsoleColor.White);
            log.WriteConsole($"   Observations        : {Sev("High")} high, {Sev("Medium")} medium, {Sev("Low")} low, {Sev("Info")} info", ConsoleColor.White);
            log.WriteConsole("   Duration            : " + Math.Round((DateTime.UtcNow - s.StartTimeUtc).TotalMinutes, 1).ToString(CultureInfo.InvariantCulture) + " min", ConsoleColor.White);
            log.WriteConsole("");
            log.WriteConsole("   Case folder : " + r.CaseRoot, ConsoleColor.White);
            if (r.ReportPath.Length > 0) log.WriteConsole("   Report      : " + r.ReportPath, ConsoleColor.White);
            if (r.ZipPath != null)
            {
                var mb = Math.Round(new FileInfo(r.ZipPath).Length / 1048576.0, 2).ToString(CultureInfo.InvariantCulture);
                log.WriteConsole($"   Package     : {r.ZipPath} ({mb} MB)", ConsoleColor.White);
                log.WriteConsole("   SHA-256     : " + r.ZipSha256, ConsoleColor.Green);
            }
            log.WriteConsole("");
            log.WriteConsole("   Open Foton_Report.html from inside the extracted folder so", ConsoleColor.DarkGray);
            log.WriteConsole("   the artifact links resolve. Findings are automated observations,", ConsoleColor.DarkGray);
            log.WriteConsole("   not conclusions - verify each one against its source artifact.", ConsoleColor.DarkGray);
            log.WriteConsole("");
        }

        static bool Int(string? v, out int n) => int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) && n >= 0;

        static int Usage(string error)
        {
            Console.Error.WriteLine(error);
            Console.Error.WriteLine("Usage: foton-collect [-OutputPath <folder>] [-CaseNumber <id>] [-Examiner <name>]");
            Console.Error.WriteLine("                     [-EventLogDays <n>] [-MaxEventsPerLog <n>] [-SkipEvtxExport] [-SkipHashing]");
            Console.Error.WriteLine("                     [-LoadUserHives] [-IncludeFileTimeline] [-IncludeUsnJournal] [-Deep] [-NoZip]");
            Console.Error.WriteLine("                     [-RequireAdministrator] [-Profile <profile.json>] [-Category <name,name>]");
            Console.Error.WriteLine("Categories: " + string.Join(", ", CollectionProfile.AllCategories));
            Console.Error.WriteLine("       foton-collect -Version");
            Console.Error.WriteLine("Default -OutputPath: " + OutputFolder.Default("Cases") + " (must be private to SYSTEM, Administrators, and this account)");
            return 1;
        }
    }
}
