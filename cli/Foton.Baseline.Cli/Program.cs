using System;
using System.IO;
using System.Linq;
using Foton.Baseline.Capture;
using Foton.Core;
using Foton.Report;
using Foton.Win;

namespace Foton.Baseline.Cli
{
    /// <summary>
    /// foton-baseline.exe: capture a normalized snapshot of stable host configuration (New-FotonBaseline).
    /// Same switches as the 1.38.x flat script. Store the result off-host; compare on a workstation.
    /// </summary>
    static class Program
    {
        static int Main(string[] args)
        {
            string? path = null, outputPath = null;
            bool noZip = false, noHtml = false, requireAdmin = false;
            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i];
                bool Is(string name) => string.Equals(a, name, StringComparison.OrdinalIgnoreCase);
                if (Is("-Version") || Is("--version") || Is("version"))
                {
                    foreach (var line in FotonVersion.Describe("foton-baseline")) Console.WriteLine(line);
                    return 0;
                }
                if ((Is("-Path") || Is("-OutputPath")) && i + 1 < args.Length)
                {
                    if (Is("-Path")) path = args[++i]; else outputPath = args[++i];
                    continue;
                }
                if (Is("-NoZip")) { noZip = true; continue; }
                if (Is("-NoHtml")) { noHtml = true; continue; }
                if (Is("-RequireAdministrator")) { requireAdmin = true; continue; }
                return Usage("Unknown argument: " + a);
            }
            if (path != null && outputPath != null) return Usage("Use -Path (JSON only) or -OutputPath (package folder), not both.");

            var elevated = HostInfo.IsElevated();
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Baseline);
            if (requireAdmin && !elevated)
            {
                log.Write("-RequireAdministrator was set, but this process is not elevated.", StatusLevel.Error);
                return 1;
            }
            if (!elevated)
                log.Write("Standard-user capture: some providers see less (loaded hives only, WMI subscriptions, other users' files). Gaps are recorded, not hidden.", StatusLevel.Warn);

            var session = new FotonSession(new SessionOptions(), DateTime.UtcNow, Environment.MachineName, HostInfo.Account(), elevated, log);
            if (path != null)
            {
                var r = BaselineCapture.Capture(session);
                var json = BaselineCapture.WriteJson(r, path);
                var html = noHtml ? null : SnapshotHtml(log, json);
                Summary(log, r, json, null, html, null);
                return 0;
            }

            var parent = outputPath ?? OutputFolder.Default("Baselines");
            if (outputPath == null && !OutputFolder.Prepare(parent, log)) return 1;
            BaselineLayout.Create(session, parent);
            log.Write("Baseline folder: " + session.CaseRoot, StatusLevel.Good);
            var result = BaselineCapture.Capture(session);
            foreach (var c in result.Coverage)
                log.Write($"{c.RecordType} ({c.Count} records)" + (c.Status == "Success" ? "" : " - " + c.Status + ": " + c.Error), c.Status == "Success" ? StatusLevel.Good : StatusLevel.Warn);
            string? snapshot = null;
            // Written before hashing, so the HTML preview is part of the hashed package (1.38.x order).
            var pkg = BaselineCapture.WritePackage(session, result, zip: !noZip,
                beforeHashing: root => { if (!noHtml) snapshot = SnapshotHtml(log, Path.Combine(root, "baseline.json")); });
            Summary(log, result, pkg.JsonPath, pkg.Root, snapshot, pkg.ZipPath);
            if (snapshot != null) log.WriteConsole("   Open Foton_Baseline.html from inside the folder. Compare uses baseline.json.", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>The capped HTML preview beside the JSON. A report failure never loses the capture.</summary>
        static string? SnapshotHtml(StatusLog log, string json)
        {
            try
            {
                var html = BaselineSnapshotReport.Write(json);
                log.Write("Baseline snapshot report: " + html, StatusLevel.Good);
                return html;
            }
            catch (Exception ex)
            {
                // Runs inside package writing, before hashing: any failure here must leave a hashed package behind.
                log.Write("Baseline snapshot report not written: " + ex.Message, StatusLevel.Warn);
                return null;
            }
        }

        static void Summary(StatusLog log, CaptureResult r, string json, string? root, string? html, string? zip)
        {
            int total = r.Coverage.Sum(c => c.Count);
            int incomplete = r.Coverage.Count(c => c.Status != "Success");
            log.WriteConsole("");
            log.WriteConsole($"   Records         : {total} across {r.Coverage.Count} record types" + (incomplete > 0 ? $" ({incomplete} provider(s) incomplete; see coverage)" : ""), ConsoleColor.White);
            log.WriteConsole("   PayloadSha256   : " + r.Document.Header.PayloadSha256, ConsoleColor.White);
            if (root != null) log.WriteConsole("   Baseline folder : " + root, ConsoleColor.White);
            log.WriteConsole("   Snapshot JSON   : " + json, ConsoleColor.White);
            if (html != null) log.WriteConsole("   Snapshot HTML   : " + html, ConsoleColor.White);
            if (zip != null) log.WriteConsole("   Package         : " + zip, ConsoleColor.White);
            log.WriteConsole("   A baseline taken after an incident is a picture of that state. Store it off-host.", ConsoleColor.DarkGray);
            log.WriteConsole("");
        }

        static int Usage(string error)
        {
            Console.Error.WriteLine(error);
            Console.Error.WriteLine("Usage: foton-baseline [-OutputPath <folder>] [-NoZip] [-NoHtml] [-RequireAdministrator]");
            Console.Error.WriteLine("       foton-baseline -Path <snapshot.json>");
            Console.Error.WriteLine("       foton-baseline -Version");
            Console.Error.WriteLine("Default -OutputPath: " + OutputFolder.Default("Baselines") + " (created private to SYSTEM, Administrators, and this account)");
            return 1;
        }
    }
}
