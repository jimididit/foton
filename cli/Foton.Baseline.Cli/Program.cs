using System;
using System.IO;
using System.Linq;
using Foton.Baseline.Capture;
using Foton.Core;
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
                Summary(log, r, json, null, null);
                return 0;
            }

            var parent = outputPath ?? DefaultOutputPath();
            BaselineLayout.Create(session, parent);
            log.Write("Baseline folder: " + session.CaseRoot, StatusLevel.Good);
            var result = BaselineCapture.Capture(session);
            foreach (var c in result.Coverage)
                log.Write($"{c.RecordType} ({c.Count} records)" + (c.Status == "Success" ? "" : " - " + c.Status + ": " + c.Error), c.Status == "Success" ? StatusLevel.Good : StatusLevel.Warn);
            if (!noHtml) log.Write("Foton_Baseline.html is not produced by this v2 pre-release; compare and report on a workstation.", StatusLevel.Info);
            var pkg = BaselineCapture.WritePackage(session, result, zip: !noZip);
            Summary(log, result, pkg.JsonPath, pkg.Root, pkg.ZipPath);
            return 0;
        }

        /// <summary>
        /// The Desktop, as in 1.38.x. RMM sessions running as SYSTEM or a service account may have no Desktop folder,
        /// so fall back to Desktop under the profile (created on write), then the working directory.
        /// </summary>
        static string DefaultOutputPath()
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (!string.IsNullOrEmpty(desktop)) return desktop;
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return string.IsNullOrEmpty(profile) ? Directory.GetCurrentDirectory() : Path.Combine(profile, "Desktop");
        }

        static void Summary(StatusLog log, CaptureResult r, string json, string? root, string? zip)
        {
            int total = r.Coverage.Sum(c => c.Count);
            int failed = r.Coverage.Count(c => c.Status != "Success");
            log.WriteConsole("");
            log.WriteConsole($"   Records         : {total} across {r.Coverage.Count} record types" + (failed > 0 ? $" ({failed} provider(s) failed)" : ""), ConsoleColor.White);
            log.WriteConsole("   PayloadSha256   : " + r.Document.Header.PayloadSha256, ConsoleColor.White);
            if (root != null) log.WriteConsole("   Baseline folder : " + root, ConsoleColor.White);
            log.WriteConsole("   Snapshot JSON   : " + json, ConsoleColor.White);
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
            return 1;
        }
    }
}
