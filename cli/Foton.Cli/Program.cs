using System;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Cli
{
    static class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 1 && IsVersionSwitch(args[0]))
            {
                foreach (var line in FotonVersion.Describe("foton")) Console.WriteLine(line);
                return 0;
            }
            if (args.Length == 2 && string.Equals(args[0], "package", StringComparison.OrdinalIgnoreCase))
                return PackageCommand(args[1]);
            if (args.Length == 2 && string.Equals(args[0], "parse", StringComparison.OrdinalIgnoreCase))
                return ParseCommand(args[1]);
            if (args.Length == 2 && string.Equals(args[0], "analyze", StringComparison.OrdinalIgnoreCase))
                return AnalyzeCommand(args[1]);
            if (args.Length == 3 && string.Equals(args[0], "ioc", StringComparison.OrdinalIgnoreCase))
                return IocCommand(args[1], args[2]);
            if (args.Length == 2 && string.Equals(args[0], "compose", StringComparison.OrdinalIgnoreCase))
                return ComposeCommand(args[1]);
            if (args.Length >= 2 && string.Equals(args[0], "carve", StringComparison.OrdinalIgnoreCase))
            {
                int maxBytes = Foton.Carve.Carver.DefaultMaxBytes, maxHits = Foton.Carve.Carver.DefaultMaxHits;
                for (int i = 2; i < args.Length; i++)
                {
                    if (i + 1 < args.Length && string.Equals(args[i], "-MaxBytes", StringComparison.OrdinalIgnoreCase) && int.TryParse(args[i + 1], out maxBytes) && maxBytes >= 0) i++;
                    else if (i + 1 < args.Length && string.Equals(args[i], "-MaxHits", StringComparison.OrdinalIgnoreCase) && int.TryParse(args[i + 1], out maxHits) && maxHits >= 0) i++;
                    else return Usage();
                }
                return CarveCommand(args[1], maxBytes, maxHits);
            }
            if (args.Length >= 1 && args.Length <= 4 && string.Equals(args[0], "tools", StringComparison.OrdinalIgnoreCase))
            {
                var rest = args.Skip(1).ToList();
                bool force = rest.RemoveAll(a => string.Equals(a, "-Force", StringComparison.OrdinalIgnoreCase)) > 0;
                if (rest.Count == 0 || (rest.Count == 1 && string.Equals(rest[0], "list", StringComparison.OrdinalIgnoreCase)))
                    return ToolsListCommand();
                if (rest.Count <= 2) return ToolsCommand(rest[0], rest.Count == 2 ? rest[1] : null, force);
            }
            if (args.Length >= 3 && string.Equals(args[0], "compare", StringComparison.OrdinalIgnoreCase))
            {
                bool noCsv = false, noHtml = false;
                string? html = null;
                for (int i = 3; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "-NoCsv", StringComparison.OrdinalIgnoreCase)) noCsv = true;
                    else if (string.Equals(args[i], "-NoHtml", StringComparison.OrdinalIgnoreCase)) noHtml = true;
                    else if (string.Equals(args[i], "-OutputPath", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) html = args[++i];
                    else return Usage();
                }
                return CompareCommand(args[1], args[2], noCsv, noHtml, html);
            }
            return Usage();
        }

        static int Usage()
        {
            foreach (var line in FotonVersion.Describe("foton")) Console.WriteLine(line);
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  foton -Version");
            Console.WriteLine("  package, parse, compose, analyze, and ioc extract a <zip> once to <zip name>-extracted beside it,");
            Console.WriteLine("  then reuse that folder and write their outputs there.");
            Console.WriteLine("  foton package <case-folder-or-zip>   open a package and verify hashes.csv");
            Console.WriteLine("  foton parse <case-folder-zip-or-file> parse copied Prefetch, LNK, jumplists, EVTX, Amcache;");
            Console.WriteLine("                                        writes analysis\\parsed_records.csv and Foton_Parse.html");
            Console.WriteLine("  foton analyze <case-folder-or-zip>   run triage heuristics; writes analysis\\findings.csv and Foton_Report.html");
            Console.WriteLine("  foton ioc <case-folder-or-zip> <ioc-file>");
            Console.WriteLine("                                        match an IOC list (.txt sha256:/path:/text:, .csv, .json);");
            Console.WriteLine("                                        writes analysis\\ioc_matches.csv");
            Console.WriteLine("  foton compose <case-folder-or-zip>   run EZ Tools / Hayabusa / Chainsaw on copied files;");
            Console.WriteLine("                                        writes analysis\\external\\ and external_parse_inventory.csv");
            Console.WriteLine("  foton tools                          list pinned and registered tools");
            Console.WriteLine("  foton tools <Hayabusa|Chainsaw> [-Force]");
            Console.WriteLine("                                        download and install the pinned release (hash-verified)");
            Console.WriteLine("  foton tools <Hayabusa|Chainsaw> <release.zip>");
            Console.WriteLine("                                        install from a downloaded archive (hash-verified)");
            Console.WriteLine("  foton tools <EZTools|Chainsaw|...> <folder-or-exe>");
            Console.WriteLine("                                        register an existing install in tools.json");
            Console.WriteLine("  foton compare <reference> <difference> [-NoCsv] [-NoHtml] [-OutputPath <html>]");
            Console.WriteLine("                                        diff two baselines (baseline.json or package folder);");
            Console.WriteLine("                                        writes baseline_diff.csv and Foton_BaselineCompare.html");
            Console.WriteLine("                                        beside the difference baseline");
            Console.WriteLine("  foton carve <blob> [-MaxBytes <n>] [-MaxHits <n>]");
            Console.WriteLine("                                        MZ/PE signature scan of a copied blob (Tier 3; not NTFS carving);");
            Console.WriteLine("                                        defaults 8 MiB and 50 hits");
            Console.WriteLine();
            Console.WriteLine("Operator guide: https://github.com/jimididit/foton/blob/main/docs/USAGE.md");
            return 1;
        }

        /// <summary>Exit 0 when every listed hash matches, 2 when any listed file changed or is missing, 1 on open failure.</summary>
        static int PackageCommand(string path)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            FotonPackage p;
            try { p = FotonPackage.Open(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                || ex is ArgumentException || ex is NotSupportedException)
            {
                log.Write("Cannot open package: " + ex.Message, StatusLevel.Error);
                return 1;
            }

            try { return Report(log, p); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                log.Write("Cannot verify package: " + ex.Message, StatusLevel.Error);
                return 1;
            }
        }

        static int Report(StatusLog log, FotonPackage p)
        {
            if (p.ZipNote != null) log.Write(p.ZipNote, StatusLevel.Info);
            log.Write($"Loaded package {p.CaseRoot} ({p.Artifacts.Count} artifacts, {p.Manifest.Count} manifest rows, {p.Kind})", StatusLevel.Good);
            if (p.NestedDuplicate != null)
                log.Write($"This package contains a full copy of itself at {Path.GetFileName(p.NestedDuplicate)}. It is skipped so artifacts are not counted twice.", StatusLevel.Warn);
            foreach (var other in p.OtherNestedCases)
                log.Write($"This package contains another case folder, {Path.GetFileName(other)}, that is not a copy of it. Its files are not loaded as this case's artifacts; review it separately.", StatusLevel.Warn);

            var v = p.VerifyHashes();
            if (!v.HashesFilePresent)
            {
                log.Write("No 00_Collection\\hashes.csv: integrity cannot be verified for this package.", StatusLevel.Warn);
                return 2;
            }
            var where = p.Kind == PackageKind.Zip ? "hashes.csv (checked inside the ZIP)" : "hashes.csv";
            log.Write($"{where}: {v.Matched} matched, {v.Mismatched.Count} changed, {v.Missing.Count} missing, {v.Unreadable.Count} unreadable, {v.Unlisted.Count} not listed",
                v.Intact ? StatusLevel.Good : StatusLevel.Warn);
            foreach (var f in v.Mismatched.Take(20)) log.Write("Changed since hashing: " + f, StatusLevel.Warn);
            foreach (var f in v.Missing.Take(20)) log.Write("Listed but missing: " + f, StatusLevel.Warn);
            foreach (var f in v.Unreadable.Take(20)) log.Write("Could not read: " + f, StatusLevel.Warn);
            if (v.NotExtracted.Count > 0)
                log.Write($"{v.NotExtracted.Count} listed file(s) were not extracted (path too long), so their hashes were not checked.", StatusLevel.Warn);
            if (v.Unlisted.Count > 0)
                log.Write("Files not in hashes.csv are expected for workstation outputs written after collection (analysis\\, reports); they are not part of the hashed record.", StatusLevel.Info);
            if (p.Manifest.Count > 0 && v.Mismatched.Any(f => f.EndsWith(@"00_Collection\collection.log", StringComparison.OrdinalIgnoreCase)))
                log.Write("collection.log differs from its hash: Foton 1.38.x appended status lines after hashing, so this alone is expected for 1.38.x packages.", StatusLevel.Info);
            var extractionMatches = ExtractionMatches(log, p);
            return v.Intact && extractionMatches ? 0 : 2;
        }

        /// <summary>
        /// For a ZIP, also checks the extraction that parse, compose, and analyze read. Foton_Report.html is left out:
        /// analyze rewrites it there by design.
        /// </summary>
        static bool ExtractionMatches(StatusLog log, FotonPackage p)
        {
            if (p.Kind != PackageKind.Zip) return true;
            if (p.NotExtracted.Count > 0)
                log.Write($"{p.NotExtracted.Count} file(s) in the ZIP have paths too long to extract under {p.ExtractedTo} (packages from Foton 2.2.0 and earlier can hold long shortcut names). Their hashes were checked in the ZIP, but parse, compose, and analyze do not see them. Move the ZIP to a folder with a shorter path, delete {Path.GetFileName(p.ExtractedTo)}, and run again.", StatusLevel.Warn);
            var e = p.VerifyExtraction();
            var drift = e.Mismatched.Concat(e.Missing).Concat(e.Unreadable)
                .Where(f => !string.Equals(f, Foton.Analyze.TriageReport.FileName, StringComparison.OrdinalIgnoreCase)).ToList();
            if (drift.Count == 0) return true;
            log.Write($"The extraction no longer matches hashes.csv for {drift.Count} file(s) that parse, compose, and analyze read. Delete {p.ExtractedTo} and run again to extract a fresh copy from the ZIP.", StatusLevel.Warn);
            foreach (var f in drift.Take(20)) log.Write("Changed in the extraction: " + f, StatusLevel.Warn);
            return false;
        }

        /// <summary>Exit 0 after a diff (changes are findings, not failures), 1 when a baseline cannot be read or compared.</summary>
        static int CompareCommand(string reference, string difference, bool noCsv, bool noHtml, string? htmlPath)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Compare);
            Foton.Baseline.Compare.CompareResult r;
            try { r = Foton.Baseline.Compare.BaselineComparer.Run(reference, difference, log, writeCsv: !noCsv); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                || ex is ArgumentException || ex is InvalidOperationException)
            {
                log.Write("Cannot compare: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            foreach (var sev in new[] { "High", "Medium", "Low", "Info" })
            {
                var n = r.Findings.Count(f => f.Severity == sev);
                if (n > 0) log.Write($"{sev}: {n}", sev == "High" ? StatusLevel.Warn : StatusLevel.Info);
            }
            foreach (var f in r.Findings.Where(x => x.Severity == "High").Take(25))
                log.Write($"{f.Title}: {f.Observation}", StatusLevel.Warn);
            if (r.DiffCsvPath != null) log.Write("Change table: " + r.DiffCsvPath, StatusLevel.Info);
            if (!noHtml)
            {
                var html = htmlPath ?? Path.Combine(Path.GetDirectoryName(BaselineDocument.ResolveJsonPath(difference))!, Foton.Baseline.Compare.BaselineCompareReport.FileName);
                try
                {
                    Foton.Baseline.Compare.BaselineCompareReport.Write(r, html);
                    log.Write("Baseline compare report: " + html, StatusLevel.Good);
                }
                catch (Exception ex)
                {
                    // The diff and baseline_diff.csv are already written; the HTML is a preview.
                    log.Write("Baseline compare report not written: " + ex.Message, StatusLevel.Warn);
                }
            }
            log.WriteConsole("     A diff records change between two snapshots. It does not show when, who, or that the host is compromised.", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>Exit 0 after a parse (unsupported rows are records, not failures), 1 when the path cannot be opened.</summary>
        static int ParseCommand(string path)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            Foton.Parse.ParseRun run;
            try { run = Foton.Parse.ParseRunner.Run(path, log); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                || ex is ArgumentException || ex is NotSupportedException)
            {
                log.Write("Cannot parse: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            if (run.CsvPath == null)
                foreach (var r in run.Records)
                    log.WriteConsole($"   {r.Format,-24} {(r.Supported ? "supported" : "unsupported"),-11} {r.Identity}", ConsoleColor.White);
            return 0;
        }

        /// <summary>Exit 0 after analysis (findings are observations, not failures), 1 when the package cannot be opened.</summary>
        static int AnalyzeCommand(string path)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            Foton.Analyze.AnalysisRun run;
            try { run = Foton.Analyze.Analyzer.RunPackage(path, log, Foton.Patterns.WorkstationPatterns.SuspiciousCommands); }
            catch (Exception ex)
            {
                // Rule groups already turn bad data into findings; anything left here is opening or writing the package.
                log.Write("Cannot analyze: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            foreach (var sev in new[] { "High", "Medium", "Low", "Info" })
            {
                var n = run.Findings.Count(f => f.Severity == sev);
                if (n > 0) log.Write($"{sev}: {n}", sev == "High" ? StatusLevel.Warn : StatusLevel.Info);
            }
            log.Write("Findings: " + run.FindingsPath, StatusLevel.Good);
            log.Write("Report: " + run.ReportPath, StatusLevel.Good);
            log.WriteConsole("     Findings are observations with a tier and a benign explanation. None is a compromise verdict.", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>Exit 0 after matching (hits are leads, not failures), 1 when the package or IOC file cannot be read.</summary>
        static int IocCommand(string package, string iocFile)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            Foton.Analyze.IocRun run;
            try { run = Foton.Analyze.Analyzer.RunIoc(package, iocFile, log); }
            catch (Exception ex)
            {
                log.Write("Cannot match IOCs: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            foreach (var h in run.Hits.Take(50))
                log.WriteConsole($"   {h.IocKind,-7} {h.IocValue}  ->  {h.Artifact}.{h.Property}: {TextFile.OneLine(h.Sample)}", ConsoleColor.White);
            if (run.Hits.Count > 50) log.WriteConsole($"   ... {run.Hits.Count - 50} more in {run.HitsPath}", ConsoleColor.DarkGray);
            log.Write("Matches: " + run.HitsPath, StatusLevel.Good);
            log.WriteConsole("     A match is a lead to verify against the cited artifact (lists match admin tools too), not a conclusion.", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>Exit 0 after compose (missing tools are coverage rows, not failures), 1 when the package cannot be used.</summary>
        static int ComposeCommand(string path)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            Foton.Tools.ComposeRun run;
            try { run = Foton.Tools.ComposeRunner.Run(path, log); }
            catch (Exception ex)
            {
                log.Write("Cannot compose: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            foreach (var r in run.Rows)
                log.WriteConsole($"   {r.Tool,-14} {(r.Version.Length > 0 ? r.Version : "-"),-12} {r.Status,-14} {(r.DestRelative.Length > 0 ? r.DestRelative : r.Note)}",
                    r.Status == "Copied" ? ConsoleColor.White : ConsoleColor.DarkGray);
            log.Write("Inventory: " + run.InventoryPath + ". Native foton parse if tools are missing.", StatusLevel.Good);
            log.WriteConsole("     Missing Hayabusa or Chainsaw: foton tools Hayabusa | Chainsaw. Existing EZ Tools folder: foton tools EZTools <dir>", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>Exit 0 after a scan (hits are Tier 3 leads, not failures), 1 when the blob cannot be read.</summary>
        static int CarveCommand(string path, int maxBytes, int maxHits)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Carve);
            Foton.Carve.CarveRun run;
            try { run = Foton.Carve.Carver.Scan(path, maxBytes, maxHits); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
            {
                log.Write("Cannot carve: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            foreach (var h in run.Hits)
                log.WriteConsole($"   {h.Offset,12}  {h.Kind,-3}  {h.WindowSha256}", ConsoleColor.White);
            log.Write($"Carve signature hits: {run.Hits.Count} (scanned {run.BytesScanned} bytes, NTFS unallocated parser not used)", StatusLevel.Good);
            if (run.Hits.Count >= maxHits) log.Write($"Stopped at the {maxHits}-hit cap; raise -MaxHits to see more.", StatusLevel.Warn);
            log.WriteConsole("     " + Foton.Carve.Carver.HitNote + " Packed installers, memory dumps, and coincidence also match; this is not evidence the file ran.", ConsoleColor.DarkGray);
            return 0;
        }

        static int ToolsListCommand()
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            foreach (var r in Foton.Tools.ToolInstaller.List(null))
                log.WriteConsole($"   {r.Name,-14} {r.Version,-16} {r.Source,-11} {r.Location}", ConsoleColor.White);
            log.WriteConsole("     Location is what compose runs (or the pinned download). Tools only on PATH are not listed.", ConsoleColor.DarkGray);
            return 0;
        }

        /// <summary>
        /// One-time workstation setup; never runs inside compose. A folder or .exe is registered, a .zip is installed
        /// against the catalog pin, and no path downloads the pinned release after a confirmation (or -Force).
        /// </summary>
        static int ToolsCommand(string name, string? path, bool force)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            try
            {
                if (path != null && !path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    log.WriteConsole("  Foton tool registration (existing install; nothing downloaded)", ConsoleColor.Cyan);
                    foreach (var r in Foton.Tools.ToolRegistry.Register(name, path, null))
                        log.WriteConsole($"   {r.Name,-14} {r.Status,-11} {r.Version,-16} {r.ExecutablePath}", ConsoleColor.White);
                    log.Write("SHA-256 values in tools.json are observed on disk, not verified against an upstream hash.", StatusLevel.Warn);
                    log.Write("PATH was not changed. Compose resolves these tools via tools.json.", StatusLevel.Good);
                    return 0;
                }

                var entry = Foton.Tools.ToolCatalog.Entry(name);
                var dest = Foton.Tools.ToolInstaller.Destination(entry, null);
                log.WriteConsole("  Foton tool install (workstation setup - not part of a case package)", ConsoleColor.Cyan);
                log.WriteConsole($"  Tool:     {entry.Name} {entry.Version}", ConsoleColor.White);
                log.WriteConsole($"  License:  {entry.License}  {entry.ProjectUrl}", ConsoleColor.White);
                log.WriteConsole($"  Source:   {path ?? entry.DownloadUrl}", ConsoleColor.White);
                log.WriteConsole($"  SHA-256:  {entry.ExpectedSha256}", ConsoleColor.White);
                log.WriteConsole($"  Dest:     {dest}", ConsoleColor.White);
                log.WriteConsole($"  Note:     {entry.Notes}", ConsoleColor.White);
                if (path == null && !force)
                {
                    Console.Write($"  Install {entry.Name} {entry.Version} into {dest}? [y/N] ");
                    var answer = Console.ReadLine();
                    if (!string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(answer?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
                    {
                        log.Write("Cancelled.", StatusLevel.Warn);
                        return 1;
                    }
                }
                Foton.Tools.ToolInstaller.Install(entry, path, null, log);
                log.Write("PATH was not changed. Compose resolves this tool via tools.json.", StatusLevel.Good);
                log.Write("Next: foton compose <case-folder>", StatusLevel.Good);
                return 0;
            }
            catch (Exception ex)
            {
                log.Write("Tool setup failed: " + ex.Message, StatusLevel.Error);
                return 1;
            }
        }

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
