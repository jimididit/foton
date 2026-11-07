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
            Console.WriteLine("  foton package <case-folder-or-zip>   open a package and verify hashes.csv");
            Console.WriteLine("  foton parse <case-folder-zip-or-file> parse copied Prefetch, LNK, jumplists, EVTX, Amcache;");
            Console.WriteLine("                                        writes analysis\\parsed_records.csv and Foton_Parse.html");
            Console.WriteLine("  foton analyze <case-folder-or-zip>   run triage heuristics; writes analysis\\findings.csv and Foton_Report.html");
            Console.WriteLine("  foton ioc <case-folder-or-zip> <ioc-file>");
            Console.WriteLine("                                        match an IOC list (.txt sha256:/path:/text:, .csv, .json);");
            Console.WriteLine("                                        writes analysis\\ioc_matches.csv");
            Console.WriteLine("  foton compare <reference> <difference> [-NoCsv] [-NoHtml] [-OutputPath <html>]");
            Console.WriteLine("                                        diff two baselines (baseline.json or package folder);");
            Console.WriteLine("                                        writes baseline_diff.csv and Foton_BaselineCompare.html");
            Console.WriteLine("                                        beside the difference baseline");
            Console.WriteLine();
            Console.WriteLine("Compose, tool install, and carve are not implemented in this v2 pre-release.");
            Console.WriteLine("For casework use Foton 1.38.x (the Foton-Workstation_v1.38.1.zip module) from https://github.com/jimididit/foton/releases.");
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
            finally { p.DeleteExtraction(); }
        }

        static int Report(StatusLog log, FotonPackage p)
        {
            log.Write($"Loaded package {p.CaseRoot} ({p.Artifacts.Count} artifacts, {p.Manifest.Count} manifest rows, {p.Kind})", StatusLevel.Good);
            if (p.Kind == PackageKind.Zip)
                log.Write("ZIP verified from a temporary extraction that is removed afterwards; chain parse/compose/analyze on an extracted folder.", StatusLevel.Info);
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
            log.Write($"hashes.csv: {v.Matched} matched, {v.Mismatched.Count} changed, {v.Missing.Count} missing, {v.Unreadable.Count} unreadable, {v.Unlisted.Count} not listed",
                v.Intact ? StatusLevel.Good : StatusLevel.Warn);
            foreach (var f in v.Mismatched.Take(20)) log.Write("Changed since hashing: " + f, StatusLevel.Warn);
            foreach (var f in v.Missing.Take(20)) log.Write("Listed but missing: " + f, StatusLevel.Warn);
            foreach (var f in v.Unreadable.Take(20)) log.Write("Could not read: " + f, StatusLevel.Warn);
            if (v.Unlisted.Count > 0)
                log.Write("Files not in hashes.csv are expected for workstation outputs written after collection (analysis\\, reports); they are not part of the hashed record.", StatusLevel.Info);
            if (p.Manifest.Count > 0 && v.Mismatched.Any(f => f.EndsWith(@"00_Collection\collection.log", StringComparison.OrdinalIgnoreCase)))
                log.Write("collection.log differs from its hash: Foton 1.38.x appended status lines after hashing, so this alone is expected for 1.38.x packages.", StatusLevel.Info);
            return v.Intact ? 0 : 2;
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
            log.Write("Findings: " + (run.FindingsPath ?? run.BesideZipPath), StatusLevel.Good);
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

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
