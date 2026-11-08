using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Analyze.Rules;
using Foton.Core;
using Foton.Package;
using static Foton.Analyze.Ps;

namespace Foton.Analyze
{
    public sealed class AnalysisRun
    {
        public List<Finding> Findings { get; internal set; } = new List<Finding>();
        public string? FindingsPath { get; internal set; }
        public string? BesideZipPath { get; internal set; }
        public string? ReportPath { get; internal set; }
    }

    public sealed class IocRun
    {
        public List<IocHit> Hits { get; internal set; } = new List<IocHit>();
        public string? HitsPath { get; internal set; }
    }

    /// <summary>
    /// Invoke-FotonAnalysis: triage heuristics over an already-collected package. Never acquires live state;
    /// identical package and pattern lists in, identical findings out. Findings are observations with a tier
    /// (fact, inference, hypothesis) and a benign explanation, never a compromise verdict.
    /// </summary>
    public static class Analyzer
    {
        /// <summary>Runs every rule group in the 1.38.x order (that order is findings.csv row order).</summary>
        public static void Run(AnalysisContext c)
        {
            Guard(c, "Host and collection", () => PostureRules.Host(c));
            Guard(c, "Defender", () => PostureRules.Defender(c));
            Guard(c, "Hardening", () => PostureRules.Hardening(c));
            Guard(c, "Firewall and RDP", () => PostureRules.FirewallRdp(c));
            Guard(c, "Accounts", () => UserProcessRules.Accounts(c));
            Guard(c, "Processes", () => UserProcessRules.Processes(c));

            var svcIndex = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            var hostSys32 = "";
            Guard(c, "Service index", () =>
            {
                svcIndex = EventHelpers.ServiceIndex(c.Data["services"]);
                var os = c.Data["os_info"];
                hostSys32 = os is PsRow osRow && osRow.Has("SystemDirectory") ? Str(osRow["SystemDirectory"]) : "";
            });

            Guard(c, "Persistence", () => PersistenceRules.Persistence(c));
            Guard(c, "Network", () => PersistenceRules.Network(c));
            Guard(c, "Event logs", () => EventLogRules.Run(c, svcIndex, hostSys32));
            Guard(c, "Software and filesystem", () => HostArtifactRules.SoftwareFilesystem(c));
            Guard(c, "Visibility gaps", () => HostArtifactRules.VisibilityGaps(c));
            Guard(c, "Workstation outputs", () => OfflineInputRules.Run(c, svcIndex, hostSys32));

            // Absence is not evidence: without the suspicious-command list every rule that needs it is inert.
            if (c.SuspiciousPatterns.Count == 0)
                c.Add("Info", "Methodology", 1, "Suspicious-command pattern matching did not run",
                    "No suspicious-command pattern list was loaded in this session, so process command lines, PowerShell console history, autostart values, and scheduled task actions were not matched against high-risk patterns. Any other finding in this report is unaffected.",
                    "This is a visibility gap, not a negative result: the absence of pattern findings here says nothing about whether such commands ran. The endpoint collector intentionally ships without the pattern list because embedding it causes antivirus to block the collector at load.",
                    "src/Private/Patterns/SuspiciousCommandPatterns.txt",
                    "Re-run Invoke-FotonAnalysis against this package from the Foton module on an analyst workstation, where the pattern list loads and these rules evaluate.");
        }

        /// <summary>
        /// One rule group that stops on malformed package data is a stated gap, never a lost run: the other
        /// groups still evaluate (1.38.x aborted the whole analysis).
        /// </summary>
        internal static void Guard(AnalysisContext c, string group, Action rules)
        {
            try { rules(); }
            catch (Exception ex)
            {
                c.Add("Info", "Methodology", 1, "An analysis rule group stopped on unexpected package data",
                    F("The {0} rules stopped and produced no further findings: {1}: {2}", group, ex.GetType().Name, TextFile.OneLine(ex.Message)),
                    "This is a visibility gap in the analysis, not a negative result: findings the stopped rules would have produced are missing from this report. Other rule groups ran normally.",
                    "",
                    "Inspect the artifacts that rule group reads for malformed or unexpected values, and re-run analyze after correcting or removing them.");
            }
        }

        /// <summary>
        /// Loads a package (folder or ZIP), analyzes it, and writes analysis\findings.csv (beside a ZIP:
        /// &lt;name&gt;_findings.csv). Never rewrites 00_Collection\hashes.csv.
        /// </summary>
        public static AnalysisRun RunPackage(string path, StatusLog log, IReadOnlyList<string> suspiciousPatterns, string? reportVersion = null)
        {
            var pkg = FotonPackage.Open(path);
            try
            {
                log.Write($"Loaded package {pkg.CaseRoot} ({pkg.Artifacts.Count} cached artifact keys)", StatusLevel.Good);
                var ctx = new AnalysisContext(PackageData.From(pkg), pkg.Manifest, pkg.CaseRoot, suspiciousPatterns, PatternLists.UserWritable);
                log.Write("Evaluating collected artifacts against triage heuristics", StatusLevel.Step);
                Run(ctx);
                log.Write($"Findings generated: {ctx.Findings.Count}", StatusLevel.Good);

                var run = new AnalysisRun { Findings = ctx.Findings };
                var root = pkg.CaseRoot;
                var extras = new[] { Path.Combine(root, "analysis", "parsed_records.csv"), Path.Combine(root, "analysis", "baseline_diff.csv"), Path.Combine(root, "analysis", "external") };
                if (File.Exists(Path.Combine(root, CaseTree.CollectionFolder, "findings.csv")) && !extras.Any(p => File.Exists(p) || Directory.Exists(p)))
                    log.Write(@"These heuristics already ran on the endpoint during Collect (00_Collection\findings.csv), so this run reproduces that report rather than adding detection. New findings come from parse, compose, IOC matching, or a baseline compare - then re-run analyze.", StatusLevel.Warn);

                if (pkg.Kind == PackageKind.Zip)
                {
                    // The case root is a temporary extraction the operator never sees.
                    run.BesideZipPath = BesideZip(pkg, "_findings.csv");
                    Csv.Write(run.BesideZipPath, ctx.Findings);
                }
                else
                {
                    var dir = Path.Combine(root, "analysis");
                    Directory.CreateDirectory(dir);
                    run.FindingsPath = Path.Combine(dir, "findings.csv");
                    // Written even with zero findings, so an earlier run's file is never left looking current.
                    Csv.Write(run.FindingsPath, ctx.Findings);
                }

                // Foton_Report.html in the case root so relative artifact links resolve; beside a ZIP otherwise.
                log.Write("Building HTML overview report", StatusLevel.Step);
                run.ReportPath = pkg.Kind == PackageKind.Zip ? BesideZip(pkg, "_Report.html") : Path.Combine(root, TriageReport.FileName);
                TriageReport.Write(new TriageReportInput
                {
                    Data = ctx.Data, Findings = ctx.Findings, Manifest = pkg.Manifest, Errors = pkg.Errors, CaseRoot = root,
                    CollectedUtc = pkg.StartTimeUtc, Version = reportVersion ?? FotonVersion.Product, EventLogDays = ctx.EventLogDays,
                    FromZip = pkg.Kind == PackageKind.Zip,
                }, run.ReportPath);
                log.Write("Report written: " + run.ReportPath, StatusLevel.Good);
                return run;
            }
            finally { pkg.DeleteExtraction(); }
        }

        /// <summary>
        /// End-of-collection analysis on the endpoint: the rules run over the case folder Collect just wrote (not over
        /// live objects), so re-running analyze on the untouched package on a workstation gives the same findings. The
        /// suspicious-command list is not shipped to endpoints; the pattern-gap finding says so. Writes
        /// Foton_Report.html in the case root and returns the findings for 00_Collection\findings.csv.
        /// </summary>
        public static List<Finding> RunCollected(string caseRoot, DateTime collectedUtc, int eventLogDays, StatusLog log)
        {
            var pkg = FotonPackage.Open(caseRoot);
            var ctx = new AnalysisContext(PackageData.From(pkg), pkg.Manifest, pkg.CaseRoot, new string[0], PatternLists.UserWritable)
            {
                EventLogDays = eventLogDays,
            };
            log.Write("Evaluating collected artifacts against triage heuristics", StatusLevel.Step);
            Run(ctx);
            log.Write($"Findings generated: {ctx.Findings.Count}", StatusLevel.Good);
            log.Write("Building HTML overview report", StatusLevel.Step);
            var report = Path.Combine(pkg.CaseRoot, TriageReport.FileName);
            TriageReport.Write(new TriageReportInput
            {
                Data = ctx.Data, Findings = ctx.Findings, Manifest = pkg.Manifest, Errors = pkg.Errors, CaseRoot = pkg.CaseRoot,
                CollectedUtc = collectedUtc, Version = FotonVersion.Product, EventLogDays = eventLogDays,
            }, report);
            log.Write("Report written: " + report, StatusLevel.Good);
            return ctx.Findings;
        }

        /// <summary>
        /// Invoke-FotonIocMatch over a package. Hits are written to analysis\ioc_matches.csv (beside a ZIP:
        /// &lt;name&gt;_ioc_matches.csv); 1.38.x only printed them.
        /// </summary>
        public static IocRun RunIoc(string packagePath, string iocPath, StatusLog log)
        {
            var iocs = IocMatcher.Load(iocPath);
            var pkg = FotonPackage.Open(packagePath);
            try
            {
                var data = PackageData.From(pkg);
                var run = new IocRun { Hits = IocMatcher.Match(data, data.Names.ToList(), iocs) };
                log.Write($"IOC matches: {run.Hits.Count} ({iocs.Count} indicator(s))", StatusLevel.Good);
                if (pkg.Kind == PackageKind.Zip)
                    run.HitsPath = BesideZip(pkg, "_ioc_matches.csv");
                else
                {
                    Directory.CreateDirectory(Path.Combine(pkg.CaseRoot, "analysis"));
                    run.HitsPath = Path.Combine(pkg.CaseRoot, "analysis", "ioc_matches.csv");
                }
                Csv.Write(run.HitsPath, run.Hits);
                return run;
            }
            finally { pkg.DeleteExtraction(); }
        }

        static string BesideZip(FotonPackage pkg, string suffix) =>
            Path.Combine(Path.GetDirectoryName(Path.GetFullPath(pkg.SourcePath)) ?? "", Path.GetFileNameWithoutExtension(pkg.SourcePath) + suffix);
    }
}
