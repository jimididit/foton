using System;
using System.Collections.Generic;
using System.Linq;
using Foton.Analyze;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    public sealed class CollectResult
    {
        public FotonSession Session { get; internal set; } = null!;
        public string CaseRoot { get; internal set; } = "";
        public string ReportPath { get; internal set; } = "";
        public int ArtifactCount { get; internal set; }
        public string? ZipPath { get; internal set; }
        public string? ZipSha256 { get; internal set; }
    }

    /// <summary>
    /// Live collect, analyze, report, and hashed package (Invoke-FotonTriage). Read-only against the host apart from
    /// the output package and, with -LoadUserHives, a reg load/unload of offline user hives. Nothing is fatal: a task
    /// or category that fails is recorded in the manifest and errors, and the run continues.
    /// </summary>
    public static class CollectRun
    {
        /// <param name="only">Category keys to run (parity probe); every category when null.</param>
        public static CollectResult Run(FotonSession s, IReadOnlyCollection<string>? only = null)
        {
            var o = s.Options;
            var root = CaseLayout.Create(s, o.OutputPath);
            s.Status.Write("Case folder: " + root, StatusLevel.Good);
            s.Status.Write($"Examiner: {TextFile.OneLine(o.Examiner)} | Case: {(string.IsNullOrWhiteSpace(o.CaseNumber) ? "not supplied" : TextFile.OneLine(o.CaseNumber))} | Coverage: {Coverage.Profile(s.IsElevated)}", StatusLevel.Info);
            // From here on nothing ends the run: only creating the case folder above can.
            Guard(s, "chain_of_custody", () => ChainOfCustody.Write(s, HostFacts.Custody()));

            // Every mounted hive is in this list the moment it loads, so the finally block unloads it whatever fails.
            var mounted = new List<string>();
            try
            {
                if (o.LoadUserHives)
                {
                    if (!s.IsElevated) s.Status.Write("LoadUserHives ignored: mounting NTUSER.DAT requires elevation", StatusLevel.Warn);
                    else
                    {
                        s.Status.Write("Mounting offline user registry hives", StatusLevel.Step);
                        s.LoadUserHivesActive = true;
                        Guard(s, "LoadUserHives", () => UserHives.Load(s, mounted));
                        s.Status.Write($"Mounted {mounted.Count} offline hive(s)", StatusLevel.Info);
                    }
                }
                // Tasks catch their own failures; a guard catches a category that breaks between tasks.
                foreach (var c in Categories.InOrder.Where(c => only == null || only.Contains(c.Key, StringComparer.OrdinalIgnoreCase)))
                    Guard(s, c.Key, () => c.Run(s));
                Guard(s, "collection_coverage", () => Coverage.Write(s));
            }
            finally
            {
                if (mounted.Count > 0)
                    Guard(s, "UnloadUserHives", () =>
                    {
                        s.Status.Write("Unmounting offline user registry hives", StatusLevel.Step);
                        UserHives.Unload(s, mounted);
                    });
            }

            // The manifest and errors are on disk before analysis, which reads the case the way a workstation would.
            Guard(s, "collection_manifest", () => PackageFiles.WriteManifestFiles(s));
            var result = new CollectResult { Session = s, CaseRoot = root };
            Guard(s, "analysis", () =>
            {
                s.Findings.AddRange(Analyzer.RunCollected(root, s.StartTimeUtc, o.EventLogDays, s.Status));
                result.ReportPath = System.IO.Path.Combine(root, TriageReport.FileName);
            });
            Guard(s, "collection_manifest", () => PackageFiles.WriteManifestFiles(s));
            Guard(s, "hashes", () => result.ArtifactCount = PackageFiles.WriteArtifactHashes(s));

            if (!o.NoZip)
            {
                Guard(s, "package_zip", () => result.ZipPath = PackageFiles.CompressCase(s));
                if (result.ZipPath != null) Guard(s, "package_hash", () => result.ZipSha256 = PackageFiles.WritePackageHashRecord(s, result.ZipPath));
            }
            return result;
        }

        /// <summary>Nothing is fatal: a step that throws is recorded in collection_errors.csv and the run continues.</summary>
        static void Guard(FotonSession s, string step, Action run)
        {
            try { run(); }
            catch (Exception ex)
            {
                s.Errors.Add(new ErrorRow { Task = step, Error = "Stopped: " + ex.Message });
                try { s.Status.Write($"{step} stopped: {ex.Message}", StatusLevel.Warn); } catch (Exception) { }
            }
        }

        /// <summary>A session for this host and token.</summary>
        public static FotonSession NewSession(SessionOptions o, StatusLog log) =>
            new FotonSession(o, DateTime.UtcNow, Environment.MachineName, HostInfo.Account(), HostInfo.IsElevated(), log);
    }
}
