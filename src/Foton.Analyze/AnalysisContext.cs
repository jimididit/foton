using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Analyze
{
    /// <summary>
    /// What one analysis run sees: the loaded package, its manifest, the pattern lists it was given, and the
    /// findings it has produced so far (in rule order, which is findings.csv order).
    /// </summary>
    public sealed class AnalysisContext
    {
        public AnalysisContext(PackageData data, IReadOnlyList<Dictionary<string, string?>> manifest, string? caseRoot,
            IReadOnlyList<string> suspiciousPatterns, IReadOnlyList<string> userWritablePatterns)
        {
            Data = data;
            Manifest = manifest;
            CaseRoot = caseRoot;
            SuspiciousPatterns = suspiciousPatterns;
            UserWritable = userWritablePatterns.Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)).ToList();
        }

        public PackageData Data { get; }
        public IReadOnlyList<Dictionary<string, string?>> Manifest { get; }
        public string? CaseRoot { get; }
        /// <summary>Empty on the endpoint, where the list is not shipped; the pattern-gap finding says so.</summary>
        public IReadOnlyList<string> SuspiciousPatterns { get; }
        internal IReadOnlyList<Regex> UserWritable { get; }
        /// <summary>Event lookback quoted in observations (Initialize-FotonSession default).</summary>
        public int EventLogDays { get; set; } = 14;
        public List<Finding> Findings { get; } = new List<Finding>();

        /// <summary>A task's manifest Status (Success, NoData, NotSelected, SkippedNotElevated, ...); null when the manifest lacks it.</summary>
        internal string? TaskStatus(string task)
        {
            foreach (var m in Manifest)
                if (m.TryGetValue("Task", out var t) && string.Equals(t, task, StringComparison.OrdinalIgnoreCase))
                    return m.TryGetValue("Status", out var s) ? s : null;
            return null;
        }

        static readonly Regex SentinelStatus = new Regex(@"^\s*Status:\s*(\w+)|Status:\s*(\w+)\.?\s*$", RegexOptions.CultureInvariant);

        /// <summary>
        /// Whether a task ran, from its manifest row, else its artifact (a Foton/WinFoton sentinel names its status in its
        /// first lines; any other content means it ran). Null when neither exists, so the caller decides what an unknown means.
        /// </summary>
        internal string? TaskStatusFromPackage(string task, string category, string format)
        {
            var status = TaskStatus(task);
            if (status != null || string.IsNullOrEmpty(CaseRoot)) return status;
            var path = System.IO.Path.Combine(new[] { CaseRoot! }.Concat(Artifact(category, task, format).Split('/')).ToArray());
            try
            {
                if (!System.IO.File.Exists(path)) return null;
                var head = TextFile.ReadLines(path).Take(2).ToArray();
                if (head.Length == 0 || !Regex.IsMatch(head[0], "^(Win)?Foton:")) return Foton.Core.TaskStatus.Success;
                foreach (var line in head)
                {
                    var m = SentinelStatus.Match(line);
                    if (m.Success) return m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                }
                return null;
            }
            catch (Exception ex) when (ex is System.IO.IOException || ex is UnauthorizedAccessException) { return null; }
        }

        string? _collectorSha256;
        bool _collectorRead;
        /// <summary>The collector's own SHA-256 from chain_of_custody.txt (null when not recorded).</summary>
        internal string? CollectorSha256
        {
            get
            {
                if (!_collectorRead) { _collectorSha256 = ChainOfCustody.ReadHeader(CaseRoot).ExecutableSha256; _collectorRead = true; }
                return _collectorSha256;
            }
        }

        /// <summary>
        /// A row describing the collector itself (its process or its file), matched by the exact SHA-256 custody recorded:
        /// an unsigned foton-collect.exe run from Downloads is the tool, not an observation about the host.
        /// </summary>
        internal bool IsCollector(object? row) =>
            CollectorSha256 != null && CollectorSha256.Length == 64 && string.Equals(Ps.Str(Ps.Get(row, "SHA256")), CollectorSha256, StringComparison.OrdinalIgnoreCase);

        /// <summary>Add-FotonFinding. Tier is evidentiary strength (1 fact, 2 inference, 3 hypothesis), not urgency.</summary>
        public void Add(string severity, string category, int tier, string title, string observation,
            string why = "", string artifact = "", string next = "")
        {
            Findings.Add(new Finding
            {
                Severity = severity, Category = category, Title = title, Observation = observation,
                Tier = tier, WhyItMatters = why, Artifact = artifact, NextStep = next,
            });
        }

        /// <summary>Get-FotonArtifactPath: package-relative path with forward slashes.</summary>
        public static string Artifact(string category, string name, string format)
        {
            string folder = "";
            foreach (var kv in CaseCategories.All) if (kv.Key == category) folder = kv.Value;
            return folder + "/" + name + "." + format;
        }

        /// <summary>Test-FotonUserWritablePath: a path matching a location where system binaries rarely live. A lead, not proof.</summary>
        public bool UserWritablePath(object? path)
        {
            var s = Ps.Str(path);
            if (string.IsNullOrWhiteSpace(s)) return false;
            return UserWritable.Any(r => r.IsMatch(s));
        }

        /// <summary>Test-FotonSuspiciousCommand: matched pattern names joined ", ", or null.</summary>
        public string? SuspiciousCommand(object? text) => Patterns.SuspiciousHits(Ps.Str(text), SuspiciousPatterns);

        /// <summary>
        /// Resolve-FotonSuspiciousHits: hits a pre-1.10.0 package stored, else computed from the raw text column.
        /// Empty when no pattern list is loaded (the caller-side gap finding covers that).
        /// </summary>
        public string ResolveHits(PsRow row, string storedProperty, string textProperty)
        {
            var stored = row.Has(storedProperty) ? Ps.Str(row[storedProperty]) : "";
            if (stored.Trim().Length > 0) return stored;
            var text = row.Has(textProperty) ? Ps.Str(row[textProperty]) : "";
            if (text.Trim().Length == 0) return "";
            return SuspiciousCommand(text) ?? "";
        }
    }
}
