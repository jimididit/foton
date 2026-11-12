using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Package;

namespace Foton.Analyze.Timeline
{
    /// <summary>One timeline row: a time from one artifact row, what that time means, and where it came from.</summary>
    public sealed class TimelineRow
    {
        public string TimeUtc { get; set; } = "";
        public string Source { get; set; } = "";
        public string Meaning { get; set; } = "";
        public string Summary { get; set; } = "";
        /// <summary>The artifact relative to the case root.</summary>
        public string Artifact { get; set; } = "";
        /// <summary>The data row in that artifact (1 is the first row after the header).</summary>
        public int Row { get; set; }
        /// <summary>Inside the collection window: the collector's own activity can appear here.</summary>
        public bool DuringCollection { get; set; }
        internal long Ticks;
    }

    /// <summary>What the timeline took from one artifact, so a missing or skipped source is visible, never silent.</summary>
    public sealed class TimelineSourceStat
    {
        public string Source { get; set; } = "";
        public string Artifact { get; set; } = "";
        public int RowsRead { get; set; }
        public int TimesUsed { get; set; }
        /// <summary>Time cells that were empty, "(not set)", or not a time.</summary>
        public int TimesWithoutValue { get; set; }
        public int OutsideWindow { get; set; }
        /// <summary>Why nothing was taken (bulk table, missing columns, older package, unreadable), or empty.</summary>
        public string LeftOut { get; set; } = "";
    }

    public sealed class TimelineOptions
    {
        public DateTime? FromUtc { get; set; }
        public DateTime? ToUtc { get; set; }
        /// <summary>Also read SRUM's hourly counter tables.</summary>
        public bool All { get; set; }
        public int MaxRows { get; set; } = 2000000;
    }

    public sealed class TimelineRun
    {
        public List<TimelineRow> Rows { get; } = new List<TimelineRow>();
        public List<TimelineSourceStat> Sources { get; } = new List<TimelineSourceStat>();
        /// <summary>Set when MaxRows was reached: later rows of the source being read, and later sources, are not in it.</summary>
        public bool Capped { get; internal set; }
        public string? TimelinePath { get; internal set; }
        public string? SourcesPath { get; internal set; }
    }

    /// <summary>
    /// The package's times in one sorted list (foton timeline, the console's Timeline tab). Reads only package files,
    /// never the live host; the same package and options give the same output. Each row keeps the plain meaning of its
    /// time from its source (a Prefetch run time is not a Shimcache modified time). A reading aid: it raises no findings
    /// and draws no conclusions.
    /// </summary>
    public static class TimelineBuilder
    {
        public const string FileName = "timeline.csv";
        public const string SourcesFileName = "timeline_sources.csv";
        const int MaxSummary = 300;
        const long MaxFileBytes = 2L * 1024 * 1024 * 1024;
        static readonly Regex TimeText = new Regex(@"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d{1,7})?\s*(Z|[+-]\d{2}:\d{2})?$");

        /// <summary>Opens the package (folder or ZIP), builds the timeline, and writes timeline.csv and timeline_sources.csv into analysis\.</summary>
        public static TimelineRun Run(string packagePath, StatusLog log, TimelineOptions options)
        {
            var pkg = FotonPackage.Open(packagePath);
            if (pkg.ZipNote != null) log.Write(pkg.ZipNote, StatusLevel.Info);
            log.Write("Building the timeline from package files (offline)", StatusLevel.Step);
            var run = Build(pkg.CaseRoot, options);
            var analysis = Path.Combine(pkg.CaseRoot, "analysis");
            Directory.CreateDirectory(analysis);
            run.TimelinePath = Path.Combine(analysis, FileName);
            run.SourcesPath = Path.Combine(analysis, SourcesFileName);
            if (run.Rows.Count > 0) Csv.Write(run.TimelinePath, run.Rows);
            else TextFile.Write(run.TimelinePath, "\"TimeUtc\",\"Source\",\"Meaning\",\"Summary\",\"Artifact\",\"Row\",\"DuringCollection\"");
            Csv.Write(run.SourcesPath, run.Sources);
            var used = run.Sources.Where(s => s.TimesUsed > 0).Select(s => s.Source).Distinct().ToList();
            log.Write($"Timeline: {run.Rows.Count} row(s) from {run.Sources.Count(s => s.TimesUsed > 0)} artifact(s) ({string.Join(", ", used)})", StatusLevel.Good);
            // One line per reason; timeline_sources.csv lists every artifact.
            foreach (var g in run.Sources.Where(s => s.LeftOut.Length > 0).GroupBy(s => s.LeftOut, StringComparer.Ordinal))
                log.Write(g.Count() == 1 ? $"Not in the timeline: {g.First().Artifact} ({g.Key})" : $"Not in the timeline ({g.Key}): {g.Count()} artifacts, for example {g.First().Artifact}", StatusLevel.Info);
            if (run.Capped)
                log.Write($"Stopped at {options.MaxRows} rows: sources read later are missing or cut short (timeline_sources.csv says which), so the rows kept are not the earliest times. Narrow it with -From and -To.", StatusLevel.Warn);
            log.Write("Timeline: " + run.TimelinePath, StatusLevel.Good);
            return run;
        }

        /// <summary>The timeline of a case root, in memory.</summary>
        public static TimelineRun Build(string caseRoot, TimelineOptions options)
        {
            var run = new TimelineRun();
            var window = CollectionWindow.FromCase(caseRoot);
            bool foton2 = IsFoton2(caseRoot);
            bool evtxECmd = Files(caseRoot, @"analysis\external\evtxecmd", "*.csv").Any();
            foreach (var source in TimelineSources.All)
            {
                foreach (var file in Files(caseRoot, source.Folder, source.Pattern))
                {
                    var stat = new TimelineSourceStat { Source = source.Name, Artifact = Relative(caseRoot, file) };
                    run.Sources.Add(stat);
                    if (source.Bulk && !options.All) { stat.LeftOut = "hourly counters; included with -All"; continue; }
                    if (source.Foton2Only && !foton2) { stat.LeftOut = "written in local time by packages before Foton 2"; continue; }
                    if (source.UnlessEvtxECmd && evtxECmd) { stat.LeftOut = "EvtxECmd output covers the same events"; continue; }
                    if (run.Capped) { stat.LeftOut = "row cap reached"; continue; }
                    try { Read(source, file, stat, run, options, window); }
                    // Package files are untrusted: anything one of them makes the reader trip on leaves that artifact out, named.
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                        || ex is FormatException || ex is OverflowException || ex is ArgumentException)
                    {
                        stat.LeftOut = "unreadable: " + TextFile.OneLine(ex.Message);
                    }
                }
            }
            run.Rows.Sort((a, b) =>
            {
                var c = a.Ticks.CompareTo(b.Ticks);
                if (c == 0) c = string.CompareOrdinal(a.Source, b.Source);
                if (c == 0) c = string.CompareOrdinal(a.Artifact, b.Artifact);
                if (c == 0) c = a.Row.CompareTo(b.Row);
                return c != 0 ? c : string.CompareOrdinal(a.Meaning, b.Meaning);
            });
            return run;
        }

        static void Read(TimelineSource source, string file, TimelineSourceStat stat, TimelineRun run, TimelineOptions options, CollectionWindow? window)
        {
            if (new FileInfo(file).Length > MaxFileBytes) { stat.LeftOut = "larger than " + MaxFileBytes + " bytes"; return; }
            var head = ArtifactReader.ReadText(file, 200, out _);
            if (head.StartsWith("Foton:", StringComparison.Ordinal) || head.StartsWith("WinFoton:", StringComparison.Ordinal)) { stat.LeftOut = "no data (the task left a note)"; return; }
            List<string>? header = null;
            int[] timeIndex = new int[0];
            var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int row = 0;
            foreach (var cells in Csv.StreamRecords(file, 8192, 512))
            {
                if (header == null)
                {
                    header = cells;
                    for (int i = 0; i < header.Count; i++) if (!index.ContainsKey(header[i])) index[header[i]] = i;
                    var missing = source.Times.Where(t => !index.ContainsKey(t.Column)).Select(t => t.Column).ToList();
                    if (missing.Count == source.Times.Length) { stat.LeftOut = "columns not found: " + string.Join(", ", missing); return; }
                    timeIndex = source.Times.Select(t => index.TryGetValue(t.Column, out var i) ? i : -1).ToArray();
                    continue;
                }
                row++;
                stat.RowsRead++;
                string Field(string name) => index.TryGetValue(name, out var i) && i < cells.Count ? cells[i] : "";
                string? summary = null;
                for (int t = 0; t < source.Times.Length; t++)
                {
                    var i = timeIndex[t];
                    if (i < 0) continue;
                    if (i >= cells.Count || !TryTime(cells[i], out var utc)) { stat.TimesWithoutValue++; continue; }
                    if ((options.FromUtc.HasValue && utc < options.FromUtc.Value) || (options.ToUtc.HasValue && utc > options.ToUtc.Value)) { stat.OutsideWindow++; continue; }
                    if (run.Rows.Count >= options.MaxRows)
                    {
                        run.Capped = true;
                        stat.LeftOut = $"row cap reached after {row - 1} of its rows (the cap keeps sources in reading order, not the earliest times)";
                        return;
                    }
                    if (summary == null)
                    {
                        summary = TextFile.OneLine(source.Summary(Field)).Trim();
                        if (summary.Length > MaxSummary) summary = summary.Substring(0, MaxSummary) + " [...]";
                    }
                    run.Rows.Add(new TimelineRow
                    {
                        Ticks = utc.Ticks, TimeUtc = FotonTime.Format(utc), Source = source.Name, Meaning = source.Times[t].Meaning,
                        Summary = summary, Artifact = stat.Artifact, Row = row, DuringCollection = window != null && window.Contains(utc),
                    });
                    stat.TimesUsed++;
                }
            }
            if (header == null) stat.LeftOut = "empty file";
        }

        /// <summary>
        /// "yyyy-MM-dd HH:mm:ss" with optional fractions, 'T', and offset (Z or +hh:mm) as UTC; no offset means UTC, as
        /// EZ Tools, Hayabusa (-U), and Foton 2 write. Empty, "(not set)", and anything else are not times.
        /// </summary>
        internal static bool TryTime(string? text, out DateTime utc)
        {
            utc = default;
            if (string.IsNullOrWhiteSpace(text)) return false;
            var m = TimeText.Match(text!.Trim());
            if (!m.Success) return false;
            if (!DateTime.TryParseExact(m.Groups[1].Value + " " + m.Groups[2].Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
                return false;
            try
            {
                // Fractions to whole 100 ns ticks (up to 7 digits), never through floating point.
                if (m.Groups[3].Success) t = t.AddTicks(long.Parse(m.Groups[3].Value.Substring(1).PadRight(7, '0'), CultureInfo.InvariantCulture));
                var offset = m.Groups[4].Value;
                if (offset.Length > 1)
                {
                    // Real UTC offsets only (at most 14:00); a malformed one is not a time, never an exception.
                    if (!TimeSpan.TryParseExact(offset.Substring(1), @"hh\:mm", CultureInfo.InvariantCulture, out var span) || span > TimeSpan.FromHours(14)) return false;
                    t = offset[0] == '+' ? t - span : t + span;
                }
            }
            catch (ArgumentOutOfRangeException) { return false; }   // an offset past the first or last representable date
            if (t.Year < 1980 || t.Year > 2100) return false;   // zero FILETIMEs and placeholder dates are not events
            utc = DateTime.SpecifyKind(t, DateTimeKind.Utc);
            return true;
        }

        /// <summary>Files directly in caseRoot\folder matching the pattern, in name order; none when any part of the path is a link.</summary>
        static IEnumerable<string> Files(string caseRoot, string folder, string pattern)
        {
            var dir = Path.Combine(caseRoot, folder);
            var current = caseRoot;
            foreach (var part in folder.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, part);
                try
                {
                    if (!Directory.Exists(current) || (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return new string[0];
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new string[0]; }
            }
            try
            {
                return new DirectoryInfo(dir).GetFiles(pattern)
                    .Where(f => (f.Attributes & FileAttributes.ReparsePoint) == 0 && string.Equals(f.Extension, ".csv", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).Select(f => f.FullName).ToList();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new string[0]; }
        }

        static string Relative(string caseRoot, string file) =>
            file.StartsWith(caseRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) ? file.Substring(caseRoot.TrimEnd('\\').Length + 1) : Path.GetFileName(file);

        /// <summary>Whether Foton 2 wrote the collection (its log's first line): earlier packages hold some times in local time.</summary>
        static bool IsFoton2(string caseRoot)
        {
            try
            {
                var log = Path.Combine(caseRoot, CaseTree.CollectionFolder, "collection.log");
                if (!File.Exists(log)) return false;
                var first = ArtifactReader.ReadText(log, 200, out _);
                var m = Regex.Match(first, @"^Foton (\d+)\.");
                return m.Success && int.TryParse(m.Groups[1].Value, out var major) && major >= 2;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return false; }
        }
    }
}
