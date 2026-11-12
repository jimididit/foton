using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using Foton.Core;

namespace Foton.Analyze.Timeline
{
    /// <summary>Which timeline rows to show. Every part is optional; empty means everything.</summary>
    public sealed class TimelineFilter
    {
        public DateTime? FromUtc { get; set; }
        public DateTime? ToUtc { get; set; }
        /// <summary>One source name (case-insensitive), or null for all.</summary>
        public string? Source { get; set; }
        /// <summary>Text anywhere in the time, source, meaning, summary, or artifact (case-insensitive).</summary>
        public string? Text { get; set; }
    }

    /// <summary>The first matching rows of a timeline.csv, how many matched in all, and the sources it holds.</summary>
    public sealed class TimelineView
    {
        public List<TimelineRow> Rows { get; } = new List<TimelineRow>();
        public int Matches { get; internal set; }
        public int RowsRead { get; internal set; }
        /// <summary>Source names in the file, sorted (at most MaxSources).</summary>
        public List<string> Sources { get; } = new List<string>();
        /// <summary>Why the file could not be read as a timeline, or null.</summary>
        public string? Problem { get; internal set; }
    }

    /// <summary>
    /// Reads analysis\timeline.csv for display (the console's Timeline tab): streams the file, so a timeline of millions
    /// of rows is filtered without holding it in memory, and keeps only the first rows that match. The file is a
    /// package file like any other: fields and source names are capped, and a file that is not a timeline is said so.
    /// </summary>
    public static class TimelineReader
    {
        public const int MaxSources = 200;
        static readonly string[] Required = { "TimeUtc", "Source", "Meaning", "Summary", "Artifact", "Row", "DuringCollection" };

        public static TimelineView Read(string timelineCsv, TimelineFilter filter, int maxRows, CancellationToken cancel = default)
        {
            var view = new TimelineView();
            var sources = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            int[]? at = null;
            bool timeFilter = filter.FromUtc.HasValue || filter.ToUtc.HasValue;
            var text = string.IsNullOrEmpty(filter.Text) ? null : filter.Text;
            var source = string.IsNullOrEmpty(filter.Source) ? null : filter.Source;
            foreach (var cells in Csv.StreamRecords(timelineCsv, 8192, 64))
            {
                cancel.ThrowIfCancellationRequested();
                if (at == null)
                {
                    var header = cells.Select(c => c.TrimStart('\uFEFF')).ToList();
                    at = Required.Select(r => header.FindIndex(h => string.Equals(h, r, StringComparison.OrdinalIgnoreCase))).ToArray();
                    var missing = Required.Where((r, i) => at[i] < 0).ToList();
                    if (missing.Count > 0) { view.Problem = "not a timeline file (columns not found: " + string.Join(", ", missing) + ")"; return view; }
                    continue;
                }
                view.RowsRead++;
                string Cell(int column) => at[column] < cells.Count ? cells[at[column]] : "";
                var row = new TimelineRow
                {
                    TimeUtc = Cell(0), Source = Cell(1), Meaning = Cell(2), Summary = Cell(3), Artifact = Cell(4),
                    Row = int.TryParse(Cell(5), NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 0,
                    DuringCollection = string.Equals(Cell(6), "True", StringComparison.OrdinalIgnoreCase),
                };
                if (sources.Count < MaxSources) sources.Add(row.Source);
                if (source != null && !string.Equals(row.Source, source, StringComparison.OrdinalIgnoreCase)) continue;
                if (timeFilter)
                {
                    // A row whose time cannot be read is outside any window.
                    if (!ParseUtc(row.TimeUtc, false, out var utc)) continue;
                    if ((filter.FromUtc.HasValue && utc < filter.FromUtc.Value) || (filter.ToUtc.HasValue && utc > filter.ToUtc.Value)) continue;
                }
                if (text != null && !new[] { row.TimeUtc, row.Source, row.Meaning, row.Summary, row.Artifact }.Any(v => v.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                view.Matches++;
                if (view.Rows.Count < maxRows) view.Rows.Add(row);
            }
            if (at == null) view.Problem = "empty file";
            view.Sources.AddRange(sources);
            return view;
        }

        /// <summary>
        /// "yyyy-MM-dd HH:mm:ss" or "yyyy-MM-dd" as UTC (foton timeline -From/-To, the console's filters). With
        /// <paramref name="endOfDay"/>, a bare date means the last tick of that day, so "-To 2026-11-09" includes the 9th.
        /// </summary>
        public static bool ParseUtc(string? text, bool endOfDay, out DateTime utc)
        {
            const DateTimeStyles utcStyles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
            var t = (text ?? "").Trim();
            if (DateTime.TryParseExact(t, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, utcStyles, out utc)) return true;
            if (!DateTime.TryParseExact(t, "yyyy-MM-dd", CultureInfo.InvariantCulture, utcStyles, out utc)) return false;
            // The last representable day has no next day; its end is the largest DateTime.
            if (endOfDay) utc = utc.Date == DateTime.MaxValue.Date ? DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc) : utc.AddDays(1).AddTicks(-1);
            return true;
        }

        /// <summary>
        /// The first time the timeline would take from one row of a package CSV (the Viewer's Show in timeline): false
        /// when the timeline reads no source from that file or the row has no usable time. Whether the row is in a
        /// particular timeline.csv also depends on how it was built (options, older packages), so callers say so.
        /// </summary>
        public static bool TimeOfRow(string relativeArtifact, IReadOnlyList<string> header, IReadOnlyList<string> cells, out DateTime utc)
        {
            utc = default;
            foreach (var s in SourcesOf(relativeArtifact))
                foreach (var t in s.Times)
                {
                    var i = -1;
                    for (int c = 0; c < header.Count; c++) if (string.Equals(header[c], t.Column, StringComparison.OrdinalIgnoreCase)) { i = c; break; }
                    if (i >= 0 && i < cells.Count && TimelineBuilder.TryTime(cells[i], out utc)) return true;
                }
            return false;
        }

        /// <summary>Whether the timeline reads times from this package file (relative to the case root).</summary>
        public static bool ReadsFile(string relativeArtifact) => SourcesOf(relativeArtifact).Any();

        static IEnumerable<TimelineSource> SourcesOf(string relativeArtifact)
        {
            var rel = relativeArtifact.Replace('/', '\\');
            var folder = Path.GetDirectoryName(rel) ?? "";
            var name = Path.GetFileName(rel);
            if (!string.Equals(Path.GetExtension(name), ".csv", StringComparison.OrdinalIgnoreCase)) return Enumerable.Empty<TimelineSource>();
            return TimelineSources.All.Where(s => string.Equals(s.Folder, folder, StringComparison.OrdinalIgnoreCase) && Matches(s.Pattern, name));
        }

        /// <summary>A file name against a source pattern ('*' wildcards, case-insensitive), as Directory.GetFiles matches it.</summary>
        static bool Matches(string pattern, string name) =>
            Regex.IsMatch(name, "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
