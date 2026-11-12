using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>One place a search text was found: a CSV cell (Row and Column) or a line of a text file (Line).</summary>
    public sealed class SearchHit
    {
        /// <summary>The file relative to the case root.</summary>
        public string Artifact { get; set; } = "";
        /// <summary>CSV: the data row (1 is the first after the header; 0 is the header itself). 0 for text files.</summary>
        public int Row { get; set; }
        /// <summary>Text files: the line (1-based). 0 for CSVs.</summary>
        public int Line { get; set; }
        /// <summary>CSV: the column's header.</summary>
        public string Column { get; set; } = "";
        /// <summary>The text around the match, on one line.</summary>
        public string Snippet { get; set; } = "";
    }

    public sealed class SearchOptions
    {
        public bool Regex { get; set; }
        /// <summary>Hits kept (every match is still counted).</summary>
        public int MaxHits { get; set; } = 10000;
        public long MaxFileBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    }

    /// <summary>What a search found and what it could not search, so a miss is never silent.</summary>
    public sealed class SearchRun
    {
        public string Query { get; internal set; } = "";
        public bool Regex { get; internal set; }
        public List<SearchHit> Hits { get; } = new List<SearchHit>();
        /// <summary>Every match, including those past MaxHits.</summary>
        public int Matches { get; internal set; }
        public int FilesSearched { get; internal set; }
        public int FilesWithMatches { get; internal set; }
        /// <summary>Binary files (EVTX, hives, Prefetch, databases): parse and compose turn those into the CSVs searched here.</summary>
        public List<string> Binary { get; } = new List<string>();
        /// <summary>Files not searched or searched only in part, with the reason.</summary>
        public List<string> NotSearched { get; } = new List<string>();
        /// <summary>Lines where a regular expression ran out of time (skipped).</summary>
        public int RegexTimeouts { get; internal set; }
        public bool Stopped { get; internal set; }
        public string? ResultsPath { get; internal set; }
        public string? SummaryPath { get; internal set; }
    }

    /// <summary>
    /// foton search and the console's Search tab: one text (or regular expression) across every CSV, JSON, text, log,
    /// XML, and HTML file in a package, collected and workstation outputs alike. Reads package files only, streamed and
    /// capped, never through links; binary artifacts are listed as not searched. Case-insensitive.
    /// </summary>
    public static class PackageSearch
    {
        public const string FilePrefix = "search_";
        const int MaxLineChars = 65536, MaxFieldChars = 65536, MaxFields = 4000, SnippetContext = 80;
        static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

        /// <summary>Opens the package, searches it, and writes analysis\search_&lt;UTC&gt;.csv (hits) and .txt (what was searched).</summary>
        public static SearchRun Run(string packagePath, string query, SearchOptions options, StatusLog log, CancellationToken cancel = default, DateTime? utcNow = null)
        {
            var pkg = FotonPackage.Open(packagePath);
            if (pkg.ZipNote != null) log.Write(pkg.ZipNote, StatusLevel.Info);
            log.Write($"Searching the package for {(options.Regex ? "the regular expression" : "the text")} \"{TextFile.OneLine(query)}\" (case-insensitive, offline)", StatusLevel.Step);
            var run = Search(pkg.CaseRoot, query, options, cancel);
            var now = utcNow ?? DateTime.UtcNow;
            var analysis = Path.Combine(pkg.CaseRoot, "analysis");
            if (!CaseIndex.Plain(pkg.CaseRoot, "analysis")) throw new IOException("analysis is a link or junction; search results not written");
            Directory.CreateDirectory(analysis);
            var stem = Path.Combine(analysis, FilePrefix + FotonTime.Stamp(now) + "Z");
            run.ResultsPath = stem + ".csv";
            run.SummaryPath = stem + ".txt";
            // Never written over or through: a file already there (a planted link included) stops the write.
            foreach (var target in new[] { run.ResultsPath, run.SummaryPath })
                if (Occupied(target)) throw new IOException("Already exists, or is a link: " + target + "; search results not written");
            if (run.Hits.Count > 0) Csv.Write(run.ResultsPath, run.Hits);
            else TextFile.Write(run.ResultsPath, "\"Artifact\",\"Row\",\"Line\",\"Column\",\"Snippet\"");
            TextFile.WriteLines(run.SummaryPath, Summary(run, now));
            log.Write($"{run.Matches} match(es) in {run.FilesWithMatches} of {run.FilesSearched} file(s)" + (run.Matches > run.Hits.Count ? $"; the first {run.Hits.Count} are listed" : ""), StatusLevel.Good);
            if (run.Binary.Count > 0) log.Write($"{run.Binary.Count} binary file(s) not searched (EVTX, hives, Prefetch, databases): parse and compose turn them into CSVs that are searched.", StatusLevel.Info);
            foreach (var n in run.NotSearched.Take(20)) log.Write("Not searched: " + n, StatusLevel.Warn);
            if (run.RegexTimeouts > 0) log.Write($"The regular expression ran out of time on {run.RegexTimeouts} line(s); those lines were skipped.", StatusLevel.Warn);
            if (run.Stopped) log.Write("Stopped before every file was searched; the results cover the files searched so far.", StatusLevel.Warn);
            log.Write("Results: " + run.ResultsPath, StatusLevel.Good);
            return run;
        }

        /// <summary>
        /// True when anything is at the path, a link whose target is missing included (File.Exists is false for those,
        /// and a write would follow them); attributes are read from the entry itself, never its target.
        /// </summary>
        internal static bool Occupied(string path)
        {
            try { File.GetAttributes(path); return true; }
            catch (Exception ex) when (ex is FileNotFoundException || ex is DirectoryNotFoundException) { return false; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }

        static IEnumerable<string> Summary(SearchRun run, DateTime now)
        {
            yield return "Foton search (" + FotonVersion.Product + ")";
            yield return "Searched (UTC): " + FotonTime.Format(now);
            yield return (run.Regex ? "Regular expression: " : "Text: ") + TextFile.OneLine(run.Query) + " (case-insensitive)";
            yield return $"Matches: {run.Matches} in {run.FilesWithMatches} of {run.FilesSearched} file(s); listed: {run.Hits.Count}";
            if (run.Stopped) yield return "Stopped before every file was searched.";
            if (run.RegexTimeouts > 0) yield return $"Lines skipped after the regular expression ran out of time: {run.RegexTimeouts}";
            yield return $"Binary files not searched: {run.Binary.Count}";
            foreach (var b in run.Binary) yield return "  " + b;
            yield return $"Not searched or searched in part: {run.NotSearched.Count}";
            foreach (var n in run.NotSearched) yield return "  " + n;
        }

        /// <summary>The search over a case root, in memory. Throws ArgumentException for an empty query or an invalid regular expression.</summary>
        public static SearchRun Search(string caseRoot, string query, SearchOptions options, CancellationToken cancel = default)
        {
            if (string.IsNullOrEmpty(query)) throw new ArgumentException("Give a text to search for.");
            caseRoot = Path.GetFullPath(caseRoot).TrimEnd('\\', '/');
            var run = new SearchRun { Query = query, Regex = options.Regex };
            Func<string, int> find;   // index of the first match in a string, or -1; its length is in lastLength
            int lastLength = query.Length;
            if (options.Regex)
            {
                var re = new Regex(query, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);   // throws ArgumentException when invalid
                find = text =>
                {
                    try
                    {
                        var m = re.Match(text);
                        if (!m.Success) return -1;
                        lastLength = m.Length;
                        return m.Index;
                    }
                    catch (RegexMatchTimeoutException) { run.RegexTimeouts++; return -1; }
                };
            }
            else find = text => text.IndexOf(query, StringComparison.OrdinalIgnoreCase);

            foreach (var file in Files(caseRoot, run))
            {
                if (cancel.IsCancellationRequested) { run.Stopped = true; break; }
                var rel = file.Substring(caseRoot.Length + 1);
                // Earlier searches' own results would match every later search for the same text.
                if (rel.StartsWith(Path.Combine("analysis", FilePrefix), StringComparison.OrdinalIgnoreCase)) continue;
                long length;
                try { length = new FileInfo(file).Length; }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { run.NotSearched.Add(rel + " (unreadable: " + TextFile.OneLine(ex.Message) + ")"); continue; }
                if (length > options.MaxFileBytes) { run.NotSearched.Add($"{rel} (larger than {options.MaxFileBytes} bytes)"); continue; }
                var shape = ArtifactReader.ShapeOf(file);
                if (shape == ArtifactShape.Binary) { run.Binary.Add(rel); continue; }
                run.FilesSearched++;
                var before = run.Matches;
                try
                {
                    if (shape == ArtifactShape.Csv) SearchCsv(file, rel, run, options, find, () => lastLength, cancel);
                    else SearchText(file, rel, run, options, find, () => lastLength, cancel);
                }
                catch (OperationCanceledException) { run.Stopped = true; run.NotSearched.Add(rel + " (stopped partway)"); break; }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is DecoderFallbackException)
                {
                    run.NotSearched.Add(rel + " (" + (run.Matches > before ? "searched in part, then: " : "unreadable: ") + TextFile.OneLine(ex.Message) + ")");
                }
                if (run.Matches > before) run.FilesWithMatches++;
            }
            return run;
        }

        static void Add(SearchRun run, SearchOptions options, string rel, int row, int line, string column, string text, int index, int length)
        {
            run.Matches++;
            if (run.Hits.Count < options.MaxHits)
                run.Hits.Add(new SearchHit { Artifact = rel, Row = row, Line = line, Column = TextFile.OneLine(column), Snippet = Snippet(text, index, length) });
        }

        /// <summary>The match with up to SnippetContext characters either side, on one line.</summary>
        internal static string Snippet(string text, int index, int length)
        {
            var start = Math.Max(0, index - SnippetContext);
            var end = Math.Min(text.Length, index + Math.Max(length, 1) + SnippetContext);
            return (start > 0 ? "..." : "") + TextFile.OneLine(text.Substring(start, end - start)).Trim() + (end < text.Length ? "..." : "");
        }

        static void SearchCsv(string file, string rel, SearchRun run, SearchOptions options, Func<string, int> find, Func<int> length, CancellationToken cancel)
        {
            List<string>? header = null;
            int row = -1;
            foreach (var cells in Csv.StreamRecords(file, MaxFieldChars, MaxFields))
            {
                cancel.ThrowIfCancellationRequested();
                row++;
                if (header == null) header = cells;
                for (int c = 0; c < cells.Count; c++)
                {
                    var i = find(cells[c]);
                    if (i >= 0) Add(run, options, rel, row, 0, c < header.Count ? header[c] : "(extra " + (c + 1).ToString(CultureInfo.InvariantCulture) + ")", cells[c], i, length());
                }
            }
        }

        static void SearchText(string file, string rel, SearchRun run, SearchOptions options, Func<string, int> find, Func<int> length, CancellationToken cancel)
        {
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(fs, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true))
            {
                int line = 0;
                foreach (var text in Lines(reader))
                {
                    cancel.ThrowIfCancellationRequested();
                    line++;
                    var i = find(text);
                    if (i >= 0) Add(run, options, rel, 0, line, "", text, i, length());
                }
            }
        }

        /// <summary>Lines of a text file; a line longer than MaxLineChars is searched in pieces of that size (a match across a piece boundary is missed).</summary>
        static IEnumerable<string> Lines(TextReader reader)
        {
            var sb = new StringBuilder();
            int ch;
            while ((ch = reader.Read()) >= 0)
            {
                if (ch == '\n')
                {
                    yield return sb.ToString().TrimEnd('\r');
                    sb.Clear();
                    continue;
                }
                sb.Append((char)ch);
                if (sb.Length >= MaxLineChars) { yield return sb.ToString(); sb.Clear(); }
            }
            if (sb.Length > 0) yield return sb.ToString();
        }

        /// <summary>Every file under the case root in name order, never through a link or junction (those are listed as not searched).</summary>
        static IEnumerable<string> Files(string caseRoot, SearchRun run)
        {
            var pending = new Stack<string>();
            pending.Push(caseRoot);
            while (pending.Count > 0)
            {
                var dir = pending.Pop();
                DirectoryInfo[] dirs;
                FileInfo[] files;
                try
                {
                    var info = new DirectoryInfo(dir);
                    dirs = info.GetDirectories().OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToArray();
                    files = info.GetFiles().OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToArray();
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    run.NotSearched.Add((dir.Length > caseRoot.Length ? dir.Substring(caseRoot.Length + 1) : ".") + "\\ (folder unreadable: " + TextFile.OneLine(ex.Message) + ")");
                    continue;
                }
                foreach (var f in files)
                {
                    if ((f.Attributes & FileAttributes.ReparsePoint) != 0) { run.NotSearched.Add(f.FullName.Substring(caseRoot.Length + 1) + " (link, not followed)"); continue; }
                    yield return f.FullName;
                }
                // Pushed in reverse so folders are searched in name order.
                for (int i = dirs.Length - 1; i >= 0; i--)
                {
                    if ((dirs[i].Attributes & FileAttributes.ReparsePoint) != 0) { run.NotSearched.Add(dirs[i].FullName.Substring(caseRoot.Length + 1) + "\\ (link, not followed)"); continue; }
                    pending.Push(dirs[i].FullName);
                }
            }
        }
    }
}
