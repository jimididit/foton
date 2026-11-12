using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>One case package found by <see cref="CaseIndex"/>: what its own files say, read without hashing.</summary>
    public sealed class CaseEntry
    {
        /// <summary>The folder, or the ZIP when there is no folder beside it (Open extracts it as the Package tab does).</summary>
        public string Path { get; set; } = "";
        public string Name { get; set; } = "";
        public string Host { get; set; } = "";
        /// <summary>From the folder name: when the collection started (UTC).</summary>
        public string CollectedUtc { get; set; } = "";
        /// <summary>Folder, Zip (no folder beside it, not extracted), or ZipExtracted.</summary>
        public string Kind { get; set; } = "Folder";
        public string CaseNumber { get; set; } = "";
        public string Examiner { get; set; } = "";
        public bool? Elevated { get; set; }
        public string Profile { get; set; } = "";
        /// <summary>analysis (workstation analyze), collect (the collector's own findings), or empty when there are none.</summary>
        public string FindingsSource { get; set; } = "";
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Info { get; set; }
        public bool Parsed { get; set; }
        public bool Composed { get; set; }
        public bool Analyzed { get; set; }
        public bool HasZip { get; set; }
        /// <summary>Why some of the above could not be read; the row is listed anyway.</summary>
        public string Problem { get; set; } = "";
    }

    /// <summary>Workstation steps whose output a case holds.</summary>
    public sealed class CaseStages
    {
        public bool Parsed { get; set; }
        public bool Composed { get; set; }
        public bool Analyzed { get; set; }
        public bool Timeline { get; set; }
    }

    /// <summary>One baseline package found by <see cref="CaseIndex"/>, from its baseline.json header.</summary>
    public sealed class BaselineEntry
    {
        public string Path { get; set; } = "";
        public string JsonPath { get; set; } = "";
        public string Name { get; set; } = "";
        public string Host { get; set; } = "";
        public string CapturedUtc { get; set; } = "";
        public bool? Elevated { get; set; }
        public bool? LoadUserHives { get; set; }
        public string ToolVersion { get; set; } = "";
        public string PayloadSha256 { get; set; } = "";
        public string Problem { get; set; } = "";
    }

    public sealed class CaseList
    {
        public List<CaseEntry> Cases { get; } = new List<CaseEntry>();
        public List<BaselineEntry> Baselines { get; } = new List<BaselineEntry>();
        /// <summary>Folders that could not be read, links that were not followed.</summary>
        public List<string> Notes { get; } = new List<string>();
    }

    /// <summary>
    /// The case and baseline packages in a set of folders, one level deep, for the console's Cases tab and foton cases.
    /// Read-only and never hashes: it reads each package's own small files (custody header, coverage, findings) with
    /// size caps, never follows a junction or link, and lists a package it cannot read with the reason instead of failing.
    /// Package contents are untrusted, so nothing here is evidence that a package is intact; Verify is.
    /// </summary>
    public static class CaseIndex
    {
        static readonly Regex CaseName = new Regex(@"^(?:Foton|WinFoton)_(.+)_(\d{8}-\d{6})Z$", RegexOptions.IgnoreCase);
        static readonly Regex CaseZip = new Regex(@"^((?:Foton|WinFoton)_(.+)_(\d{8}-\d{6})Z)\.zip$", RegexOptions.IgnoreCase);
        static readonly Regex BaselineName = new Regex(@"^FotonBaseline_(.+)_(\d{8}-\d{6})Z$", RegexOptions.IgnoreCase);
        const long MaxSmallFile = 4L * 1024 * 1024;
        const long MaxFindings = 32L * 1024 * 1024;
        const long MaxBaselineJson = 256L * 1024 * 1024;

        public static CaseList Scan(IEnumerable<string> folders)
        {
            var list = new CaseList();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var folder in folders.Where(f => !string.IsNullOrWhiteSpace(f)))
            {
                string root;
                try { root = Normalize(folder); }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException) { list.Notes.Add("Not a folder path: " + folder); continue; }
                if (!seen.Add(root)) continue;
                DirectoryInfo[] dirs;
                FileInfo[] zips;
                try
                {
                    if (!Directory.Exists(root)) { list.Notes.Add("Not found: " + root); continue; }
                    var info = new DirectoryInfo(root);
                    dirs = info.GetDirectories();
                    zips = info.GetFiles("*.zip");
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException)
                {
                    list.Notes.Add("Cannot read " + root + ": " + TextFile.OneLine(ex.Message));
                    continue;
                }
                // Only a folder listed as a case stands in for the ZIP beside it; any other folder of that name does not hide the ZIP.
                var listedCases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var d in dirs)
                {
                    bool caseName = CaseName.IsMatch(d.Name), baselineName = BaselineName.IsMatch(d.Name);
                    if (!caseName && !baselineName) continue;
                    if ((d.Attributes & FileAttributes.ReparsePoint) != 0) { list.Notes.Add("Link or junction not followed: " + d.FullName); continue; }
                    if (caseName && !Plain(d.FullName, CaseTree.CollectionFolder))
                    {
                        list.Notes.Add("Link or junction not followed: " + System.IO.Path.Combine(d.FullName, CaseTree.CollectionFolder));
                        continue;
                    }
                    if (caseName && Directory.Exists(System.IO.Path.Combine(d.FullName, CaseTree.CollectionFolder)))
                    {
                        list.Cases.Add(ReadCase(d.FullName, d.Name, "Folder", hasZip: File.Exists(d.FullName + ".zip")));
                        listedCases.Add(d.Name);
                    }
                    else if (baselineName && Plain(d.FullName, "baseline.json") && File.Exists(System.IO.Path.Combine(d.FullName, "baseline.json")))
                        list.Baselines.Add(ReadBaseline(d.FullName, d.Name));
                }
                foreach (var z in zips)
                {
                    var m = CaseZip.Match(z.Name);
                    if (!m.Success || listedCases.Contains(m.Groups[1].Value)) continue;   // the case folder beside it is listed instead
                    var extracted = z.FullName.Substring(0, z.FullName.Length - 4) + ZipExtraction.Suffix;
                    string? caseRoot = null;
                    try
                    {
                        if (Directory.Exists(extracted) && (new DirectoryInfo(extracted).Attributes & FileAttributes.ReparsePoint) == 0)
                            caseRoot = CaseTree.FindCaseRoot(extracted);
                        // The case folder inside the extraction must not be a link either.
                        if (caseRoot != null && !string.Equals(caseRoot, extracted, StringComparison.OrdinalIgnoreCase)
                            && !Plain(extracted, System.IO.Path.GetFileName(caseRoot)))
                        {
                            list.Notes.Add("Link or junction not followed: " + caseRoot);
                            caseRoot = null;
                        }
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { caseRoot = null; }
                    var e = caseRoot != null ? ReadCase(caseRoot, m.Groups[1].Value, "ZipExtracted", hasZip: true) : Named(m.Groups[1].Value, "Zip");
                    e.Path = z.FullName;
                    e.HasZip = true;
                    list.Cases.Add(e);
                }
            }
            list.Cases.Sort((a, b) => Newest(a.CollectedUtc, a.Name, b.CollectedUtc, b.Name));
            list.Baselines.Sort((a, b) => Newest(a.CapturedUtc, a.Name, b.CapturedUtc, b.Name));
            return list;
        }

        /// <summary>A full path without a trailing backslash, except a drive root: "D:\" stays, since "D:" means the current folder on D.</summary>
        internal static string Normalize(string folder)
        {
            var root = System.IO.Path.GetFullPath(folder.Trim());
            var drive = System.IO.Path.GetPathRoot(root) ?? "";
            return root.Length > drive.Length ? root.TrimEnd('\\') : root;
        }

        /// <summary>
        /// The listing as text lines (foton cases). Values from package files are already one line (TextFile.OneLine);
        /// names and paths from the file system are flattened here too, so nothing can reach a terminal as a control
        /// sequence. The entries keep exact paths for Open; -Json escapes control characters itself.
        /// </summary>
        public static IEnumerable<string> Lines(CaseList list)
        {
            string Who(bool? elevated) => elevated == null ? "unknown" : elevated.Value ? "admin" : "standard";
            string T(string? s) => TextFile.OneLine(s);
            yield return $"Cases ({list.Cases.Count}), newest first";
            foreach (var c in list.Cases)
            {
                var stages = string.Join(" ", new[] { c.Parsed ? "parsed" : null, c.Composed ? "composed" : null, c.Analyzed ? "analyzed" : null }.Where(s => s != null));
                var findings = c.FindingsSource.Length == 0 ? "no findings" : $"H{c.High} M{c.Medium} L{c.Low} I{c.Info} ({c.FindingsSource})";
                yield return $"  {T(c.CollectedUtc)}  {T(c.Host)}  {(c.CaseNumber.Length > 0 ? T(c.CaseNumber) : "(no case number)")}  {Who(c.Elevated)}" +
                    $"{(c.Profile.Length > 0 ? "  profile " + T(c.Profile) : "")}  {findings}{(stages.Length > 0 ? "  " + stages : "")}  {c.Kind}{(c.HasZip && c.Kind == "Folder" ? "+zip" : "")}";
                yield return "      " + T(c.Path);
                if (c.Problem.Length > 0) yield return "      unreadable: " + T(c.Problem);
            }
            yield return "";
            yield return $"Baselines ({list.Baselines.Count}), newest first";
            foreach (var b in list.Baselines)
            {
                yield return $"  {T(b.CapturedUtc)}  {T(b.Host)}  {Who(b.Elevated)}{(b.LoadUserHives == true ? "  user hives" : "")}  Foton {T(b.ToolVersion)}  payload {T(b.PayloadSha256)}";
                yield return "      " + T(b.Path);
                if (b.Problem.Length > 0) yield return "      unreadable: " + T(b.Problem);
            }
            foreach (var n in list.Notes) yield return "Note: " + T(n);
        }

        static int Newest(string at, string an, string bt, string bn)
        {
            var c = string.CompareOrdinal(bt, at);
            return c != 0 ? c : string.Compare(an, bn, StringComparison.OrdinalIgnoreCase);
        }

        static CaseEntry Named(string name, string kind)
        {
            var e = new CaseEntry { Name = name, Kind = kind };
            var m = CaseName.Match(name);
            if (m.Success) { e.Host = m.Groups[1].Value; e.CollectedUtc = Stamp(m.Groups[2].Value); }
            return e;
        }

        /// <summary>yyyyMMdd-HHmmss as yyyy-MM-dd HH:mm:ss (sorts the same); the raw stamp when it is not a date.</summary>
        static string Stamp(string s) =>
            DateTime.TryParseExact(s, "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)
                ? FotonTime.Format(t) : s;

        static CaseEntry ReadCase(string root, string name, string kind, bool hasZip)
        {
            var e = Named(name, kind);
            e.Path = root;
            e.HasZip = hasZip;
            var problems = new List<string>();
            var col = System.IO.Path.Combine(root, CaseTree.CollectionFolder);
            // A file is read only when no folder between the case root and it, and not the file itself, is a link.
            bool Usable(string relative)
            {
                if (Plain(root, relative)) return true;
                problems.Add(relative + " is reached through a link or junction: not followed");
                return false;
            }

            if (Usable(@"00_Collection\chain_of_custody.txt"))
            {
                var custody = ChainOfCustody.ReadHeader(root);
                e.CaseNumber = TextFile.OneLine(custody.CaseNumber ?? "");
                e.Examiner = TextFile.OneLine(custody.Examiner ?? "");
            }

            try
            {
                var coverage = System.IO.Path.Combine(col, "collection_coverage.json");
                if (Usable(@"00_Collection\collection_coverage.json") && File.Exists(coverage))
                {
                    if (Json.Parse(Small(coverage)) is IDictionary c)
                    {
                        if (c.Contains("Elevated") && c["Elevated"] is bool b) e.Elevated = b;
                        if (c.Contains("ProfileName") && c["ProfileName"] is string p) e.Profile = TextFile.OneLine(p);
                    }
                }
            }
            catch (Exception ex) when (Readable(ex)) { problems.Add("coverage: " + TextFile.OneLine(ex.Message)); }

            var stages = Stages(root);
            e.Parsed = stages.Parsed;
            e.Composed = stages.Composed;
            e.Analyzed = stages.Analyzed;
            var findings = e.Analyzed ? @"analysis\findings.csv" : @"00_Collection\findings.csv";
            try
            {
                if (File.Exists(System.IO.Path.Combine(root, findings)) && Usable(findings))
                {
                    CountFindings(System.IO.Path.Combine(root, findings), e);
                    e.FindingsSource = e.Analyzed ? "analysis" : "collect";
                }
            }
            catch (Exception ex) when (Readable(ex)) { problems.Add("findings: " + TextFile.OneLine(ex.Message)); }

            e.Problem = string.Join("; ", problems);
            return e;
        }

        /// <summary>
        /// Which workstation steps have written their output in a case (the Cases list and the console's checklist).
        /// Existence checks only; a linked analysis folder counts as not done.
        /// </summary>
        public static CaseStages Stages(string root)
        {
            var analysisPlain = Plain(root, "analysis");
            bool Has(string relative) => analysisPlain && File.Exists(System.IO.Path.Combine(root, relative));
            return new CaseStages
            {
                Parsed = Has(@"analysis\parsed_records.csv"),
                Composed = Plain(root, @"analysis\external") && Has(@"analysis\external\external_parse_inventory.csv"),
                Analyzed = Has(@"analysis\findings.csv"),
                Timeline = Has(@"analysis\timeline.csv"),
            };
        }

        static void CountFindings(string path, CaseEntry e)
        {
            if (new FileInfo(path).Length > MaxFindings) throw new InvalidDataException("findings.csv is larger than " + MaxFindings + " bytes");
            int severity = -1;
            foreach (var row in Csv.StreamRecords(path, 4096, 64))
            {
                if (severity < 0) { severity = row.FindIndex(c => string.Equals(c, "Severity", StringComparison.OrdinalIgnoreCase)); if (severity < 0) return; continue; }
                if (severity >= row.Count) continue;
                switch (row[severity])
                {
                    case "High": e.High++; break;
                    case "Medium": e.Medium++; break;
                    case "Low": e.Low++; break;
                    case "Info": e.Info++; break;
                }
            }
        }

        static BaselineEntry ReadBaseline(string root, string name)
        {
            var e = new BaselineEntry { Path = root, Name = name, JsonPath = System.IO.Path.Combine(root, "baseline.json") };
            var m = BaselineName.Match(name);
            if (m.Success) { e.Host = m.Groups[1].Value; e.CapturedUtc = Stamp(m.Groups[2].Value); }
            try
            {
                if (new FileInfo(e.JsonPath).Length > MaxBaselineJson) throw new InvalidDataException("baseline.json is larger than " + MaxBaselineJson + " bytes");
                var h = BaselineDocument.Load(e.JsonPath).Header;
                if (h.Hostname.Length > 0) e.Host = TextFile.OneLine(h.Hostname);
                if (h.CapturedUtc.Length > 0) e.CapturedUtc = TextFile.OneLine(h.CapturedUtc);
                e.Elevated = h.Elevated;
                e.LoadUserHives = h.LoadUserHives;
                e.ToolVersion = TextFile.OneLine(h.ToolVersion);
                e.PayloadSha256 = TextFile.OneLine(h.PayloadSha256);
            }
            catch (Exception ex) when (Readable(ex)) { e.Problem = "baseline.json: " + TextFile.OneLine(ex.Message); }
            return e;
        }

        /// <summary>
        /// True when no folder or file from <paramref name="root"/> down to root\<paramref name="relative"/> is a link or
        /// junction (parts that do not exist are fine). Fails closed: an attribute that cannot be read counts as a link.
        /// </summary>
        public static bool IsPlain(string root, string relative) => Plain(root, relative);

        internal static bool Plain(string root, string relative)
        {
            var current = root;
            foreach (var part in relative.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                current = System.IO.Path.Combine(current, part);
                try
                {
                    if (!File.Exists(current) && !Directory.Exists(current)) return true;
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) { return false; }
            }
            return true;
        }

        static string Small(string path)
        {
            if (new FileInfo(path).Length > MaxSmallFile) throw new InvalidDataException(System.IO.Path.GetFileName(path) + " is larger than " + MaxSmallFile + " bytes");
            return File.ReadAllText(path, Encoding.UTF8).TrimStart('\uFEFF');
        }

        static bool Readable(Exception ex) =>
            ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException
            || ex is InvalidOperationException || ex is FormatException || ex is InvalidCastException;
    }
}
