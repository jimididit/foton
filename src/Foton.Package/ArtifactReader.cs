using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;

namespace Foton.Package
{
    public enum ArtifactShape { Csv, Json, Text, Binary }

    /// <summary>A CSV read for display: columns in file order and up to a row cap.</summary>
    public sealed class CsvTable
    {
        public IReadOnlyList<string> Columns { get; internal set; } = new string[0];
        public List<string[]> Rows { get; } = new List<string[]>();
        /// <summary>True when the file holds more rows than were read.</summary>
        public bool Truncated { get; internal set; }

        /// <summary>Row indexes whose cells contain <paramref name="text"/> (case-insensitive); every row for empty text.</summary>
        public List<int> Filter(string text)
        {
            if (string.IsNullOrEmpty(text)) return Enumerable.Range(0, Rows.Count).ToList();
            var hits = new List<int>();
            for (int i = 0; i < Rows.Count; i++)
                if (Rows[i].Any(c => c.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0)) hits.Add(i);
            return hits;
        }
    }

    /// <summary>
    /// Reads package files for a viewer, with caps so a large artifact cannot exhaust memory: display only, offline,
    /// never interpreted. Binary artifacts (EVTX, hives, Prefetch) are for parse and compose, not this reader.
    /// </summary>
    public static class ArtifactReader
    {
        static readonly HashSet<string> TextExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".txt", ".log", ".md", ".xml", ".html", ".htm", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".reg", ".inf", ".ini",
            ".cfg", ".conf", ".yml", ".yaml", ".tsv",
        };

        /// <summary>By extension, then by content: a file with no NUL in its first 4 KB reads as text.</summary>
        public static ArtifactShape ShapeOf(string path)
        {
            var ext = Path.GetExtension(path);
            if (string.Equals(ext, ".csv", StringComparison.OrdinalIgnoreCase)) return ArtifactShape.Csv;
            if (string.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase)) return ArtifactShape.Json;
            if (TextExtensions.Contains(ext)) return ArtifactShape.Text;
            try
            {
                var head = new byte[4096];
                int n;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) n = fs.Read(head, 0, head.Length);
                return n > 0 && Array.IndexOf(head, (byte)0, 0, n) < 0 ? ArtifactShape.Text : ArtifactShape.Binary;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return ArtifactShape.Binary; }
        }

        public static CsvTable ReadCsv(string path, int maxRows)
        {
            var t = new CsvTable();
            foreach (var r in Csv.StreamRecords(path))
            {
                if (t.Columns.Count == 0) { t.Columns = r.ToArray(); continue; }
                if (t.Rows.Count >= maxRows) { t.Truncated = true; break; }
                var row = new string[t.Columns.Count];
                for (int c = 0; c < row.Length; c++) row[c] = c < r.Count ? r[c] : "";
                t.Rows.Add(row);
            }
            return t;
        }

        /// <summary>The first <paramref name="maxChars"/> characters (UTF-8, BOM honored).</summary>
        public static string ReadText(string path, int maxChars, out bool truncated)
        {
            using (var reader = new StreamReader(path, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true))
            {
                var buffer = new char[maxChars + 1];
                int read = 0, n;
                while (read < buffer.Length && (n = reader.Read(buffer, read, buffer.Length - read)) > 0) read += n;
                truncated = read > maxChars;
                return new string(buffer, 0, Math.Min(read, maxChars));
            }
        }
    }

    /// <summary>What 00_Collection\hashes.csv recorded for each file, for a per-file integrity line in a viewer.</summary>
    public sealed class PackageHashes
    {
        readonly string _root;
        readonly Dictionary<string, string> _sha = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public PackageHashes(string caseRoot)
        {
            _root = Path.GetFullPath(caseRoot).TrimEnd('\\') + "\\";
            var csv = Path.Combine(caseRoot, CaseTree.CollectionFolder, "hashes.csv");
            Present = File.Exists(csv);
            if (!Present) return;
            foreach (var row in Csv.Read(csv))
            {
                var rel = (row.TryGetValue("RelativePath", out var r) ? r ?? "" : "").Replace('/', '\\');
                if (rel.StartsWith(@".\", StringComparison.Ordinal)) rel = rel.Substring(2);
                rel = rel.TrimStart('\\');
                if (rel.Length > 0 && row.TryGetValue("SHA256", out var h) && h != null) _sha[rel] = h;
            }
        }

        public bool Present { get; }

        /// <summary>The integrity line for one file: matches, changed since hashing, or not in hashes.csv.</summary>
        public string Status(string fullPath, string actualSha256)
        {
            if (!Present) return "No hashes.csv in this package: integrity cannot be checked.";
            var full = Path.GetFullPath(fullPath);
            if (!full.StartsWith(_root, StringComparison.OrdinalIgnoreCase)) return "Outside the case folder.";
            var rel = full.Substring(_root.Length);
            // Only the package's own hash list is exempt; a file of the same name anywhere else is checked like any other.
            if (rel.Equals(CaseTree.CollectionFolder + @"\hashes.csv", StringComparison.OrdinalIgnoreCase) || rel.Equals(CaseTree.CollectionFolder + @"\hashes.txt", StringComparison.OrdinalIgnoreCase))
                return "The hash list itself (not listed in it).";
            if (!_sha.TryGetValue(rel, out var expected))
                return "Not in hashes.csv: written after collection (workstation output) or added later.";
            return string.Equals(expected, actualSha256, StringComparison.OrdinalIgnoreCase)
                ? "Matches hashes.csv."
                : "Changed since hashing: does not match hashes.csv.";
        }
    }
}
