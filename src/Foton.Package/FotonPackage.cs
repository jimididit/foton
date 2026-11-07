using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Package
{
    public enum PackageKind { Folder, Zip }

    public enum ArtifactKind { Json, Csv, Txt }

    /// <summary>One loaded artifact file. Exactly one of Json / Rows / Lines is set, by Kind.</summary>
    public sealed class Artifact
    {
        public string Name { get; internal set; } = "";
        public string Path { get; internal set; } = "";
        public ArtifactKind Kind { get; internal set; }
        /// <summary>Parsed JSON graph (Dictionary&lt;string, object&gt;, object[], primitives).</summary>
        public object? Json { get; internal set; }
        /// <summary>CSV rows. Values stay strings; "True"/"False" are compared with Bool().</summary>
        public IReadOnlyList<Dictionary<string, string?>> Rows { get; internal set; } = new Dictionary<string, string?>[0];
        public IReadOnlyList<string> Lines { get; internal set; } = new string[0];

        /// <summary>Import-Csv kept True/False as text and 1.38.x analysis converted them; this is that test.</summary>
        public static bool Bool(Dictionary<string, string?> row, string column) =>
            row.TryGetValue(column, out var v) && string.Equals(v, "True", StringComparison.Ordinal);
    }

    /// <summary>
    /// An already-collected Foton or WinFoton case (folder or ZIP), loaded for offline work
    /// (Get-FotonPackage / Import-FotonPackageData). Never reads the live host; never modifies the package.
    /// </summary>
    public sealed class FotonPackage
    {
        public string SourcePath { get; private set; } = "";
        public PackageKind Kind { get; private set; }
        public string CaseRoot { get; private set; } = "";
        /// <summary>The temporary folder a ZIP was extracted to (null for folders); remove with DeleteExtraction.</summary>
        public string? ExtractedTo { get; private set; }

        /// <summary>Deletes the temporary ZIP extraction. Never touches a folder package.</summary>
        public void DeleteExtraction()
        {
            if (ExtractedTo == null || !Directory.Exists(ExtractedTo)) return;
            try { Directory.Delete(ExtractedTo, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        /// <summary>A verified full copy of the case nested inside it, skipped by every recursive walk.</summary>
        public string? NestedDuplicate { get; private set; }
        /// <summary>
        /// Other case folders embedded in this one (not a verified copy). Not loaded as this case's artifacts,
        /// so they cannot override them; their files stay visible to VerifyHashes as unlisted.
        /// </summary>
        public IReadOnlyList<string> OtherNestedCases { get; private set; } = new string[0];
        /// <summary>From the folder name (..._yyyyMMdd-HHmmssZ), when present.</summary>
        public DateTime? StartTimeUtc { get; private set; }
        public IReadOnlyList<Dictionary<string, string?>> Manifest { get; private set; } = new Dictionary<string, string?>[0];
        public IReadOnlyList<Dictionary<string, string?>> Errors { get; private set; } = new Dictionary<string, string?>[0];
        /// <summary>Artifacts by file name without extension (as session Data was keyed).</summary>
        public IReadOnlyDictionary<string, Artifact> Artifacts { get; private set; } = new Dictionary<string, Artifact>();

        // Package bookkeeping and generated outputs: not collect tasks.
        static readonly HashSet<string> SkipNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "hashes.csv", "hashes.txt", "findings.csv", "collection.log",
            "chain_of_custody.txt", "collection_manifest.csv", "collection_errors.csv",
        };

        static readonly Regex SkipDirs = new Regex(@"[\\/](evtx|analysis)([\\/]|$)", RegexOptions.IgnoreCase);
        static readonly Regex Stamp = new Regex(@"_(20\d{6}-\d{6})Z$");

        /// <summary>
        /// Opens a case folder (or a parent holding one), or extracts a ZIP to a fresh folder under
        /// <paramref name="extractRoot"/> (default %TEMP%). Throws when no 00_Collection is found.
        /// </summary>
        public static FotonPackage Open(string path, string? extractRoot = null)
        {
            var p = new FotonPackage { SourcePath = Path.GetFullPath(path) };
            string search;
            if (File.Exists(path) && string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase))
            {
                p.Kind = PackageKind.Zip;
                search = Path.Combine(extractRoot ?? Path.GetTempPath(), "FotonPkg-" + Guid.NewGuid().ToString("N"));
                p.ExtractedTo = search;
                try { SafeZip.Extract(path, search); }
                catch { p.DeleteExtraction(); throw; }
            }
            else if (Directory.Exists(path))
            {
                p.Kind = PackageKind.Folder;
                search = p.SourcePath;
            }
            else throw new FileNotFoundException("Package path not found: " + path, path);

            var root = CaseTree.FindCaseRoot(search);
            if (root == null)
            {
                p.DeleteExtraction();
                throw new InvalidDataException("No 00_Collection folder under " + search + ". Point at an extracted WinFoton/Foton case.");
            }
            p.CaseRoot = root;
            p.NestedDuplicate = CaseTree.FindNestedDuplicate(p.CaseRoot);
            p.OtherNestedCases = CaseTree.OtherChildCases(p.CaseRoot);
            p.Load();
            return p;
        }

        void Load()
        {
            var col = Path.Combine(CaseRoot, CaseTree.CollectionFolder);
            var manifest = Path.Combine(col, "collection_manifest.csv");
            if (File.Exists(manifest)) Manifest = Csv.Read(manifest);
            var errors = Path.Combine(col, "collection_errors.csv");
            if (File.Exists(errors)) Errors = Csv.Read(errors);

            var artifacts = new Dictionary<string, Artifact>(StringComparer.OrdinalIgnoreCase);
            // Ordinal path order so "same name in two folders" resolves the same way on every run (last wins).
            var files = Directory.GetFiles(CaseRoot, "*", SearchOption.AllDirectories)
                .Where(f => !CaseTree.IsUnder(f, NestedDuplicate) && !OtherNestedCases.Any(c => CaseTree.IsUnder(f, c)))
                .Where(f => Regex.IsMatch(Path.GetExtension(f), @"^\.(json|csv|txt)$", RegexOptions.IgnoreCase))
                .Where(f => !SkipNames.Contains(Path.GetFileName(f)))
                .Where(f => !SkipDirs.IsMatch(Path.GetDirectoryName(f)!.Substring(CaseRoot.Length)))
                .OrderBy(f => f, StringComparer.Ordinal);
            foreach (var f in files)
            {
                var a = LoadArtifact(f);
                if (a != null) artifacts[a.Name] = a;
            }
            Artifacts = artifacts;

            var m = Stamp.Match(Path.GetFileName(CaseRoot));
            if (m.Success && DateTime.TryParseExact(m.Groups[1].Value, "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
                StartTimeUtc = t;
        }

        /// <summary>
        /// Null for skip/no-data text files ("Foton:" / "WinFoton:" sentinel first line), empty JSON, or
        /// unreadable content: a failed load is not data.
        /// </summary>
        static Artifact? LoadArtifact(string path)
        {
            try
            {
                var lines = TextFile.ReadLines(path);
                if (lines.Length > 0 && Regex.IsMatch(lines[0], "^(Foton|WinFoton):")) return null;
                var a = new Artifact { Name = Path.GetFileNameWithoutExtension(path), Path = path };
                switch (Path.GetExtension(path).ToLowerInvariant())
                {
                    case ".json":
                        var raw = string.Join("\n", lines);
                        if (string.IsNullOrWhiteSpace(raw)) return null;
                        a.Kind = ArtifactKind.Json;
                        a.Json = Core.Json.Parse(raw);
                        return a;
                    case ".csv":
                        a.Kind = ArtifactKind.Csv;
                        a.Rows = Csv.Read(path);
                        return a;
                    default:
                        a.Kind = ArtifactKind.Txt;
                        a.Lines = lines;
                        return a;
                }
            }
            catch (Exception) { return null; }
        }

        /// <summary>Re-hashes every file listed in 00_Collection\hashes.csv against the bytes on disk.</summary>
        public HashVerification VerifyHashes()
        {
            var csv = Path.Combine(CaseRoot, CaseTree.CollectionFolder, "hashes.csv");
            var v = new HashVerification { HashesFile = csv, HashesFilePresent = File.Exists(csv) };
            if (!v.HashesFilePresent) return v;
            var listed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in Csv.Read(csv))
            {
                // Older packages wrote forward slashes; compare on one separator.
                var rel = (row.TryGetValue("RelativePath", out var r) ? r ?? "" : "").Replace('/', '\\');
                var expected = row.TryGetValue("SHA256", out var h) ? h ?? "" : "";
                listed.Add(rel);
                var full = Path.GetFullPath(Path.Combine(CaseRoot, rel));
                if (!full.StartsWith(CaseRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                { v.Mismatched.Add(rel + " (path outside the case)"); continue; }
                if (!File.Exists(full)) { v.Missing.Add(rel); continue; }
                string actual;
                try { actual = Hashing.Sha256Hex(full); } catch (Exception) { v.Unreadable.Add(rel); continue; }
                if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) v.Matched++;
                else v.Mismatched.Add(rel);
            }
            foreach (var f in Directory.GetFiles(CaseRoot, "*", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (CaseTree.IsUnder(f, NestedDuplicate)) continue;
                var rel = f.Substring(CaseRoot.Length).TrimStart('\\');
                var name = Path.GetFileName(f);
                if (name == "hashes.csv" || name == "hashes.txt" || listed.Contains(rel)) continue;
                v.Unlisted.Add(rel);
            }
            return v;
        }
    }

    /// <summary>
    /// Result of re-hashing a package. Unlisted files are expected for workstation outputs written after
    /// collection (analysis\, re-rendered reports); a Mismatched or Missing listed file is not.
    /// </summary>
    public sealed class HashVerification
    {
        public string HashesFile { get; internal set; } = "";
        public bool HashesFilePresent { get; internal set; }
        public int Matched { get; internal set; }
        public List<string> Mismatched { get; } = new List<string>();
        public List<string> Missing { get; } = new List<string>();
        public List<string> Unreadable { get; } = new List<string>();
        public List<string> Unlisted { get; } = new List<string>();
        public bool Intact => HashesFilePresent && Mismatched.Count == 0 && Missing.Count == 0 && Unreadable.Count == 0;
    }
}
