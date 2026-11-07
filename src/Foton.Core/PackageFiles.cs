using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace Foton.Core
{
    /// <summary>One hashes.csv row.</summary>
    public sealed class HashRow
    {
        public string RelativePath { get; set; } = "";
        public long SizeBytes { get; set; }
        public string SHA256 { get; set; } = "";
        public string ModifiedUtc { get; set; } = "";
    }

    /// <summary>End-of-run package files: manifest, errors, findings, hashes, ZIP, package integrity record.</summary>
    public static class PackageFiles
    {
        public static void WriteManifestFiles(FotonSession s)
        {
            var dir = s.Dir("Collection");
            Csv.Write(Path.Combine(dir, "collection_manifest.csv"), s.Manifest);
            if (s.Findings.Count > 0) Csv.Write(Path.Combine(dir, "findings.csv"), s.Findings);
            if (s.Errors.Count > 0) Csv.Write(Path.Combine(dir, "collection_errors.csv"), s.Errors);
        }

        /// <summary>
        /// SHA-256 of every file in the case (except the hash files and a nested duplicate tree), written
        /// to hashes.csv and hashes.txt. Rows are in ordinal path order so the file is the same on every run.
        /// </summary>
        public static int WriteArtifactHashes(FotonSession s)
        {
            s.Status.Write("Hashing collected artifacts (SHA-256)", StatusLevel.Step);
            // Hashing is the last write into the case: close the log first so its hash stays valid.
            s.Status.Seal("collection.log closed before hashing; later status lines are console-only.");
            var root = s.CaseRoot ?? throw new InvalidOperationException("No case root.");
            var rows = HashTree(root);
            var dir = s.Dir("Collection");
            Csv.Write(Path.Combine(dir, "hashes.csv"), rows);
            var txt = new List<string>
            {
                "Foton artifact hashes (SHA-256) - generated " + FotonTime.Format(s.Status.UtcNow()) + " UTC",
                "",
            };
            txt.AddRange(rows.Select(r => r.SHA256 + "  " + r.RelativePath));
            TextFile.WriteLines(Path.Combine(dir, "hashes.txt"), txt);
            s.Status.Write($"Hashed {rows.Count} artifacts", StatusLevel.Good);
            return rows.Count;
        }

        public static List<HashRow> HashTree(string root)
        {
            var nested = CaseTree.FindNestedDuplicate(root);
            var rows = new List<HashRow>();
            foreach (var path in Directory.GetFiles(root, "*", SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal))
            {
                var name = Path.GetFileName(path);
                if (name == "hashes.csv" || name == "hashes.txt") continue;
                if (CaseTree.IsUnder(path, nested)) continue;
                var fi = new FileInfo(path);
                string hash;
                try { hash = Hashing.Sha256Hex(path); } catch (Exception) { hash = "HASH_ERROR"; }
                rows.Add(new HashRow
                {
                    RelativePath = path.Substring(root.Length).TrimStart('\\'),
                    SizeBytes = fi.Length,
                    SHA256 = hash,
                    ModifiedUtc = FotonTime.Format(fi.LastWriteTimeUtc),
                });
            }
            return rows;
        }

        /// <summary>
        /// &lt;case&gt;.zip with the case folder as the top-level entry. A nested copy of the case is left
        /// out (and reported) rather than doubling the transfer. Returns null on failure; the folder remains.
        /// </summary>
        public static string? CompressCase(FotonSession s)
        {
            s.Status.Write("Compressing case package", StatusLevel.Step);
            var root = s.CaseRoot ?? throw new InvalidOperationException("No case root.");
            var zipPath = root + ".zip";
            var nested = CaseTree.FindNestedDuplicate(root);
            if (nested != null)
                s.Status.Write($"Case folder contains a nested copy of itself at {Path.GetFileName(nested)}. It is excluded from the ZIP; the collected tree is unaffected.", StatusLevel.Warn);
            try
            {
                if (File.Exists(zipPath)) File.Delete(zipPath);
                var top = Path.GetFileName(root);
                using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
                {
                    foreach (var path in Directory.GetFiles(root, "*", SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal))
                    {
                        if (CaseTree.IsUnder(path, nested)) continue;
                        var entry = top + "/" + path.Substring(root.Length).TrimStart('\\').Replace('\\', '/');
                        zip.CreateEntryFromFile(path, entry, CompressionLevel.Optimal);
                    }
                }
                return zipPath;
            }
            catch (Exception ex)
            {
                s.Status.Write($"Compression failed: {ex.Message}. The uncompressed case folder is still available.", StatusLevel.Warn);
                return null;
            }
        }

        /// <summary>&lt;case&gt;_PACKAGE_HASH.txt beside the ZIP: the hash to verify at every custody transfer.</summary>
        public static string WritePackageHashRecord(FotonSession s, string zipPath)
        {
            string hash;
            try { hash = Hashing.Sha256Hex(zipPath); } catch (Exception) { hash = "HASH_ERROR"; }
            var mb = Math.Round(new FileInfo(zipPath).Length / 1048576.0, 2).ToString(CultureInfo.InvariantCulture);
            var lines = new[]
            {
                "Foton package integrity record",
                "",
                "Package      : " + Path.GetFileName(zipPath),
                "SHA-256      : " + hash,
                "Size (MB)    : " + mb,
                "Created UTC  : " + FotonTime.Format(s.Status.UtcNow()),
                "Host         : " + s.Hostname,
                "Examiner     : " + s.Options.Examiner,
                "Case         : " + s.Options.CaseNumber,
                "",
                "Record this hash on receipt and verify it at every custody transfer:",
                "  Get-FileHash -Algorithm SHA256 <package.zip>",
            };
            TextFile.WriteLines(s.CaseRoot + "_PACKAGE_HASH.txt", lines);
            return hash;
        }
    }
}
