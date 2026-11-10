using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>A ZIP package's extraction beside it: where it is, whether this run made it, and what did not fit.</summary>
    public sealed class ZipExtractionResult
    {
        public string Folder { get; internal set; } = "";
        public string ZipSha256 { get; internal set; } = "";
        /// <summary>True when an earlier run extracted this same ZIP (matching SHA-256) and the folder was reused.</summary>
        public bool Reused { get; internal set; }
        /// <summary>Stored names of entries left out because their path would be too long for Windows.</summary>
        public List<string> NotExtracted { get; } = new List<string>();
    }

    /// <summary>
    /// Extracts a package ZIP once to &lt;name&gt;-extracted beside it, so every verb (package, parse, compose, analyze,
    /// ioc) works on one operator-visible folder and its outputs accumulate there; nothing goes to %TEMP%. A record in
    /// the folder ties it to the ZIP's SHA-256, which is re-hashed on every open: a replaced ZIP, or a folder Foton did
    /// not finish extracting, is refused rather than mixed with another package. Foton never deletes such a folder.
    /// </summary>
    public static class ZipExtraction
    {
        public const string Suffix = "-extracted";
        public const string RecordName = "foton_extraction.json";

        public static string FolderFor(string zipPath)
        {
            var full = Path.GetFullPath(zipPath);
            return Path.Combine(Path.GetDirectoryName(full) ?? "", Path.GetFileNameWithoutExtension(full) + Suffix);
        }

        public static ZipExtractionResult Ensure(string zipPath)
        {
            var zip = Path.GetFullPath(zipPath);
            var result = new ZipExtractionResult { Folder = FolderFor(zip), ZipSha256 = Hashing.Sha256Hex(zip) };
            if (Directory.Exists(result.Folder) || File.Exists(result.Folder))
                return Reuse(result, zip);

            // A short sibling name, never longer than the final leaf, so a path that fits after the rename fit while extracting.
            var parent = Path.GetDirectoryName(result.Folder)!;
            string staging;
            do staging = Path.Combine(parent, "~" + Guid.NewGuid().ToString("N").Substring(0, 10));
            while (Directory.Exists(staging) || File.Exists(staging));
            try
            {
                SafeZip.Extract(zip, staging, null, result.NotExtracted, result.Folder);
                // The record must describe the bytes extracted, so a ZIP replaced while extracting is refused.
                if (!string.Equals(Hashing.Sha256Hex(zip), result.ZipSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(Path.GetFileName(zip) + " changed while it was being extracted. Run again once it is no longer being written.");
                TextFile.Write(Path.Combine(staging, RecordName), Json.Indented(new Dictionary<string, object?>
                {
                    ["ZipFile"] = Path.GetFileName(zip),
                    ["ZipSha256"] = result.ZipSha256,
                    ["ExtractedUtc"] = FotonTime.Format(DateTime.UtcNow),
                    ["FotonVersion"] = FotonVersion.Product,
                    ["NotExtracted"] = result.NotExtracted,
                }));
                MoveWithRetry(staging, result.Folder);
            }
            catch (IOException) when (Directory.Exists(result.Folder) && Directory.Exists(staging))
            {
                // Another run finished the same extraction first: use it if it is this ZIP's.
                TryDelete(staging);
                return Reuse(result, zip);
            }
            catch
            {
                TryDelete(staging);
                throw;
            }
            return result;
        }

        static ZipExtractionResult Reuse(ZipExtractionResult result, string zip)
        {
            var record = Path.Combine(result.Folder, RecordName);
            Dictionary<string, object>? fields = null;
            try { if (File.Exists(record)) fields = Json.Parse(File.ReadAllText(record)) as Dictionary<string, object>; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is InvalidOperationException) { }
            if (fields == null || !fields.TryGetValue("ZipSha256", out var h) || !(h is string recorded))
                throw new InvalidDataException($"{result.Folder} exists but is not a completed Foton extraction of {Path.GetFileName(zip)} (no {RecordName}). Remove or rename it, then run again; or point Foton at the case folder inside it.");
            if (!string.Equals(recorded, result.ZipSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"{result.Folder} was extracted from a different ZIP (SHA-256 {recorded}; {Path.GetFileName(zip)} is now {result.ZipSha256}). Remove or rename the folder, then run again.");
            if (fields.TryGetValue("NotExtracted", out var n) && n is IEnumerable names && !(n is string))
                result.NotExtracted.AddRange(names.OfType<string>());
            result.Reused = true;
            return result;
        }

        /// <summary>
        /// Windows refuses to rename a folder while another process (typically antivirus scanning the files just written)
        /// holds one of them open, so a few short retries before the failure is reported.
        /// </summary>
        static void MoveWithRetry(string from, string to)
        {
            for (int attempt = 1; ; attempt++)
            {
                try { Directory.Move(from, to); return; }
                catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && attempt < 5 && !Directory.Exists(to))
                {
                    System.Threading.Thread.Sleep(200 * attempt);
                }
            }
        }

        static void TryDelete(string folder)
        {
            try { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
        }
    }
}
