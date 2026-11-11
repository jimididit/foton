using System;
using System.IO;
using System.Linq;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>
    /// What `foton package` and the console report about a package: how it loaded, nested cases, and whether every file
    /// listed in hashes.csv still matches. Shared so both front ends say the same thing.
    /// </summary>
    public static class PackageCheck
    {
        /// <summary>Exit-code meaning: 0 every listed hash matches, 2 a listed file changed or is missing (or no hashes.csv).</summary>
        public static int Report(StatusLog log, FotonPackage p)
        {
            if (p.ZipNote != null) log.Write(p.ZipNote, StatusLevel.Info);
            log.Write($"Loaded package {p.CaseRoot} ({p.Artifacts.Count} artifacts, {p.Manifest.Count} manifest rows, {p.Kind})", StatusLevel.Good);
            if (p.NestedDuplicate != null)
                log.Write($"This package contains a full copy of itself at {Path.GetFileName(p.NestedDuplicate)}. It is skipped so artifacts are not counted twice.", StatusLevel.Warn);
            foreach (var other in p.OtherNestedCases)
                log.Write($"This package contains another case folder, {Path.GetFileName(other)}, that is not a copy of it. Its files are not loaded as this case's artifacts; review it separately.", StatusLevel.Warn);

            var v = p.VerifyHashes();
            if (!v.HashesFilePresent)
            {
                log.Write("No 00_Collection\\hashes.csv: integrity cannot be verified for this package.", StatusLevel.Warn);
                return 2;
            }
            var where = p.Kind == PackageKind.Zip ? "hashes.csv (checked inside the ZIP)" : "hashes.csv";
            log.Write($"{where}: {v.Matched} matched, {v.Mismatched.Count} changed, {v.Missing.Count} missing, {v.Unreadable.Count} unreadable, {v.Unlisted.Count} not listed",
                v.Intact ? StatusLevel.Good : StatusLevel.Warn);
            foreach (var f in v.Mismatched.Take(20)) log.Write("Changed since hashing: " + f, StatusLevel.Warn);
            foreach (var f in v.Missing.Take(20)) log.Write("Listed but missing: " + f, StatusLevel.Warn);
            foreach (var f in v.Unreadable.Take(20)) log.Write("Could not read: " + f, StatusLevel.Warn);
            if (v.Unlisted.Count > 0)
                log.Write("Files not in hashes.csv are expected for workstation outputs written after collection (analysis\\, reports); they are not part of the hashed record.", StatusLevel.Info);
            if (p.Manifest.Count > 0 && v.Mismatched.Any(f => f.EndsWith(@"00_Collection\collection.log", StringComparison.OrdinalIgnoreCase)))
                log.Write("collection.log differs from its hash: Foton 1.38.x appended status lines after hashing, so this alone is expected for 1.38.x packages.", StatusLevel.Info);
            var extractionMatches = ExtractionMatches(log, p);
            return v.Intact && extractionMatches ? 0 : 2;
        }

        /// <summary>
        /// For a ZIP, also checks the extraction that parse, compose, and analyze read. The triage report is left out:
        /// analyze rewrites it there by design.
        /// </summary>
        static bool ExtractionMatches(StatusLog log, FotonPackage p)
        {
            if (p.Kind != PackageKind.Zip) return true;
            if (p.NotExtracted.Count > 0)
                log.Write($"{p.NotExtracted.Count} file(s) in the ZIP have paths too long to extract under {p.ExtractedTo} (packages from Foton 2.2.0 and earlier can hold long shortcut names). Their hashes were checked in the ZIP, but parse, compose, and analyze do not see them. Move the ZIP to a folder with a shorter path, delete {Path.GetFileName(p.ExtractedTo)}, and run again.", StatusLevel.Warn);
            var e = p.VerifyExtraction();
            // hashes.csv paths are relative to the case root; older packages may prefix them with .\ or \.
            var drift = e.Mismatched.Concat(e.Missing).Concat(e.Unreadable)
                .Where(f => !string.Equals(f.TrimStart('.', '\\'), CaseTree.ReportFileName, StringComparison.OrdinalIgnoreCase)).ToList();
            if (drift.Count == 0) return true;
            log.Write($"The extraction no longer matches hashes.csv for {drift.Count} file(s) that parse, compose, and analyze read. Delete {p.ExtractedTo} and run again to extract a fresh copy from the ZIP.", StatusLevel.Warn);
            foreach (var f in drift.Take(20)) log.Write("Changed in the extraction: " + f, StatusLevel.Warn);
            return false;
        }
    }
}
