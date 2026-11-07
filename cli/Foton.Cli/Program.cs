using System;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Cli
{
    static class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 1 && IsVersionSwitch(args[0]))
            {
                foreach (var line in FotonVersion.Describe("foton")) Console.WriteLine(line);
                return 0;
            }
            if (args.Length == 2 && string.Equals(args[0], "package", StringComparison.OrdinalIgnoreCase))
                return PackageCommand(args[1]);

            foreach (var line in FotonVersion.Describe("foton")) Console.WriteLine(line);
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  foton -Version");
            Console.WriteLine("  foton package <case-folder-or-zip>   open a package and verify hashes.csv");
            Console.WriteLine();
            Console.WriteLine("Parse, compose, analyze, and compare are not implemented in this v2 pre-release.");
            Console.WriteLine("For casework use Foton 1.38.x (the Foton-Workstation_v1.38.1.zip module) from https://github.com/jimididit/foton/releases.");
            return 1;
        }

        /// <summary>Exit 0 when every listed hash matches, 2 when any listed file changed or is missing, 1 on open failure.</summary>
        static int PackageCommand(string path)
        {
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            FotonPackage p;
            try { p = FotonPackage.Open(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException)
            {
                log.Write("Cannot open package: " + ex.Message, StatusLevel.Error);
                return 1;
            }

            try { return Report(log, p); }
            finally { p.DeleteExtraction(); }
        }

        static int Report(StatusLog log, FotonPackage p)
        {
            log.Write($"Loaded package {p.CaseRoot} ({p.Artifacts.Count} artifacts, {p.Manifest.Count} manifest rows, {p.Kind})", StatusLevel.Good);
            if (p.Kind == PackageKind.Zip)
                log.Write("ZIP verified from a temporary extraction that is removed afterwards; chain parse/compose/analyze on an extracted folder.", StatusLevel.Info);
            if (p.NestedDuplicate != null)
                log.Write($"This package contains a full copy of itself at {Path.GetFileName(p.NestedDuplicate)}. It is skipped so artifacts are not counted twice.", StatusLevel.Warn);

            var v = p.VerifyHashes();
            if (!v.HashesFilePresent)
            {
                log.Write("No 00_Collection\\hashes.csv: integrity cannot be verified for this package.", StatusLevel.Warn);
                return 2;
            }
            log.Write($"hashes.csv: {v.Matched} matched, {v.Mismatched.Count} changed, {v.Missing.Count} missing, {v.Unreadable.Count} unreadable, {v.Unlisted.Count} not listed",
                v.Intact ? StatusLevel.Good : StatusLevel.Warn);
            foreach (var f in v.Mismatched.Take(20)) log.Write("Changed since hashing: " + f, StatusLevel.Warn);
            foreach (var f in v.Missing.Take(20)) log.Write("Listed but missing: " + f, StatusLevel.Warn);
            foreach (var f in v.Unreadable.Take(20)) log.Write("Could not read: " + f, StatusLevel.Warn);
            if (v.Unlisted.Count > 0)
                log.Write("Files not in hashes.csv are expected for workstation outputs written after collection (analysis\\, reports); they are not part of the hashed record.", StatusLevel.Info);
            if (p.Manifest.Count > 0 && v.Mismatched.Any(f => f.EndsWith(@"00_Collection\collection.log", StringComparison.OrdinalIgnoreCase)))
                log.Write("collection.log differs from its hash: Foton 1.38.x appended status lines after hashing, so this alone is expected for 1.38.x packages.", StatusLevel.Info);
            return v.Intact ? 0 : 2;
        }

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
