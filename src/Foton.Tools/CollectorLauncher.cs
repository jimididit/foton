using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools
{
    /// <summary>
    /// A collector that passed the console's checks, ready to run. Until disposed it holds the file open for reading
    /// only (others may read and run it, nobody may write, replace, rename, or delete it), so the file Windows starts is
    /// the file that was hashed. Dispose once the process has started.
    /// </summary>
    public sealed class CollectorCheck : IDisposable
    {
        internal FileStream? Hold;
        public string Path { get; internal set; } = "";
        public string Version { get; internal set; } = "";
        public string Sha256 { get; internal set; } = "";
        /// <summary>True when SHA256SUMS.txt beside it listed this hash; false when there was no list (the operator is asked).</summary>
        public bool Verified { get; internal set; }

        public void Dispose()
        {
            Hold?.Dispose();
            Hold = null;
        }
    }

    /// <summary>What the operator chose on the Acquire tab. Null values are left to the collector's defaults.</summary>
    public sealed class AcquireRequest
    {
        public CollectorKind Kind { get; set; }
        public string? OutputPath { get; set; }
        public string? CaseNumber { get; set; }
        public string? Examiner { get; set; }
        public string? ProfilePath { get; set; }
        public bool LoadUserHives { get; set; }
    }

    /// <summary>
    /// How foton-console runs foton-collect.exe / foton-baseline.exe on this PC: which file it may run, the command line,
    /// and where the run writes. The console never collects in process; the collector is its own verified executable.
    /// </summary>
    public static class CollectorLauncher
    {
        static readonly Regex CaseFolder = new Regex(@"^Foton_.+_\d{8}-\d{6}Z$", RegexOptions.IgnoreCase);
        static readonly Regex BaselineFolder = new Regex(@"^FotonBaseline_(.+)_(\d{8}-\d{6})Z$", RegexOptions.IgnoreCase);

        public static string FileName(CollectorKind kind) => kind == CollectorKind.Collect ? "foton-collect.exe" : "foton-baseline.exe";

        /// <summary>Collect 2.8.0 reads -Profile; baseline 2.6.0 reads -LoadUserHives.</summary>
        public static Version MinimumVersion(CollectorKind kind) => kind == CollectorKind.Collect ? new Version(2, 8, 0) : new Version(2, 6, 0);

        /// <summary>
        /// A drive path (C:\...) or a UNC path (\\server\share); not relative or drive-relative (C:folder). The console and
        /// the collector start in different folders, so a relative output folder would name two places.
        /// </summary>
        public static bool IsFullPath(string path) =>
            path.StartsWith(@"\\", StringComparison.Ordinal) || (path.Length >= 3 && char.IsLetter(path[0]) && path[1] == ':' && path[2] == '\\');

        public static string DefaultOutput(CollectorKind kind) => CaseTree.DefaultOutput(kind == CollectorKind.Collect ? "Cases" : "Baselines");

        /// <summary>
        /// Refuses a file that is not this collector or is too old, and one that differs from (or is missing from) the
        /// SHA256SUMS.txt beside it. Without a list the result is unverified and the console asks the operator.
        /// </summary>
        public static CollectorCheck Check(string exePath, CollectorKind kind)
        {
            var info = new FileInfo(exePath);
            if (!info.Exists) throw new FileNotFoundException(FileName(kind) + " is not beside the console: " + exePath, exePath);
            // Held from the hash to the start (FileShare.Read): the version, the hash, and the launch see the same bytes.
            var hold = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                var v = FileVersionInfo.GetVersionInfo(info.FullName);
                var version = CheckExecutable(FileName(kind), MinimumVersion(kind), v.OriginalFilename, v.FileVersion);
                string sha;
                using (var h = System.Security.Cryptography.SHA256.Create())
                    sha = BitConverter.ToString(h.ComputeHash(hold)).Replace("-", "").ToLowerInvariant();
                var verified = Verify(System.IO.Path.Combine(info.DirectoryName!, DeploymentBundle.SumsFileName), info.Name, sha);
                return new CollectorCheck { Hold = hold, Path = info.FullName, Version = DeploymentBundle.Show(version), Sha256 = sha, Verified = verified };
            }
            catch
            {
                hold.Dispose();
                throw;
            }
        }

        static Version Full(Version v) => new Version(v.Major, v.Minor, Math.Max(v.Build, 0), Math.Max(v.Revision, 0));

        /// <summary>
        /// The executable's version when its version resource names <paramref name="expected"/> and it is at least
        /// <paramref name="minimum"/>; otherwise InvalidDataException naming why.
        /// </summary>
        internal static Version CheckExecutable(string expected, Version minimum, string? originalFilename, string? fileVersion)
        {
            if (!string.Equals(originalFilename, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"This is not {expected} (its version resource names '{originalFilename}').");
            if (!Version.TryParse(fileVersion ?? "", out var version))
                throw new InvalidDataException($"{expected} has no readable version ('{fileVersion}').");
            if (Full(version) < Full(minimum))
                throw new InvalidDataException($"{expected} {DeploymentBundle.Show(version)} is too old for the console; use {DeploymentBundle.Show(minimum)} or later.");
            return version;
        }

        /// <summary>
        /// False when there is no SHA256SUMS.txt; true when it lists the file with this hash. A list that leaves the file
        /// out, or gives another hash, is refused: the executable is not the one released with that list.
        /// </summary>
        internal static bool Verify(string sumsPath, string fileName, string sha256)
        {
            var sums = new FileInfo(sumsPath);
            if (!sums.Exists) return false;
            if (sums.Length > 64 * 1024) throw new InvalidDataException("SHA256SUMS.txt beside " + fileName + " is too large to be a release list.");
            foreach (var line in File.ReadAllLines(sums.FullName))
            {
                var m = Regex.Match(line, @"^([0-9a-fA-F]{64}) [ *](.+)$");
                if (!m.Success || !string.Equals(m.Groups[2].Value.Trim(), fileName, StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(m.Groups[1].Value, sha256, StringComparison.OrdinalIgnoreCase)) return true;
                throw new InvalidDataException($"{fileName} does not match SHA256SUMS.txt beside it (listed {m.Groups[1].Value.ToLowerInvariant()}, file is {sha256}). It is not the released file.");
            }
            throw new InvalidDataException($"SHA256SUMS.txt beside {fileName} does not list it, so the file cannot be checked against the release.");
        }

        /// <summary>The collector's command line. Values with quotes, control characters, or a leading '-' are refused.</summary>
        public static string Arguments(AcquireRequest r)
        {
            var a = new List<string>();
            void Add(string name, string? value)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                var v = value!.Trim();
                if (v.IndexOf('"') >= 0 || v.Any(char.IsControl) || v.StartsWith("-", StringComparison.Ordinal))
                    throw new ArgumentException($"{name} cannot contain quotes or control characters, or start with '-': {TextFile.OneLine(v)}");
                a.Add("-" + name);
                a.Add(v);
            }
            Add("OutputPath", r.OutputPath);
            if (r.Kind == CollectorKind.Collect)
            {
                Add("CaseNumber", r.CaseNumber);
                Add("Examiner", r.Examiner);
                Add("Profile", r.ProfilePath);
            }
            else if (r.LoadUserHives) a.Add("-LoadUserHives");
            return CommandLine.Join(a);
        }

        /// <summary>
        /// The package folder this run created: the newest matching folder created at or after the start. Null when none
        /// exists yet or the folder cannot be listed (a collector elevated as another account writes into a folder private
        /// to that account and Administrators).
        /// </summary>
        public static string? FindNewRun(string parent, CollectorKind kind, DateTime startedUtc) => NewRuns(parent, kind, startedUtc).FirstOrDefault();

        /// <summary>
        /// Every package folder created at or after the start, newest first. More than one means another collection wrote
        /// to the same folder at the same time: the console then cannot tell which is its own and says so.
        /// </summary>
        public static IReadOnlyList<string> NewRuns(string parent, CollectorKind kind, DateTime startedUtc)
        {
            var pattern = kind == CollectorKind.Collect ? CaseFolder : BaselineFolder;
            return Folders(parent)
                .Where(d => pattern.IsMatch(d.Name) && d.CreationTimeUtc >= startedUtc.AddSeconds(-2))
                .OrderByDescending(d => d.CreationTimeUtc).ThenByDescending(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .Select(d => d.FullName).ToList();
        }

        static DirectoryInfo[] Folders(string parent)
        {
            try { return Directory.Exists(parent) ? new DirectoryInfo(parent).GetDirectories() : new DirectoryInfo[0]; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException) { return new DirectoryInfo[0]; }
        }

        public static string LogPath(CollectorKind kind, string root) =>
            kind == CollectorKind.Collect ? System.IO.Path.Combine(root, CaseTree.CollectionFolder, "collection.log") : System.IO.Path.Combine(root, "baseline.log");

        /// <summary>The newest baseline of the same host older than <paramref name="newRoot"/> (by the UTC stamp in the name).</summary>
        public static string? EarlierBaseline(string parent, string newRoot)
        {
            var m = BaselineFolder.Match(System.IO.Path.GetFileName(newRoot.TrimEnd('\\')));
            if (!m.Success) return null;
            string host = m.Groups[1].Value, stamp = m.Groups[2].Value;
            return Folders(parent)
                .Select(d => new KeyValuePair<DirectoryInfo, Match>(d, BaselineFolder.Match(d.Name)))
                .Where(p => p.Value.Success && string.Equals(p.Value.Groups[1].Value, host, StringComparison.OrdinalIgnoreCase)
                    && string.CompareOrdinal(p.Value.Groups[2].Value, stamp) < 0 && File.Exists(System.IO.Path.Combine(p.Key.FullName, "baseline.json")))
                .OrderByDescending(p => p.Value.Groups[2].Value, StringComparer.Ordinal)
                .Select(p => p.Key.FullName).FirstOrDefault();
        }
    }
}
