using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools
{
    public enum CollectorKind { Collect, Baseline }

    /// <summary>A collector that passed the console's checks, ready to run.</summary>
    public sealed class CollectorCheck
    {
        public string Path { get; internal set; } = "";
        public string Version { get; internal set; } = "";
        public string Sha256 { get; internal set; } = "";
        /// <summary>True when SHA256SUMS.txt beside it listed this hash; false when there was no list (the operator is asked).</summary>
        public bool Verified { get; internal set; }
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

        public static string DefaultOutput(CollectorKind kind) => CaseTree.DefaultOutput(kind == CollectorKind.Collect ? "Cases" : "Baselines");

        /// <summary>
        /// Refuses a file that is not this collector or is too old, and one that differs from (or is missing from) the
        /// SHA256SUMS.txt beside it. Without a list the result is unverified and the console asks the operator.
        /// </summary>
        public static CollectorCheck Check(string exePath, CollectorKind kind)
        {
            var info = new FileInfo(exePath);
            if (!info.Exists) throw new FileNotFoundException(FileName(kind) + " is not beside the console: " + exePath, exePath);
            var v = FileVersionInfo.GetVersionInfo(info.FullName);
            var version = DeploymentBundle.CheckExecutable(FileName(kind), MinimumVersion(kind), v.OriginalFilename, v.FileVersion);
            var sha = Hashing.Sha256Hex(info.FullName).ToLowerInvariant();
            var verified = DeploymentBundle.Verify(System.IO.Path.Combine(info.DirectoryName!, DeploymentBundle.SumsFileName), info.Name, sha);
            return new CollectorCheck { Path = info.FullName, Version = version.ToString(3), Sha256 = sha, Verified = verified };
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

        /// <summary>The package folder this run created: the newest matching folder created at or after the start.</summary>
        public static string? FindNewRun(string parent, CollectorKind kind, DateTime startedUtc)
        {
            if (!Directory.Exists(parent)) return null;
            var pattern = kind == CollectorKind.Collect ? CaseFolder : BaselineFolder;
            return new DirectoryInfo(parent).GetDirectories()
                .Where(d => pattern.IsMatch(d.Name) && d.CreationTimeUtc >= startedUtc.AddSeconds(-2))
                .OrderByDescending(d => d.CreationTimeUtc).ThenByDescending(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .Select(d => d.FullName).FirstOrDefault();
        }

        public static string LogPath(CollectorKind kind, string root) =>
            kind == CollectorKind.Collect ? System.IO.Path.Combine(root, CaseTree.CollectionFolder, "collection.log") : System.IO.Path.Combine(root, "baseline.log");

        /// <summary>The newest baseline of the same host older than <paramref name="newRoot"/> (by the UTC stamp in the name).</summary>
        public static string? EarlierBaseline(string parent, string newRoot)
        {
            var m = BaselineFolder.Match(System.IO.Path.GetFileName(newRoot.TrimEnd('\\')));
            if (!m.Success || !Directory.Exists(parent)) return null;
            string host = m.Groups[1].Value, stamp = m.Groups[2].Value;
            return new DirectoryInfo(parent).GetDirectories()
                .Select(d => new KeyValuePair<DirectoryInfo, Match>(d, BaselineFolder.Match(d.Name)))
                .Where(p => p.Value.Success && string.Equals(p.Value.Groups[1].Value, host, StringComparison.OrdinalIgnoreCase)
                    && string.CompareOrdinal(p.Value.Groups[2].Value, stamp) < 0 && File.Exists(System.IO.Path.Combine(p.Key.FullName, "baseline.json")))
                .OrderByDescending(p => p.Value.Groups[2].Value, StringComparer.Ordinal)
                .Select(p => p.Key.FullName).FirstOrDefault();
        }
    }
}
