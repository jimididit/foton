using System;
using System.Collections.Generic;
using System.IO;

namespace Foton.Core
{
    /// <summary>Operator switches for one run (the flatten / Invoke-FotonTriage parameters).</summary>
    public sealed class SessionOptions
    {
        public string OutputPath { get; set; } = "";
        public string CaseNumber { get; set; } = "";
        public string Examiner { get; set; } = "";
        public int EventLogDays { get; set; } = 14;
        public int MaxEventsPerLog { get; set; } = 3000;
        public bool SkipEvtxExport { get; set; }
        public bool SkipHashing { get; set; }
        public bool LoadUserHives { get; set; }
        public bool IncludeFileTimeline { get; set; }
        public bool IncludeUsnJournal { get; set; }
        public bool Deep { get; set; }
        public bool NoZip { get; set; }
        public bool RequireAdministrator { get; set; }
        /// <summary>-Profile / -Category selection; null collects every category.</summary>
        public CollectionProfile? Profile { get; set; }
    }

    /// <summary>
    /// State of one collection or baseline run. Replaces $script:FotonSession. Facts about the live
    /// host (hostname, account, elevation) are supplied by the caller, so Core never touches the host.
    /// </summary>
    public sealed class FotonSession
    {
        public FotonSession(SessionOptions options, DateTime startTimeUtc, string hostname, string account, bool isElevated, StatusLog? status = null)
        {
            Options = options;
            StartTimeUtc = DateTime.SpecifyKind(startTimeUtc, DateTimeKind.Utc);
            Hostname = hostname;
            Account = account;
            IsElevated = isElevated;
            Status = status ?? new StatusLog();
        }

        public SessionOptions Options { get; }
        public string Version { get; } = FotonVersion.Product;
        public DateTime StartTimeUtc { get; }
        public string Hostname { get; }
        /// <summary>DOMAIN\user that ran the collection.</summary>
        public string Account { get; }
        public bool IsElevated { get; }
        public StatusLog Status { get; }

        public string? CaseRoot { get; internal set; }
        public Dictionary<string, string> Dirs { get; } = new Dictionary<string, string>();
        public string? LogFile => Status.LogFile;

        public List<ManifestRow> Manifest { get; } = new List<ManifestRow>();
        public List<ErrorRow> Errors { get; } = new List<ErrorRow>();
        public List<Finding> Findings { get; } = new List<Finding>();

        /// <summary>Task results kept for later tasks and in-run analysis (Data[name]).</summary>
        public Dictionary<string, object?> Data { get; } = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Folders the profile scans skipped as earlier Foton packages (forgeable, so disclosed).</summary>
        public List<string> ExcludedEarlierPackages { get; } = new List<string>();
        public bool LoadUserHivesActive { get; set; }

        public string Dir(string category) =>
            Dirs.TryGetValue(category, out var d) ? d : throw new InvalidOperationException("Case folders are not created yet (call CaseLayout.Create).");
    }

    /// <summary>
    /// Creates FotonBaseline_&lt;host&gt;_&lt;yyyyMMdd-HHmmss&gt;Z. A baseline package is flat: baseline.json,
    /// coverage.json, baseline.log, and the hash files all sit in the package root.
    /// </summary>
    public static class BaselineLayout
    {
        public static string FolderName(string hostname, DateTime startUtc) => "FotonBaseline_" + hostname + "_" + FotonTime.Stamp(startUtc) + "Z";

        public static string Create(FotonSession session, string outputPath)
        {
            Directory.CreateDirectory(outputPath);
            var root = Path.Combine(outputPath, FolderName(session.Hostname, session.StartTimeUtc));
            Directory.CreateDirectory(root);
            session.CaseRoot = root;
            session.Dirs["Collection"] = root;
            var log = Path.Combine(root, "baseline.log");
            TextFile.Write(log, "Foton " + session.Version + " baseline capture log");
            session.Status.LogFile = log;
            return root;
        }
    }

    /// <summary>Creates Foton_&lt;host&gt;_&lt;yyyyMMdd-HHmmss&gt;Z with the ten category folders and collection.log.</summary>
    public static class CaseLayout
    {
        public static string FolderName(string hostname, DateTime startUtc) => "Foton_" + hostname + "_" + FotonTime.Stamp(startUtc) + "Z";

        public static string Create(FotonSession session, string outputPath)
        {
            Directory.CreateDirectory(outputPath);
            var root = Path.Combine(outputPath, FolderName(session.Hostname, session.StartTimeUtc));
            Directory.CreateDirectory(root);
            session.CaseRoot = root;
            foreach (var kv in CaseCategories.All)
            {
                var dir = Path.Combine(root, kv.Value);
                Directory.CreateDirectory(dir);
                session.Dirs[kv.Key] = dir;
            }
            var log = Path.Combine(session.Dirs["Collection"], "collection.log");
            TextFile.Write(log, "Foton " + session.Version + " collection log");
            session.Status.LogFile = log;
            return root;
        }
    }
}
