using System.Collections.Generic;

namespace Foton.Core
{
    /// <summary>Case categories and their folders, in package order. Category keys are the task registry's selection keys.</summary>
    public static class CaseCategories
    {
        public static readonly IReadOnlyList<KeyValuePair<string, string>> All = new[]
        {
            new KeyValuePair<string, string>("Collection", "00_Collection"),
            new KeyValuePair<string, string>("System", "01_System"),
            new KeyValuePair<string, string>("Users", "02_Users_and_Access"),
            new KeyValuePair<string, string>("Processes", "03_Processes_and_Volatile"),
            new KeyValuePair<string, string>("Network", "04_Network"),
            new KeyValuePair<string, string>("Persistence", "05_Persistence"),
            new KeyValuePair<string, string>("Security", "06_Security_Posture"),
            new KeyValuePair<string, string>("EventLogs", "07_Event_Logs"),
            new KeyValuePair<string, string>("Filesystem", "08_Filesystem"),
            new KeyValuePair<string, string>("Software", "09_Software_and_Drivers"),
        };

        public static string FolderOf(string category)
        {
            foreach (var kv in All) if (kv.Key == category) return kv.Value;
            throw new KeyNotFoundException("Unknown case category: " + category);
        }
    }

    /// <summary>Task outcomes written to the manifest and coverage.</summary>
    public static class TaskStatus
    {
        public const string Success = "Success";
        public const string NoData = "NoData";
        public const string Error = "Error";
        public const string WriteError = "WriteError";
        public const string SkippedNotElevated = "SkippedNotElevated";
        public const string Partial = "Partial";
        public const string Failed = "Failed";
    }

    public enum TaskFormat { Json, Csv, Txt }

    /// <summary>One collection_manifest.csv row (column order is the 1.38.x order).</summary>
    public sealed class ManifestRow
    {
        public string Category { get; set; } = "";
        public string Task { get; set; } = "";
        public string Description { get; set; } = "";
        public string File { get; set; } = "";
        public int Records { get; set; }
        public string Status { get; set; } = "";
        public int DurationMs { get; set; }
        public string Error { get; set; } = "";
    }

    /// <summary>One collection_errors.csv row.</summary>
    public sealed class ErrorRow
    {
        public string Task { get; set; } = "";
        public string Error { get; set; } = "";
    }

    /// <summary>
    /// An automated observation. Tier is evidentiary strength, not urgency: 1 observed artifact,
    /// 2 supported inference, 3 unverified hypothesis (carved or uncorroborated). Never assert
    /// compromise, attribution, intent, or causation; name a benign reading in WhyItMatters.
    /// </summary>
    public sealed class Finding
    {
        public string Severity { get; set; } = "Info";
        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Observation { get; set; } = "";
        public int Tier { get; set; } = 2;
        public string WhyItMatters { get; set; } = "";
        public string Artifact { get; set; } = "";
        public string NextStep { get; set; } = "";
    }

    /// <summary>
    /// A per-file copy or save outcome (Copy-FotonHostFile, reg save). Tasks returning these rows get
    /// their manifest status from the rows: CopyError / SaveError make the task Partial or Failed.
    /// </summary>
    public interface ICopyRow
    {
        string SourcePath { get; }
        string Status { get; }
        string Note { get; }
    }
}
