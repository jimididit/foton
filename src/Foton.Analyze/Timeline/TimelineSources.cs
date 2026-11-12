using System;
using System.Collections.Generic;

namespace Foton.Analyze.Timeline
{
    /// <summary>One time column of a source and what a time there means, in words an examiner can quote.</summary>
    sealed class TimeColumn
    {
        public TimeColumn(string column, string meaning) { Column = column; Meaning = meaning; }
        public string Column { get; }
        public string Meaning { get; }
    }

    /// <summary>
    /// One timeline source: which package files it reads (a folder relative to the case root and a file pattern), which
    /// columns hold times and what each means, and how a row is summarised. Columns are looked up by name; a file
    /// without them is reported as a format the timeline does not read, never guessed at.
    /// </summary>
    sealed class TimelineSource
    {
        public string Name = "";
        public string Folder = "";
        public string Pattern = "";
        public TimeColumn[] Times = new TimeColumn[0];
        public Func<Func<string, string>, string> Summary = f => "";
        /// <summary>Hourly counters rather than events: read only with -All.</summary>
        public bool Bulk;
        /// <summary>Times written as local time by packages before Foton 2: read only from Foton 2 packages.</summary>
        public bool Foton2Only;
        /// <summary>Foton's own event-log exports: read only when EvtxECmd output is absent (the same events otherwise).</summary>
        public bool UnlessEvtxECmd;
    }

    /// <summary>
    /// The sources the timeline reads, compose outputs first. To add one, add an entry: the file, the time columns with
    /// a plain meaning each (say what the time is, not what it proves), and the summary columns.
    /// </summary>
    static class TimelineSources
    {
        static string Join(params string[] parts)
        {
            var kept = new List<string>();
            foreach (var p in parts) if (!string.IsNullOrWhiteSpace(p)) kept.Add(p.Trim());
            return string.Join("  ", kept);
        }

        static string First(Func<string, string> f, params string[] columns)
        {
            foreach (var c in columns) { var v = f(c); if (!string.IsNullOrWhiteSpace(v)) return v; }
            return "";
        }

        public static readonly TimelineSource[] All =
        {
            // Compose outputs (analysis\external): third-party parsers over copied package files.
            new TimelineSource
            {
                Name = "PECmd", Folder = @"analysis\external\pecmd", Pattern = "*_Timeline.csv",
                Times = new[] { new TimeColumn("RunTime", "Ran (Prefetch run time)") },
                Summary = f => First(f, "ExecutableName", "SourceFilename"),
            },
            new TimelineSource
            {
                Name = "EvtxECmd", Folder = @"analysis\external\evtxecmd", Pattern = "*.csv",
                Times = new[] { new TimeColumn("TimeCreated", "Event logged") },
                Summary = f => Join(f("EventId") + " " + f("Channel") + ":", f("MapDescription"), f("PayloadData1")),
            },
            new TimelineSource
            {
                Name = "Hayabusa", Folder = @"analysis\external\hayabusa", Pattern = "*.csv",
                Times = new[] { new TimeColumn("Timestamp", "Rule hit (Hayabusa)") },
                Summary = f => Join(f("Level") + ":", f("RuleTitle"), "(" + f("Channel") + " " + f("EventID") + ")"),
            },
            new TimelineSource
            {
                Name = "Chainsaw", Folder = @"analysis\external\chainsaw", Pattern = "*.csv",
                Times = new[] { new TimeColumn("timestamp", "Rule hit (Chainsaw)") },
                Summary = f => Join(f("detections"), "(event " + f("Event ID") + ")"),
            },
            new TimelineSource
            {
                Name = "LECmd", Folder = @"analysis\external\lecmd", Pattern = "*.csv",
                Times = new[]
                {
                    new TimeColumn("SourceCreated", "Shortcut file created"),
                    new TimeColumn("SourceModified", "Shortcut file modified"),
                    new TimeColumn("TargetCreated", "Target created (as recorded in the shortcut)"),
                    new TimeColumn("TargetModified", "Target modified (as recorded in the shortcut)"),
                    new TimeColumn("TargetAccessed", "Target accessed (as recorded in the shortcut)"),
                },
                Summary = f => First(f, "LocalPath", "NetworkPath", "TargetIDAbsolutePath", "SourceFile"),
            },
            new TimelineSource
            {
                Name = "JLECmd", Folder = @"analysis\external\jlecmd", Pattern = "*_AutomaticDestinations.csv",
                Times = new[]
                {
                    new TimeColumn("CreationTime", "Jump list entry created"),
                    new TimeColumn("LastModified", "Jump list entry last used"),
                    new TimeColumn("TargetModified", "Target modified (as recorded in the jump list)"),
                },
                Summary = f => Join(First(f, "Path", "LocalPath", "TargetIDAbsolutePath"), "[" + f("AppIdDescription") + "]"),
            },
            new TimelineSource
            {
                Name = "JLECmd", Folder = @"analysis\external\jlecmd", Pattern = "*_CustomDestinations.csv",
                Times = new[]
                {
                    new TimeColumn("SourceModified", "Jump list file modified"),
                    new TimeColumn("TargetModified", "Target modified (as recorded in the jump list)"),
                },
                Summary = f => Join(First(f, "LocalPath", "TargetIDAbsolutePath", "EntryName"), "[" + f("AppIdDescription") + "]"),
            },
            new TimelineSource
            {
                Name = "SBECmd", Folder = @"analysis\external\sbecmd", Pattern = "*.csv",
                Times = new[]
                {
                    new TimeColumn("FirstInteracted", "Folder first interacted with (shellbag)"),
                    new TimeColumn("LastInteracted", "Folder last interacted with (shellbag)"),
                },
                Summary = f => First(f, "AbsolutePath", "Value"),
            },
            new TimelineSource
            {
                Name = "AppCompatCacheParser", Folder = @"analysis\external\appcompatcacheparser", Pattern = "*.csv",
                Times = new[] { new TimeColumn("LastModifiedTimeUTC", "File modified (Shimcache entry; not a run time)") },
                Summary = f => f("Path"),
            },
            new TimelineSource
            {
                Name = "AmcacheParser", Folder = @"analysis\external\amcacheparser", Pattern = "*_UnassociatedFileEntries.csv",
                Times = new[] { new TimeColumn("FileKeyLastWriteTimestamp", "Amcache file entry written (presence, not proof it ran)") },
                Summary = f => First(f, "FullPath", "Name"),
            },
            new TimelineSource
            {
                Name = "AmcacheParser", Folder = @"analysis\external\amcacheparser", Pattern = "*_DriverBinaries.csv",
                Times = new[] { new TimeColumn("KeyLastWriteTimestamp", "Amcache driver entry written") },
                Summary = f => Join(f("DriverName"), f("DriverCompany")),
            },
            new TimelineSource
            {
                Name = "AmcacheParser", Folder = @"analysis\external\amcacheparser", Pattern = "*_ShortCuts.csv",
                Times = new[] { new TimeColumn("KeyLastWriteTimestamp", "Amcache shortcut entry written") },
                Summary = f => First(f, "ShortcutTargetPath", "LnkName"),
            },
            new TimelineSource
            {
                Name = "RECmd", Folder = @"analysis\external\recmd", Pattern = "recmd.csv",
                Times = new[] { new TimeColumn("LastWriteTimestamp", "Registry key last written") },
                Summary = f => Join(f("Description") + ":", f("KeyPath"), f("ValueName")),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_NetworkConnections_Output.csv",
                Times = new[] { new TimeColumn("ConnectStartTime", "Network connection started (SRUM)") },
                Summary = f => Join(f("ExeInfo"), f("ProfileName")),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_NetworkUsages_Output.csv",
                Times = new[] { new TimeColumn("Timestamp", "Network use in the hour starting here (SRUM)") },
                Summary = f => Join(f("ExeInfo"), "sent " + f("BytesSent"), "received " + f("BytesReceived")),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_AppResourceUseInfo_Output.csv", Bulk = true,
                Times = new[] { new TimeColumn("Timestamp", "Resource use in the hour starting here (SRUM)") },
                Summary = f => f("ExeInfo"),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_AppTimelineProvider_Output.csv", Bulk = true,
                Times = new[] { new TimeColumn("Timestamp", "App in use in the period starting here (SRUM)") },
                Summary = f => f("ExeInfo"),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_EnergyUsage_Output.csv", Bulk = true,
                Times = new[] { new TimeColumn("Timestamp", "Energy use recorded (SRUM)") },
                Summary = f => f("ExeInfo"),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_PushNotifications_Output.csv", Bulk = true,
                Times = new[] { new TimeColumn("Timestamp", "Push notification recorded (SRUM)") },
                Summary = f => f("ExeInfo"),
            },
            new TimelineSource
            {
                Name = "SrumECmd", Folder = @"analysis\external\srumecmd", Pattern = "*_SrumECmd_vfuprov_Output.csv", Bulk = true,
                Times = new[] { new TimeColumn("StartTime", "Usage period started (SRUM vfuprov)") },
                Summary = f => f("ExeInfo"),
            },
            new TimelineSource
            {
                Name = "MFTECmd", Folder = @"analysis\external\mftecmd", Pattern = "*.csv",
                Times = new[] { new TimeColumn("UpdateTimestamp", "File system change recorded (USN journal)") },
                Summary = f => Join((f("ParentPath").Length > 0 ? f("ParentPath").TrimEnd('\\') + "\\" : "") + f("Name"), "[" + f("UpdateReasons") + "]"),
            },

            // Foton's own collected CSVs (UTC in Foton 2 packages).
            new TimelineSource
            {
                Name = "Foton", Folder = "03_Processes_and_Volatile", Pattern = "running_processes.csv",
                Times = new[] { new TimeColumn("CreationTimeUtc", "Process started (still running at collection)") },
                Summary = f => Join(f("Name"), f("Path")),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "05_Persistence", Pattern = "scheduled_tasks.csv", Foton2Only = true,
                Times = new[] { new TimeColumn("LastRunTime", "Scheduled task last ran") },
                Summary = f => Join(f("TaskPath") + f("TaskName"), f("Actions")),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "06_Security_Posture", Pattern = "defender_detections.csv",
                Times = new[] { new TimeColumn("InitialDetectionTimeUtc", "Defender detection first recorded") },
                Summary = f => Join(f("ThreatID"), f("Resources"), f("ProcessName")),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "06_Security_Posture", Pattern = "defender_detections.csv", Foton2Only = true,
                Times = new[] { new TimeColumn("LastThreatStatusChangeTime", "Defender detection status changed") },
                Summary = f => Join(f("ThreatID"), f("ThreatStatus"), f("Resources")),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "08_Filesystem", Pattern = "bam_dam_user_settings.csv",
                Times = new[] { new TimeColumn("LastExecuteUtc", "Last run (BAM/DAM)") },
                Summary = f => f("Path"),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "08_Filesystem", Pattern = "recycle_bin_contents.csv",
                Times = new[] { new TimeColumn("DeletedUtc", "Deleted to the Recycle Bin") },
                Summary = f => First(f, "FileName", "FullName"),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "08_Filesystem", Pattern = "recently_modified_system_files.csv",
                Times = new[]
                {
                    new TimeColumn("CreatedUtc", "System file created"),
                    new TimeColumn("ModifiedUtc", "System file modified"),
                },
                Summary = f => f("Path"),
            },
            new TimelineSource
            {
                Name = "Foton", Folder = "07_Event_Logs", Pattern = "*.csv", UnlessEvtxECmd = true,
                Times = new[] { new TimeColumn("TimeCreatedUtc", "Event logged") },
                Summary = f => Join(f("EventId") + " " + f("Log") + ":", FirstLine(f("Message"))),
            },
        };

        static string FirstLine(string s)
        {
            var i = s.IndexOfAny(new[] { '\r', '\n' });
            return i < 0 ? s : s.Substring(0, i);
        }
    }
}
