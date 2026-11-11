using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>
    /// Selected Event IDs from the main and operational logs, log configuration, and a time-filtered raw EVTX export
    /// (Invoke-FotonEventLogCollection). Rows are the events as recorded; Analyze decides what they mean.
    /// To add a query, add a line to Queries; to export another log, add it to ExportLogs.
    /// </summary>
    public static class EventLogCollection
    {
        const string Cat = "EventLogs";
        const int MaxMessage = 2000;

        sealed class Query
        {
            public Query(string name, string log, int[] ids, string description) { Name = name; Log = log; Ids = ids; Description = description; }
            public string Name { get; }
            public string Log { get; }
            public int[] Ids { get; }
            public string Description { get; }
        }

        static readonly Query[] Queries =
        {
            new Query("security_logon_events", "Security", new[] { 4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779 }, "Logon success/failure, explicit credential use, privilege assignment"),
            new Query("security_account_management", "Security", new[] { 4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4767, 4781 }, "Account creation, modification, group membership changes"),
            new Query("security_process_creation", "Security", new[] { 4688, 4689 }, "Process creation/termination (requires audit policy enabled)"),
            new Query("security_policy_and_log_changes", "Security", new[] { 1102, 4719, 4739, 4907, 4912 }, "Audit log cleared and audit policy changes"),
            new Query("security_object_and_share_access", "Security", new[] { 5140, 5142, 5143, 5144, 5145, 4663, 4656 }, "Share and object access events"),
            new Query("security_scheduled_task_and_service", "Security", new[] { 4697, 4698, 4699, 4700, 4701, 4702 }, "Service installation and scheduled task changes"),
            new Query("security_kerberos_ntlm", "Security", new[] { 4768, 4769, 4771, 4776 }, "Kerberos/NTLM authentication events"),
            new Query("system_service_and_driver", "System", new[] { 7045, 7040, 7034, 7031, 7036, 219, 41, 1001 }, "Service install/state change, driver load, unexpected shutdown"),
            new Query("system_log_and_boot", "System", new[] { 104, 6005, 6006, 6008, 6013, 1074 }, "Log clearing, boot, shutdown events"),
            new Query("powershell_operational", "Microsoft-Windows-PowerShell/Operational", new[] { 4103, 4104, 53504 }, "PowerShell script block and module logging"),
            new Query("powershell_classic", "Windows PowerShell", new[] { 400, 403, 600, 800 }, "Classic PowerShell engine lifecycle and provider events"),
            new Query("defender_operational", "Microsoft-Windows-Windows Defender/Operational", new[] { 1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012 }, "Defender detections, actions, and configuration changes"),
            new Query("task_scheduler_operational", "Microsoft-Windows-TaskScheduler/Operational", new[] { 106, 129, 140, 141, 200, 201 }, "Task registration, deletion, and execution"),
            new Query("terminal_services_local", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", new[] { 21, 22, 23, 24, 25, 39, 40 }, "RDP session connect/disconnect/reconnect"),
            new Query("terminal_services_remote", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", new[] { 1149, 1148 }, "RDP authentication attempts with source IP"),
            new Query("wmi_activity", "Microsoft-Windows-WMI-Activity/Operational", new[] { 5857, 5858, 5859, 5860, 5861 }, "WMI provider and permanent subscription activity"),
            new Query("windows_firewall", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", new[] { 2003, 2004, 2005, 2006, 2033 }, "Firewall rule and profile changes"),
            new Query("bits_client", "Microsoft-Windows-Bits-Client/Operational", new[] { 3, 4, 59, 60 }, "BITS transfer jobs (download activity)"),
            new Query("app_crashes", "Application", new[] { 1000, 1001, 1002 }, "Application crash and hang reports"),
            new Query("sysmon_operational", "Microsoft-Windows-Sysmon/Operational", new[] { 1, 3, 6, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25 }, "Sysmon telemetry if Sysmon is deployed"),
        };

        static readonly string[] ConfigLogs =
        {
            "Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-WMI-Activity/Operational",
        };

        static readonly string[] ExportLogs =
        {
            "Security", "System", "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Bits-Client/Operational",
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        };

        public static void Run(FotonSession s)
        {
            var days = s.Options.EventLogDays;
            var max = s.Options.MaxEventsPerLog;
            s.Status.Write($"Collecting event logs (last {days} days, max {max} per query)", StatusLevel.Step);
            var startUtc = DateTime.UtcNow.AddDays(-days);
            foreach (var q in Queries)
                Task(s, Cat, q.Name, q.Description, TaskFormat.Csv, () => Events(q, startUtc, max), elevated: q.Log == "Security");
            Task(s, Cat, "event_log_configuration", "Log size, retention, and enablement (gap analysis)", TaskFormat.Csv, LogConfiguration);
            ExportEvtx(s, days);
        }

        /// <summary>The structured query Get-WinEvent -FilterHashtable @{ LogName; Id; StartTime } builds.</summary>
        internal static string XPath(IEnumerable<int> ids, DateTime startUtc) =>
            "*[System[(" + string.Join(" or ", ids.Select(i => "EventID=" + i.ToString(CultureInfo.InvariantCulture))) + ") and TimeCreated[@SystemTime>='"
            + startUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) + "']]]";

        /// <summary>
        /// Newest first, capped, then sorted by time (newest first; equal seconds keep log order).
        /// A log that does not exist is no data. Access denied is an error, not an empty log: absence is not evidence.
        /// </summary>
        static object Events(Query q, DateTime startUtc, int max)
        {
            var rows = new List<Dictionary<string, object?>>();
            try
            {
                using (var reader = new EventLogReader(new EventLogQuery(q.Log, PathType.LogName, XPath(q.Ids, startUtc)) { ReverseDirection = true }))
                {
                    while (rows.Count < max)
                    {
                        var e = reader.ReadEvent();
                        if (e == null) break;
                        using (e) rows.Add(Row(e, q.Log));
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            return rows.OrderByDescending(r => (string)r["TimeCreatedUtc"]!, StringComparer.Ordinal).ToList();
        }

        /// <summary>ConvertTo-FotonEventRow: message capped at 2000 characters, then whitespace runs collapsed.</summary>
        internal static Dictionary<string, object?> Row(EventRecord e, string log)
        {
            var msg = "";
            try { msg = e.FormatDescription() ?? ""; }
            catch (EventLogException) { }
            return new Dictionary<string, object?>
            {
                ["TimeCreatedUtc"] = e.TimeCreated is DateTime t ? FotonTime.Format(t.ToUniversalTime()) : "",
                ["Log"] = log,
                ["EventId"] = e.Id,
                ["Level"] = Safe(() => e.LevelDisplayName),
                ["Provider"] = e.ProviderName ?? "",
                ["Computer"] = e.MachineName ?? "",
                ["UserSid"] = e.UserId?.Value ?? "",
                ["RecordId"] = e.RecordId,
                ["Message"] = Collapse(msg),
            };
        }

        internal static string Collapse(string message) =>
            Regex.Replace(message.Length > MaxMessage ? message.Substring(0, MaxMessage) + "...[truncated]" : message, @"\s+", " ");

        /// <summary>Provider metadata lookups throw when the publisher is not registered on this host.</summary>
        static string Safe(Func<string?> read)
        {
            try { return read() ?? ""; }
            catch (EventLogException) { return ""; }
        }

        /// <summary>
        /// Get-WinEvent -ListLog fields. IsEnabled is NotPresent only when the log does not exist (Analyze reads that as
        /// "Sysmon is not installed"); a log this token may not open is AccessDenied, any other failure is Unreadable, and
        /// size/count stay blank when only the log file is unreadable.
        /// </summary>
        static object LogConfiguration()
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, object?> Missing(string name, string state) => new Dictionary<string, object?>
            {
                ["LogName"] = name, ["IsEnabled"] = state, ["LogMode"] = "", ["MaximumSizeMB"] = 0, ["CurrentSizeMB"] = 0,
                ["RecordCount"] = 0, ["OldestRecordUtc"] = "", ["LogFilePath"] = "",
            };
            using (var session = new EventLogSession())
            {
                foreach (var name in ConfigLogs)
                {
                    try
                    {
                        using (var cfg = new EventLogConfiguration(name, session))
                        {
                            EventLogInformation? info = null;
                            try { info = session.GetLogInformation(name, PathType.LogName); }
                            catch (Exception ex) when (ex is EventLogException || ex is UnauthorizedAccessException) { }
                            rows.Add(new Dictionary<string, object?>
                            {
                                ["LogName"] = cfg.LogName, ["IsEnabled"] = cfg.IsEnabled, ["LogMode"] = cfg.LogMode.ToString(),
                                ["MaximumSizeMB"] = Math.Round(cfg.MaximumSizeInBytes / 1048576.0, 2),
                                ["CurrentSizeMB"] = info != null ? (object)Math.Round((info.FileSize ?? 0) / 1048576.0, 2) : "",
                                ["RecordCount"] = info?.RecordCount, ["OldestRecordUtc"] = "", ["LogFilePath"] = cfg.LogFilePath,
                            });
                        }
                    }
                    catch (EventLogNotFoundException) { rows.Add(Missing(name, "NotPresent")); }
                    catch (UnauthorizedAccessException) { rows.Add(Missing(name, "AccessDenied")); }
                    catch (EventLogException) { rows.Add(Missing(name, "Unreadable")); }
                }
            }
            return rows;
        }

        /// <summary>wevtutil epl with a timediff filter, one file per log under 07_Event_Logs\evtx (Security only when elevated).</summary>
        static void ExportEvtx(FotonSession s, int days)
        {
            if (s.Options.SkipEvtxExport) { s.Status.Write("EVTX export skipped by parameter", StatusLevel.Info); return; }
            var profile = s.Options.Profile;
            if (profile != null && !profile.Selects(Cat, CollectionProfile.EvtxExport))
            {
                s.Status.Write("EVTX export not selected by the collection profile", StatusLevel.Info);
                return;
            }
            s.Status.Write("Exporting raw EVTX files (time-filtered)", StatusLevel.Step);
            string dir;
            try { dir = Directory.CreateDirectory(Path.Combine(s.Dirs[Cat], "evtx")).FullName; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                s.Status.Write("EVTX export failed: " + ex.Message, StatusLevel.Warn);
                return;
            }
            var ms = (long)days * 86400000L;
            foreach (var log in ExportLogs)
            {
                if (!s.IsElevated && log == "Security")
                {
                    s.Status.Write("EVTX export skipped for Security (not elevated)", StatusLevel.Info);
                    continue;
                }
                var dest = Path.Combine(dir, Regex.Replace(log, @"[\\/ ]", "_") + ".evtx");
                var output = Exec.System32("wevtutil.exe", $"epl \"{log}\" \"{dest}\" \"/q:*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]\" /ow:true", 600000);
                if (File.Exists(dest)) s.Status.Write("Exported " + log, StatusLevel.Good);
                else s.Status.Write($"No EVTX export produced for {log}: {TextFile.OneLine(output.Trim())}", StatusLevel.Info);
            }
        }
    }
}
