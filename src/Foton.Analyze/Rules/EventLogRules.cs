using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>Findings from exported event log CSVs (Collect's selected Event IDs).</summary>
    static class EventLogRules
    {
        static readonly Regex NamesCollector1 = new Regex(@"(?i)\b[A-Za-z]+-Foton[A-Za-z0-9]*\b");
        static readonly Regex NamesCollector2 = new Regex(@"(?i)\bFotonSession\b");

        /// <summary>Test-FotonMessageNamesCollector: text naming a Verb-Foton* function or FotonSession (a bare "Foton" path is not enough).</summary>
        internal static bool NamesCollector(string? text) =>
            !string.IsNullOrWhiteSpace(text) && (NamesCollector1.IsMatch(text) || NamesCollector2.IsMatch(text));

        /// <summary>Test-FotonCollectorAttributedEvent: names the collector, or falls inside the collection window.</summary>
        internal static bool CollectorAttributed(string timeCreatedUtc, string message, CollectionWindow? window)
        {
            if (NamesCollector(message)) return true;
            if (window == null || string.IsNullOrWhiteSpace(timeCreatedUtc)) return false;
            if (!DateTime.TryParse(timeCreatedUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts)) return false;
            return window.Contains(ts);
        }

        static object? First(List<object?> rows, string name) => Get(rows[0], name);

        public static void Run(AnalysisContext c, Dictionary<string, object?> svcIndex, string hostSys32)
        {
            var pol = c.Data["security_policy_and_log_changes"];
            if (IsTrue(pol))
            {
                var cleared = Items(pol).Where(e => Eq(Get(e, "EventId"), 1102)).ToList();
                if (cleared.Count > 0)
                    c.Add("High", "EventLogs", 1, "Security event log was cleared",
                        F("Event ID 1102 recorded {0} time(s). Most recent: {1} UTC.", cleared.Count, First(cleared, "TimeCreatedUtc")),
                        "Clearing the Security log destroys authentication and audit history. It is occasionally done during maintenance, but it is also a standard anti-forensic step.",
                        AnalysisContext.Artifact("EventLogs", "security_policy_and_log_changes", "csv"),
                        "Identify the account in the 1102 record and determine whether the clearing was authorized. Any event history before that timestamp is unavailable from this host.");
            }
            var sysLog = c.Data["system_log_and_boot"];
            if (IsTrue(sysLog))
            {
                var cleared = Items(sysLog).Where(e => Eq(Get(e, "EventId"), 104)).ToList();
                if (cleared.Count > 0)
                    c.Add("High", "EventLogs", 1, "An event log was cleared (System log, event 104)",
                        F("Event ID 104 recorded {0} time(s). Most recent: {1} UTC.", cleared.Count, First(cleared, "TimeCreatedUtc")),
                        "Event 104 records which log was cleared and by whom. Coverage gaps created by clearing must be stated explicitly in any timeline built from this data.",
                        AnalysisContext.Artifact("EventLogs", "system_log_and_boot", "csv"));
            }
            var svcEvents = c.Data["system_service_and_driver"];
            if (IsTrue(svcEvents))
            {
                var all7045 = Items(svcEvents).Where(e => Eq(Str(Get(e, "EventId")), "7045")).ToList();
                var installs = all7045.Where(e => !EventHelpers.PerUserServiceEvent(e, svcIndex, hostSys32)).ToList();
                if (installs.Count > 0)
                {
                    var names = SortUnique(installs.Select(EventHelpers.ServiceName).Where(n => n.Length > 0));
                    var nameText = names.Count > 0 ? F(" Services: {0}.", string.Join("; ", names.Take(12))) : "";
                    int perUser = all7045.Count - installs.Count;
                    if (perUser > 0)
                        nameText += F(" Excludes {0} per-user service instance(s) of known Windows templates hosted by System32 svchost.exe. The event does not record ServiceDll; it was checked in services.csv for instances that still existed at collection time, and instances removed at logoff could not be checked.", perUser);
                    // The export covers the configured lookback, not the minutes the collector ran.
                    c.Add("Medium", "EventLogs", 1, "Service install events in the exported logs",
                        F("{0} service install event(s) (ID 7045) in the exported System log. Most recent: {1} UTC.{2}", installs.Count, First(installs, "TimeCreatedUtc"), nameText),
                        "Remote execution tooling (PsExec and similar) and many malware families install a service. So do software updates, drivers, and management agents. Compare each install against expected software deployment activity.",
                        AnalysisContext.Artifact("EventLogs", "system_service_and_driver", "csv"));
                }
            }
            var acctEvents = c.Data["security_account_management"];
            if (IsTrue(acctEvents))
            {
                var acct = EventHelpers.AccountChanges(EventHelpers.AccountFacts(acctEvents));
                var art = AnalysisContext.Artifact("EventLogs", "security_account_management", "csv");
                if (acct.Persistent.Count > 0 || acct.PrivilegedAdds.Count > 0)
                {
                    var who = SortUnique(acct.Persistent.Select(f => f.AccountName).Where(n => n.Length > 0));
                    var grp = SortUnique(acct.PrivilegedAdds.Select(f => f.GroupName).Where(n => n.Length > 0));
                    c.Add("Medium", "EventLogs", 1, "Accounts created or privileged groups changed in the exported logs",
                        F("{0} account creation(s) not followed by a quick deletion (4720){1}, and {2} addition(s) to privileged groups (4728/4732/4756){3}.",
                            acct.Persistent.Count, who.Count > 0 ? ": " + string.Join(", ", who) : "", acct.PrivilegedAdds.Count, grp.Count > 0 ? ": " + string.Join(", ", grp) : ""),
                        "New accounts and privileged group additions are both routine IT activity and a standard persistence/privilege step. The distinguishing factor is whether they map to an approved change.",
                        art, "Match each event to a change ticket or known onboarding. Note the account that performed the change, not just the account affected.");
                }
                if (acct.Transient.Count > 0)
                {
                    var tn = SortUnique(acct.Transient.Select(f => f.AccountName).Where(n => n.Length > 0));
                    c.Add("Low", "EventLogs", 1, "Accounts created and deleted within a minute",
                        F("{0} account(s) were created (4720) and deleted (4726) with the same SID within 60 seconds{1}. Each pair used a new SID.",
                            acct.Transient.Count, tn.Count > 0 ? ": " + string.Join(", ", tn) : ""),
                        "Provisioning scripts, local-admin rotation tools, and some installers create and remove an account in the same run, often at every boot. Repeating create/delete with no privileged group membership is usually automation; it is still worth naming the script or task responsible.",
                        art, "Find the scheduled task or deployment job that runs at the same times (boot, logon) and confirm it is expected.");
                }
            }
            var logons = c.Data["security_logon_events"];
            if (IsTrue(logons))
            {
                var art = AnalysisContext.Artifact("EventLogs", "security_logon_events", "csv");
                var failed = Items(logons).Count(e => Eq(Get(e, "EventId"), 4625));
                if (failed > 25)
                    c.Add("Medium", "EventLogs", 2, "Elevated volume of failed logon attempts",
                        F("{0} failed logon event(s) (4625) in the last {1} days.", failed, c.EventLogDays),
                        "High 4625 volume is consistent with password spraying or brute force, and equally consistent with a stale service account or a mapped drive using an expired credential.",
                        art, "Group the failures by target account, source workstation, and logon type before characterizing the activity.");
                var explicitUse = Items(logons).Count(e => Eq(Get(e, "EventId"), 4648));
                if (explicitUse > 0)
                    c.Add("Low", "EventLogs", 1, "Explicit credential use recorded",
                        F("{0} event(s) with ID 4648 (logon using explicitly supplied credentials).", explicitUse),
                        "4648 records runas-style credential use and often marks the pivot point in lateral movement, though it is also generated by ordinary administrative tooling.",
                        art);
            }
            var psEvents = c.Data["powershell_operational"];
            if (IsTrue(psEvents))
            {
                var window = CollectionWindow.FromCase(c.CaseRoot);
                var flagged = new List<object?>();
                int self = 0;
                foreach (var ev in Items(psEvents))
                {
                    if (c.SuspiciousCommand(Get(ev, "Message")) == null) continue;
                    if (CollectorAttributed(Str(Get(ev, "TimeCreatedUtc")), Str(Get(ev, "Message")), window)) { self++; continue; }
                    flagged.Add(ev);
                }
                if (flagged.Count > 0)
                    c.Add("High", "EventLogs", 2, "PowerShell script block logs contain high-risk content",
                        F("{0} event(s) matched risk patterns. Most recent: {1} UTC.{2}", flagged.Count, First(flagged, "TimeCreatedUtc"),
                            self > 0 ? F(" Excludes {0} event(s) attributable to the Foton collector itself.", self) : ""),
                        "Script block logging captures deobfuscated script content at execution time, which makes it some of the highest-value evidence available on a Windows endpoint.",
                        AnalysisContext.Artifact("EventLogs", "powershell_operational", "csv"),
                        "Read the full Message column for each matched event and reconstruct the script from multi-part 4104 records.");
            }
            var defEvents = c.Data["defender_operational"];
            if (IsTrue(defEvents))
            {
                var art = AnalysisContext.Artifact("EventLogs", "defender_operational", "csv");
                var cfg = Items(defEvents).Where(e => In(Get(e, "EventId"), 5001, 5007, 5010, 5012)).ToList();
                if (cfg.Count > 0)
                    c.Add("High", "EventLogs", 1, "Defender configuration or protection state was changed",
                        F("{0} configuration-change event(s) (5001/5007/5010/5012). Most recent: {1} UTC.", cfg.Count, First(cfg, "TimeCreatedUtc")),
                        "Event 5007 records the old and new value of a Defender setting, which is how exclusion additions and protection disables are attributed and timed.",
                        art);
                var det = Items(defEvents).Where(e => In(Get(e, "EventId"), 1116, 1117)).ToList();
                if (det.Count > 0)
                    c.Add("High", "EventLogs", 1, "Defender logged malware detections in the window",
                        F("{0} detection event(s) (1116/1117). Most recent: {1} UTC.", det.Count, First(det, "TimeCreatedUtc")),
                        "Detection events name the threat, the file path, and the process that introduced it, which anchors the earliest known point of the intrusion.",
                        art);
            }
            var rdpEvents = c.Data["terminal_services_remote"];
            if (IsTrue(rdpEvents))
            {
                var auth = Items(rdpEvents).Where(e => Eq(Get(e, "EventId"), 1149)).ToList();
                if (auth.Count > 0)
                    c.Add("Medium", "EventLogs", 1, "Successful RDP authentications recorded",
                        F("{0} event(s) with ID 1149 in the last {1} days. Most recent: {2} UTC.", auth.Count, c.EventLogDays, First(auth, "TimeCreatedUtc")),
                        "Event 1149 carries the source IP address of the connecting client, which is the fastest way to separate expected administrative access from unexpected remote access.",
                        AnalysisContext.Artifact("EventLogs", "terminal_services_remote", "csv"));
            }
            var wmiEvents = c.Data["wmi_activity"];
            if (IsTrue(wmiEvents))
            {
                var perm = Items(wmiEvents).Count(e => In(Get(e, "EventId"), 5860, 5861));
                if (perm > 0)
                    c.Add("Medium", "EventLogs", 2, "WMI permanent subscription activity recorded",
                        F("{0} event(s) with ID 5860/5861.", perm),
                        "Event 5861 records permanent event consumer registration, the core artifact of fileless WMI persistence. Legitimate management software also registers consumers.",
                        AnalysisContext.Artifact("EventLogs", "wmi_activity", "csv"),
                        "Compare against wmi_event_subscriptions.txt to see which subscriptions currently exist on the host.");
            }
        }

        /// <summary>Sort-Object -Unique: case-insensitive order and uniqueness (invariant culture).</summary>
        internal static List<string> SortUnique(IEnumerable<string> items) =>
            items.Distinct(StringComparer.InvariantCultureIgnoreCase).OrderBy(x => x, StringComparer.InvariantCultureIgnoreCase).ToList();
    }
}
