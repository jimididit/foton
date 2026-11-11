using System.Collections.Generic;
using System.Linq;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>Software and drivers, filesystem artifacts, WMI subscriptions, and visibility gaps in the package itself.</summary>
    static class HostArtifactRules
    {
        static string S(object? row, string name) => Str(Get(row, name));

        public static void SoftwareFilesystem(AnalysisContext c)
        {
            var rat = c.Data["remote_access_tool_indicators"];
            if (IsTrue(rat) && Items(rat).Count > 0)
                c.Add("Medium", "Software", 2, "Remote access or data transfer tooling present",
                    F("{0} indicator(s): {1}.", Items(rat).Count, Sample(Items(rat).Select(r => (object?)$"{S(r, "Source")}: {S(r, "Detail")}"), 6)),
                    "Tools such as remote support agents, tunneling utilities, and bulk transfer clients are used legitimately by IT and are also the tools of choice for hands-on-keyboard access and exfiltration. Presence alone is not an indicator of compromise.",
                    AnalysisContext.Artifact("Software", "remote_access_tool_indicators", "csv"),
                    "Confirm each item against the approved software inventory and check install dates against the incident timeline.");
            var drivers = c.Data["drivers"];
            if (IsTrue(drivers))
            {
                var unsigned = Items(drivers).Where(d => Eq(Get(d, "State"), "Running") && !In(Get(d, "SignatureStatus"), "Valid", "FileNotFound", "NotHashed")).ToList();
                if (unsigned.Count > 0)
                    c.Add("Medium", "Software", 2, "Running drivers without a valid signature",
                        F("{0} driver(s): {1}.", unsigned.Count, Sample(unsigned.Select(d => (object?)$"{S(d, "Name")} [{S(d, "SignatureStatus")}]"))),
                        "Kernel drivers run with the highest privilege available. Unsigned or invalidly signed drivers are worth verifying, though signature checks on system drivers can fail for benign reasons including catalog-signed files.",
                        AnalysisContext.Artifact("Software", "drivers", "csv"));
            }

            var exes = c.Data["executables_in_user_writable_paths"];
            if (IsTrue(exes))
            {
                var candidates = Items(exes).Where(e => !In(Get(e, "SignatureStatus"), "Valid", "NotHashed") && Match(Get(e, "Extension"), @"\.(exe|dll|scr|com|pif|sys)$")).ToList();
                var recent = candidates.Where(e => !c.IsCollector(e)).ToList();
                var self = candidates.Count > recent.Count ? " The collector's own executable (matched by the SHA-256 in chain_of_custody.txt) is not counted." : "";
                if (recent.Count > 0)
                    c.Add(recent.Count > 25 ? "Low" : "Medium", "Filesystem", 2, "Unsigned executables present in user-writable directories",
                        F("{0} file(s). Most recently modified: {1}.{2}", recent.Count, Sample(recent.Select(e => (object?)$"{S(e, "Path")} ({S(e, "ModifiedUtc")})"), 5), self),
                        "Temp and AppData accumulate unsigned files from ordinary use (installers, updaters, browser downloads), so volume alone means little. The value here is having hashes and timestamps to filter against the incident window.",
                        AnalysisContext.Artifact("Filesystem", "executables_in_user_writable_paths", "csv"),
                        "Filter the artifact by ModifiedUtc within the suspected incident window and hash-check the survivors.");
            }
            var ads = c.Data["alternate_data_streams"];
            if (IsTrue(ads))
            {
                var odd = Items(ads).Where(a => Ne(Get(a, "Stream"), "Zone.Identifier")).ToList();
                if (odd.Count > 0)
                    c.Add("Medium", "Filesystem", 2, "Non-standard alternate data streams found",
                        F("{0} stream(s): {1}.", odd.Count, Sample(odd.Select(a => (object?)$"{S(a, "File")}:{S(a, "Stream")}"), 4)),
                        "ADS can hide executable content inside an otherwise innocuous file. Zone.Identifier streams are normal and are excluded from this count.",
                        AnalysisContext.Artifact("Filesystem", "alternate_data_streams", "csv"));
            }
            var usb = c.Data["usb_device_history"];
            if (IsTrue(usb))
            {
                var stor = Items(usb).Where(u => Eq(Get(u, "Source"), "USBSTOR")).ToList();
                if (stor.Count > 0)
                    c.Add("Info", "Filesystem", 1, "USB storage device history",
                        F("{0} USB storage device record(s). Sample: {1}.", stor.Count, Sample(Each(stor, u => Get(u, "FriendlyName")), 5)),
                        "USBSTOR records which removable devices have been attached. Registry presence establishes connection, not that files were copied.",
                        AnalysisContext.Artifact("Filesystem", "usb_device_history", "csv"));
            }

            var subs = c.Data["wmi_event_subscriptions"];
            if (IsTrue(subs))
            {
                var text = string.Join("\n", Items(subs).Select(Str));
                if (Match(text, "__EventFilter") && !Match(text, @"(?s)=== __EventFilter ===\s*\(none\)"))
                    c.Add("Medium", "Persistence", 2, "WMI event subscriptions exist on this host",
                        @"One or more objects were returned from root\subscription (__EventFilter, __EventConsumer, or __FilterToConsumerBinding).",
                        "WMI subscriptions provide fileless persistence that survives reboot and leaves no file on disk. Monitoring products (SCCM among them) also create subscriptions, so each one must be identified.",
                        AnalysisContext.Artifact("Persistence", "wmi_event_subscriptions", "txt"),
                        "Read the artifact and identify the consumer command for each binding. Anything invoking a script interpreter warrants immediate attention.");
            }
        }

        public static void VisibilityGaps(AnalysisContext c)
        {
            var logCfg = c.Data["event_log_configuration"];
            // IsEnabled is the string NotPresent when ListLog threw; compare as text, never as a coerced bool.
            if (IsTrue(logCfg) && Items(logCfg).Any(l => Like(Get(l, "LogName"), "*Sysmon*") && Eq(Str(Get(l, "IsEnabled")), "NotPresent")))
                c.Add("Info", "EventLogs", 1, "Sysmon is not installed on this host",
                    "The Microsoft-Windows-Sysmon/Operational log is not present.",
                    "Without Sysmon, process creation with hashes, network connection attribution, and image load telemetry are largely unavailable. This limits what can be reconstructed and should be stated as a limitation in any report.",
                    AnalysisContext.Artifact("EventLogs", "event_log_configuration", "csv"));

            // Installed but stopped is a different gap from not installed: older events may exist, nothing new is recorded.
            var svcList = c.Data["services"];
            if (IsTrue(svcList))
            {
                var stopped = Items(svcList).Where(s => Match(S(s, "Name"), "^Sysmon(64)?$") && Match(S(s, "StartMode"), "^Auto") && Ne(S(s, "State"), "Running")).ToList();
                if (stopped.Count > 0)
                {
                    var s = stopped[0];
                    c.Add("Low", "EventLogs", 1, "Sysmon is installed but not running",
                        F("Service {0} is set to {1} start but was {2} at collection time.", Get(s, "Name"), Get(s, "StartMode"), Get(s, "State")),
                        "An automatic-start Sysmon that is stopped records nothing new: process, network, and image-load telemetry stop at the moment it stopped. Crashes, failed updates, and managing agents (EDR/MDR products often own Sysmon) cause this as well as tampering.",
                        AnalysisContext.Artifact("Persistence", "services", "csv"),
                        "Find when it stopped (System 7034/7036 for the service, last Sysmon/Operational event) and ask whoever manages Sysmon on this host whether that is expected.");
                }
            }

            var incomplete = c.Manifest.Where(m => In(m.TryGetValue("Status", out var st) ? st : null, "Partial", "Failed")).ToList();
            if (incomplete.Count > 0)
            {
                string V(Dictionary<string, string?> m, string k) => m.TryGetValue(k, out var v) ? v ?? "" : "";
                var list = string.Join("; ", incomplete.Take(10).Select(m => F("{0} ({1})", V(m, "Task"), V(m, "Status"))));
                c.Add("Info", "Collection", 1, "Some collection tasks captured only part of their files",
                    F("{0} task(s) did not capture every file they targeted: {1}. Details are in collection_errors.csv and the task CSVs (Status column).", incomplete.Count, list),
                    "A missing hive, Prefetch file, or log copy is a visibility gap in this package, not evidence the artifact was empty on the host. Parsers and compose tools cannot see what was not copied.",
                    AnalysisContext.Artifact("Collection", "collection_errors", "csv"),
                    "Read the Note column for each failed row. Locked files usually need an elevated re-collect, a shadow copy, or an imaging tool.");
            }

            var notSelected = c.Manifest.Where(m => m.TryGetValue("Status", out var st) && st == "NotSelected")
                .Select(m => m.TryGetValue("Task", out var t) ? t ?? "" : "").ToList();
            var profileCov = c.Data["collection_coverage"] as PsRow;
            var profileName = profileCov != null && profileCov.Has("ProfileName") ? Str(profileCov["ProfileName"]) : "";
            if (profileCov != null && profileCov.Has("NotSelectedTasks"))
                foreach (var t in Items(profileCov["NotSelectedTasks"]).Select(Str))
                    if (!notSelected.Contains(t, System.StringComparer.OrdinalIgnoreCase)) notSelected.Add(t);
            if (notSelected.Count > 0 || profileName.Length > 0)
                c.Add("Info", "Collection", 1, "A collection profile limited what was collected",
                    notSelected.Count == 0
                        ? F("Profile '{0}' was used and left out no task this run carried.", profileName)
                        : F("Profile '{0}' left out {1} task(s): {2}.", profileName.Length > 0 ? profileName : "(unnamed)", notSelected.Count, Sample(notSelected.Select(t => (object?)t), 12)),
                    "Tasks the profile did not select were not run, so their artifacts are absent by the operator's choice. No finding in this report is based on their absence; rules that need them did not evaluate. Collect again without the profile, or with those categories, if the case needs them.",
                    AnalysisContext.Artifact("Collection", "collection_profile", "json"),
                    "Compare the profile's categories with the questions this case has to answer.");

            // Profile scans skip earlier Foton packages; the name and marker files that identify one can be forged.
            var cov = c.Data["collection_coverage"];
            var excluded = cov is PsRow covRow && covRow.Has("ExcludedEarlierPackages") ? Items(covRow["ExcludedEarlierPackages"]).Where(IsTrue).ToList() : new List<object?>();
            if (excluded.Count > 0)
                c.Add("Info", "Collection", 1, "Earlier Foton package folders were skipped by profile scans",
                    F("{0} folder(s) identified as earlier Foton packages were not scanned for executables, shortcuts, or alternate data streams: {1}.", excluded.Count, string.Join("; ", excluded.Take(10).Select(Str))),
                    "Earlier collections on the same host are expected and re-collecting them only adds noise. A folder is recognised by its name pattern plus a collection.log or baseline.json marker, and both can be created by anyone, so a folder listed here was not inspected.",
                    AnalysisContext.Artifact("Collection", "collection_coverage", "json"),
                    "Confirm each listed folder is a collection the operator or host owner ran. Inspect any unfamiliar one directly.");

            // Only a read that happened can report no events. Not selected, skipped on a standard token, or neither a manifest
            // row nor an artifact (the task never started) means the log was not read. A package with no manifest at all
            // keeps the old reading.
            var procCreateStatus = c.TaskStatusFromPackage("security_process_creation", "EventLogs", "csv");
            var procCreate = c.Data["security_process_creation"];
            var procCreateRan = procCreateStatus == null ? c.Manifest.Count == 0 : In(procCreateStatus, "Success", "NoData");
            if (procCreateRan && (!IsTrue(procCreate) || Items(procCreate).Count == 0))
                c.Add("Info", "EventLogs", 1, "No process creation events (4688) were collected",
                    "The Security log returned no 4688 events for the collection window.",
                    "Process creation auditing is off by default. The absence of these events is a logging gap, not evidence that no processes were created.",
                    AnalysisContext.Artifact("Security", "audit_policy", "txt"));
        }
    }
}
