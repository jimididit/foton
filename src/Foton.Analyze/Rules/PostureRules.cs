using System.Linq;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>Host context, collection rights, Defender, registry hardening, firewall and RDP.</summary>
    static class PostureRules
    {
        public static void Host(AnalysisContext c)
        {
            var os = c.Data["os_info"];
            if (IsTrue(os))
                c.Add("Info", "System", 1, "Host and collection baseline",
                    F("{0} running {1} (build {2}), {3} days since last boot (includes sleep and hibernation, so not necessarily time powered on), time zone {4} (offset {5}).",
                        Get(os, "Hostname"), Get(os, "Caption"), Get(os, "BuildNumber"), Get(os, "UptimeDays"), Get(os, "TimeZone"), Get(os, "UtcOffset")),
                    "All timestamps in this package are recorded in UTC. Confirm the host clock was accurate before building any timeline (see time_sync.txt).",
                    AnalysisContext.Artifact("System", "os_info", "json"));

            var cov = c.Data["collection_coverage"];
            if (IsTrue(cov) && Eq(Get(cov, "Elevated"), false))
                c.Add("Info", "Collection", 1, "Collection ran without Administrator rights",
                    F("Coverage profile {0} as {1}. {2} task(s) were skipped because they require an elevated token (see collection_coverage.json).",
                        Get(cov, "CoverageProfile"), Get(cov, "CollectionAccount"), Get(cov, "SkippedTaskCount")),
                    "Standard-user collection still captures the current user's process list, readable network state, HKCU persistence, and profile artifacts. It does not capture the Security log, Prefetch copies, Amcache, SRUM, VSS, audit policy export, or other users' files. Missing those artifacts is a visibility gap, not evidence they were empty. Re-run elevated when the host owner can grant it.",
                    AnalysisContext.Artifact("Collection", "collection_coverage", "json"),
                    "If this is an incident, obtain an elevated collection or a disk/memory image. If this is a self-audit on a locked-down work PC, treat skipped tasks as out of scope and verify remaining artifacts against that user's activity only.");
        }

        public static void Defender(AnalysisContext c)
        {
            var def = c.Data["defender_status"];
            var defArtifact = AnalysisContext.Artifact("Security", "defender_status", "json");
            if (IsTrue(def))
            {
                if (Eq(Get(def, "RealTimeProtectionEnabled"), false))
                    c.Add("High", "Security", 1, "Defender real-time protection is disabled",
                        "Get-MpComputerStatus reports RealTimeProtectionEnabled = False.",
                        "Real-time protection off is both a common attacker action after gaining privilege and a common administrator misconfiguration. Correlate with Defender event IDs 5001/5007 to establish when and by what it was changed.",
                        defArtifact,
                        "Check defender_operational.csv for configuration-change events around the disable time, and confirm whether a third-party AV legitimately took over.");
                if (Eq(Get(def, "AntivirusEnabled"), false) || Eq(Get(def, "AMServiceEnabled"), false))
                    c.Add("High", "Security", 1, "Defender antimalware service is not running",
                        F("AMServiceEnabled = {0}, AntivirusEnabled = {1}.", Get(def, "AMServiceEnabled"), Get(def, "AntivirusEnabled")),
                        "A stopped antimalware service leaves the endpoint without on-access detection. This may be legitimate if a third-party product is installed; confirm against installed_av_products.csv.",
                        defArtifact);
                if (Eq(Get(def, "IsTamperProtected"), false))
                    c.Add("Low", "Security", 1, "Defender tamper protection is off",
                        "IsTamperProtected = False.",
                        "Without tamper protection, Defender settings can be modified by any process running with local administrator rights.",
                        defArtifact);
                var age = Get(def, "AntivirusSignatureAgeDays");
                if (age != null && Gt(age, 7))
                    c.Add("Medium", "Security", 1, "Antivirus signatures are stale",
                        F("Signature age is {0} days (version {1}).", age, Get(def, "AntivirusSignatureVersion")),
                        "Stale signatures reduce detection coverage and can indicate the host has been offline, or that update channels are blocked.",
                        defArtifact);
            }

            var pref = c.Data["defender_preferences_and_exclusions"];
            var prefArtifact = AnalysisContext.Artifact("Security", "defender_preferences_and_exclusions", "json");
            if (IsTrue(pref))
            {
                // Tamper Protection / policy can return "N/A: ..." placeholders instead of paths: a visibility gap.
                bool Readable(object? v) => !string.IsNullOrWhiteSpace(Str(v)) && !Match(v, @"^N/A\s*:");
                var rawPaths = Items(Get(pref, "ExclusionPath")).Where(IsTrue).ToList();
                var rawProcs = Items(Get(pref, "ExclusionProcess")).Where(IsTrue).ToList();
                var exPaths = rawPaths.Where(Readable).ToList();
                var exProcs = rawProcs.Where(Readable).ToList();
                if (rawPaths.Count + rawProcs.Count > 0 && exPaths.Count + exProcs.Count == 0)
                    c.Add("Info", "Security", 1, "Defender exclusion lists could not be read",
                        "Get-MpPreference returned an unreadable placeholder for exclusion paths/processes (often Tamper Protection or MDM policy).",
                        "Absence of readable exclusions is a visibility gap, not evidence that no exclusions are configured. Attackers and admins both use exclusions; without the list this surface cannot be audited from the package alone.",
                        prefArtifact,
                        "Re-check exclusions from an account/policy context that can read them, or inspect the Defender CSP / GPO that owns them.");
                else if (exPaths.Count > 0 || exProcs.Count > 0)
                {
                    bool risky = exPaths.Any(p => c.UserWritablePath(p) || Match(p, @"^[A-Za-z]:\\?$") || Match(p, @"^[A-Za-z]:\\Users\\?$") || Match(p, @"^[A-Za-z]:\\Windows\\?$"));
                    c.Add(risky ? "High" : "Medium", "Security", 2, "Defender exclusions are configured",
                        F("{0} path exclusion(s) and {1} process exclusion(s) are set. Paths: {2}. Processes: {3}.", exPaths.Count, exProcs.Count, Sample(exPaths), Sample(exProcs)),
                        "Exclusions are frequently added by attackers to create a safe staging directory, and are also routinely added by administrators for line-of-business software. Broad exclusions (drive roots, user-writable directories) are the ones worth scrutiny.",
                        prefArtifact,
                        "Determine who added each exclusion and when. Inspect the contents of every excluded path directly, since on-access scanning did not cover it.");
                }
                if (Eq(Get(pref, "DisableScriptScanning"), true) || Eq(Get(pref, "DisableBehaviorMonitoring"), true) || Eq(Get(pref, "DisableIOAVProtection"), true))
                    c.Add("High", "Security", 1, "Defender protection components are disabled by preference",
                        F("DisableScriptScanning={0}, DisableBehaviorMonitoring={1}, DisableIOAVProtection={2}.", Get(pref, "DisableScriptScanning"), Get(pref, "DisableBehaviorMonitoring"), Get(pref, "DisableIOAVProtection")),
                        "Selective component disabling is a targeted weakening of endpoint defenses rather than a broad on/off toggle.",
                        prefArtifact);
            }

            var det = c.Data["defender_detections"];
            if (IsTrue(det) && Items(det).Count > 0)
                c.Add("High", "Security", 1, "Antivirus detection history is present",
                    F("{0} detection record(s) recorded. Sample: {1}.", Items(det).Count, Sample(Each(Items(det), d => Get(d, "Resources")), 3)),
                    "Prior detections show what reached the endpoint. A detection that was only partially remediated, or that recurred, is a strong lead.",
                    AnalysisContext.Artifact("Security", "defender_detections", "csv"),
                    "For each detection, confirm the remediation action succeeded and check whether the same resource path appears in the filesystem or persistence artifacts.");
        }

        public static void Hardening(AnalysisContext c)
        {
            var hard = c.Data["hardening_registry_settings"];
            if (!IsTrue(hard)) return;
            var map = new System.Collections.Generic.Dictionary<string, object?>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var h in Items(hard))
            {
                var key = Get(h, "Setting");
                if (key != null) map[Str(key)] = Get(h, "Value");
            }
            object? M(string k) => map.TryGetValue(k, out var v) ? v : null;
            var art = AnalysisContext.Artifact("Security", "hardening_registry_settings", "csv");

            if (Eq(M("UseLogonCredential"), "1"))
                c.Add("High", "Security", 1, "WDigest cleartext credential storage is enabled",
                    @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1.",
                    "This forces plaintext credentials into LSASS memory. It is not a default setting and is a well-documented pre-credential-theft modification.",
                    art, "Establish when this value was set and by which account. Treat credentials used on this host as potentially exposed.");
            if (Eq(M("EnableLUA"), "0"))
                c.Add("High", "Security", 1, "User Account Control is disabled", "EnableLUA = 0.",
                    "With UAC off, any process launched by an administrator account runs fully elevated without prompting.", art);
            if (Eq(M("AlwaysInstallElevated"), "1"))
                c.Add("High", "Security", 1, "AlwaysInstallElevated is enabled", "HKLM Installer policy AlwaysInstallElevated = 1.",
                    "Any user can install an MSI package with SYSTEM privileges. This is a direct local privilege escalation path.", art);
            if (Eq(M("AutoAdminLogon"), "1"))
                c.Add("High", "Security", 2, "Automatic logon is configured",
                    F("AutoAdminLogon = 1 for account '{0}'.", M("DefaultUserName")),
                    "Autologon commonly accompanies a DefaultPassword value stored in cleartext in the registry, and it grants console access without authentication.",
                    art, "Check for a DefaultPassword value in the Winlogon key and rotate that credential.");
            if (Eq(M("LocalAccountTokenFilterPolicy"), "1"))
                c.Add("Medium", "Security", 2, "LocalAccountTokenFilterPolicy is enabled", "LocalAccountTokenFilterPolicy = 1.",
                    "Local administrator accounts can authenticate remotely with full token privileges, which enables pass-the-hash style lateral movement using local accounts.", art);
            if (Eq(M("SMB1"), "1"))
                c.Add("Medium", "Security", 1, "SMBv1 server is enabled", "LanmanServer SMB1 = 1.",
                    "SMBv1 is deprecated and carries known remote code execution exposure. It also lacks modern signing and encryption.", art);
            if (Ne(M("EnableScriptBlockLogging"), "1"))
                c.Add("Low", "Security", 1, "PowerShell script block logging is not enabled", "EnableScriptBlockLogging is not set to 1.",
                    "This is a visibility gap rather than a compromise indicator: PowerShell activity prior to collection may not be recoverable from logs. Absence of PowerShell events in this package cannot be read as absence of PowerShell activity.",
                    AnalysisContext.Artifact("Security", "powershell_environment", "json"));
            if (Ne(M("RunAsPPL"), "1"))
                c.Add("Low", "Security", 1, "LSASS is not running as a protected process", "RunAsPPL is not set to 1.",
                    "Without PPL, LSASS memory can be read by any process with debug privilege, which is the standard credential-dumping path.", art);
        }

        /// <summary>Test-FotonIsFalse: a boolean false, or the text False / 0 / No.</summary>
        internal static bool IsFalse(object? v)
        {
            if (v is bool b) return !b;
            if (v == null) return false;
            var s = Str(v).Trim();
            return Eq(s, "False") || Eq(s, "0") || Eq(s, "No");
        }

        public static void FirewallRdp(AnalysisContext c)
        {
            var fw = c.Data["firewall_profiles"];
            if (IsTrue(fw))
            {
                var off = Items(fw).Where(p => IsFalse(Get(p, "Enabled"))).ToList();
                if (off.Count > 0)
                    c.Add("Medium", "Network", 1, "One or more firewall profiles are disabled",
                        F("Disabled profile(s): {0}.", Sample(Each(off, p => Get(p, "Name")))),
                        "A disabled profile removes inbound filtering on networks using that profile and is a common post-compromise change to enable remote access.",
                        AnalysisContext.Artifact("Network", "firewall_profiles", "csv"));
            }
            var rdp = c.Data["rdp_configuration"];
            if (IsTrue(rdp) && Eq(Get(rdp, "RdpEnabled"), true))
            {
                var sev = "Low";
                var note = "RDP is enabled.";
                if (Eq(Get(rdp, "UserAuthentication"), 0))
                {
                    sev = "Medium";
                    note = "RDP is enabled and Network Level Authentication is disabled.";
                }
                c.Add(sev, "Users", 1, "Remote Desktop is enabled",
                    F("{0} Listening port: {1}. Members of Remote Desktop Users: {2}.", note, Get(rdp, "PortNumber"), Get(rdp, "RemoteDesktopUsers")),
                    "RDP is one of the most common initial access and lateral movement vectors. Whether this is expected depends on the endpoint role; confirm with the system owner.",
                    AnalysisContext.Artifact("Users", "rdp_configuration", "json"),
                    "Review terminal_services_remote.csv (event 1149) for the source IPs of successful RDP authentications.");
            }
        }
    }
}
