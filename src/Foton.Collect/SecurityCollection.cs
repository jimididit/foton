using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>One file a task wrote into the package from a tool (gpresult /h), with its own copy status.</summary>
    public sealed class ToolOutputRow : ICopyRow
    {
        public string SourcePath { get; set; } = "";
        public string DestRelative { get; set; } = "";
        public long SizeBytes { get; set; }
        public string SHA256 { get; set; } = "";
        public string Status { get; set; } = "";
        public string Note { get; set; } = "";
    }

    /// <summary>
    /// AV state, logging, hardening, and application-control configuration (Invoke-FotonSecurityCollection). The
    /// Defender, SMB, and Device Guard cmdlets 1.38.x called are CDXML wrappers over these WMI classes.
    /// </summary>
    public static class SecurityCollection
    {
        const string Cat = "Security", Cimv2 = @"root\cimv2", Defender = @"root\Microsoft\Windows\Defender";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting security posture, AV state, logging and hardening configuration", StatusLevel.Step);
            Task(s, Cat, "defender_status", "Microsoft Defender engine, signature, and protection state", TaskFormat.Json, DefenderStatus);
            Task(s, Cat, "defender_preferences_and_exclusions", "Defender preferences, including exclusion paths/processes/extensions", TaskFormat.Json, DefenderPreferences);
            Task(s, Cat, "defender_detections", "Defender threat detection history", TaskFormat.Csv, () => DefenderDetections(s));
            Task(s, Cat, "installed_av_products", "Registered AV products from Security Center", TaskFormat.Csv, () =>
                Wmi.Query(@"root\SecurityCenter2", "SELECT displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, timestamp FROM AntiVirusProduct")
                    .Select(a => new Dictionary<string, object?>
                    {
                        ["displayName"] = Raw(a, "displayName"), ["productState"] = Raw(a, "productState"), ["pathToSignedProductExe"] = Raw(a, "pathToSignedProductExe"),
                        ["pathToSignedReportingExe"] = Raw(a, "pathToSignedReportingExe"), ["timestamp"] = Raw(a, "timestamp"),
                    }).ToList());
            Task(s, Cat, "hardening_registry_settings", "UAC, LSA, WDigest, SMB, and credential protection settings", TaskFormat.Csv, Hardening);
            Task(s, Cat, "audit_policy", "Advanced audit policy configuration (log coverage)", TaskFormat.Txt, () => Exec.System32("auditpol.exe", "/get /category:*"), elevated: true);
            Task(s, Cat, "smb_and_winrm_config", "SMB server config, SMBv1 feature state, WinRM listeners", TaskFormat.Txt, SmbAndWinRm);
            Task(s, Cat, "powershell_environment", "PowerShell versions, policy, and logging configuration", TaskFormat.Json, PowerShellEnvironment);
            // Every certificate in these stores, despite the task name (kept for package compatibility): an issuer name is
            // chosen by whoever made the certificate, so filtering "not Microsoft" by name would let a rogue CA named
            // Microsoft through. Review the rows whose issuer is not a known Microsoft root.
            Task(s, Cat, "non_microsoft_root_certificates", "Every LocalMachine Root, intermediate CA, and TrustedPublisher certificate (rogue CA check; not filtered by issuer name)", TaskFormat.Csv, Certificates);
            Task(s, Cat, "applocker_wdac_and_policy", "Application control policy and applied group policy summary", TaskFormat.Txt, AppControl);
            if (s.Options.Deep)
                Task(s, Cat, "gpresult_html", "Deep: gpresult /h HTML and /x XML reports into the package (requires elevation).", TaskFormat.Csv, () => GpResultHtml(s), elevated: true);
        }

        /// <summary>A WMI datetime as UTC text (1.38.x [string]-cast these in the machine's culture and local time).</summary>
        static string When(ManagementBaseObject o, string name) => Dmtf(Raw(o, name));

        // SELECT * on the Defender classes: Defender drops properties between platform builds, and naming a property the
        // class no longer has fails the whole query; Raw() turns a missing property into null instead.
        static object DefenderStatus()
        {
            var st = First(Defender, "SELECT * FROM MSFT_MpComputerStatus") ?? throw new InvalidOperationException("MSFT_MpComputerStatus returned no instance.");
            return new Dictionary<string, object?>
            {
                ["AMServiceEnabled"] = Raw(st, "AMServiceEnabled"),
                ["AntispywareEnabled"] = Raw(st, "AntispywareEnabled"),
                ["AntivirusEnabled"] = Raw(st, "AntivirusEnabled"),
                ["RealTimeProtectionEnabled"] = Raw(st, "RealTimeProtectionEnabled"),
                ["BehaviorMonitorEnabled"] = Raw(st, "BehaviorMonitorEnabled"),
                ["IoavProtectionEnabled"] = Raw(st, "IoavProtectionEnabled"),
                ["OnAccessProtectionEnabled"] = Raw(st, "OnAccessProtectionEnabled"),
                ["NISEnabled"] = Raw(st, "NISEnabled"),
                ["TamperProtectionSource"] = Raw(st, "TamperProtectionSource"),
                ["IsTamperProtected"] = Raw(st, "IsTamperProtected"),
                ["AntivirusSignatureVersion"] = Raw(st, "AntivirusSignatureVersion"),
                ["AntivirusSignatureLastUpdated"] = When(st, "AntivirusSignatureLastUpdated"),
                ["AntivirusSignatureAgeDays"] = Raw(st, "AntivirusSignatureAge"),
                ["QuickScanAge"] = Raw(st, "QuickScanAge"),
                ["FullScanAge"] = Raw(st, "FullScanAge"),
                ["LastQuickScanTime"] = When(st, "QuickScanEndTime"),
                ["AMEngineVersion"] = Raw(st, "AMEngineVersion"),
                ["AMProductVersion"] = Raw(st, "AMProductVersion"),
            };
        }

        static object DefenderPreferences()
        {
            var p = First(Defender, "SELECT * FROM MSFT_MpPreference") ?? throw new InvalidOperationException("MSFT_MpPreference returned no instance.");
            object List(string name) => Raw(p, name) is IEnumerable e && !(Raw(p, name) is string) ? e.Cast<object?>().ToList() : new List<object?>();
            string Text(string name) => Raw(p, name) is object v ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";
            return new Dictionary<string, object?>
            {
                ["ExclusionPath"] = List("ExclusionPath"),
                ["ExclusionProcess"] = List("ExclusionProcess"),
                ["ExclusionExtension"] = List("ExclusionExtension"),
                ["ExclusionIpAddress"] = List("ExclusionIpAddress"),
                ["DisableRealtimeMonitoring"] = Raw(p, "DisableRealtimeMonitoring"),
                ["DisableBehaviorMonitoring"] = Raw(p, "DisableBehaviorMonitoring"),
                ["DisableScriptScanning"] = Raw(p, "DisableScriptScanning"),
                ["DisableArchiveScanning"] = Raw(p, "DisableArchiveScanning"),
                ["DisableIOAVProtection"] = Raw(p, "DisableIOAVProtection"),
                ["DisableIntrusionPreventionSystem"] = Raw(p, "DisableIntrusionPreventionSystem"),
                ["DisableBlockAtFirstSeen"] = Raw(p, "DisableBlockAtFirstSeen"),
                ["MAPSReporting"] = Text("MAPSReporting"),
                ["SubmitSamplesConsent"] = Text("SubmitSamplesConsent"),
                ["PUAProtection"] = Text("PUAProtection"),
                ["EnableControlledFolderAccess"] = Text("EnableControlledFolderAccess"),
                ["AttackSurfaceReductionRules_Ids"] = List("AttackSurfaceReductionRules_Ids"),
                ["AttackSurfaceReductionRules_Actions"] = List("AttackSurfaceReductionRules_Actions"),
            };
        }

        /// <summary>
        /// Detection history. A query that fails is never an empty "no detections" table: with nothing read the task
        /// fails with the reasons; with some rows read the failure is recorded in collection_errors.csv.
        /// </summary>
        static object DefenderDetections(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            var errors = new List<string>();
            string Resources(ManagementBaseObject o) => Raw(o, "Resources") is string[] r ? string.Join(" | ", r) : "";
            string Text(ManagementBaseObject o, string n) => Raw(o, n) is object v ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";
            try
            {
                foreach (var t in Wmi.Query(Defender, "SELECT * FROM MSFT_MpThreatDetection"))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["DetectionID"] = Raw(t, "DetectionID"), ["ThreatID"] = Raw(t, "ThreatID"),
                        ["InitialDetectionTimeUtc"] = When(t, "InitialDetectionTime"), ["LastThreatStatusChangeTime"] = When(t, "LastThreatStatusChangeTime"),
                        ["ThreatStatus"] = Text(t, "ThreatStatusID"), ["CleaningAction"] = Text(t, "CleaningActionID"), ["Resources"] = Resources(t),
                        ["ProcessName"] = Raw(t, "ProcessName"), ["DomainUser"] = Raw(t, "DomainUser"),
                    });
            }
            catch (Exception ex) when (WmiFailed(ex)) { errors.Add("MSFT_MpThreatDetection: " + ex.Message); }
            try
            {
                foreach (var t in Wmi.Query(Defender, "SELECT * FROM MSFT_MpThreat"))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["DetectionID"] = "MpThreat", ["ThreatID"] = Raw(t, "ThreatID"), ["InitialDetectionTimeUtc"] = "", ["LastThreatStatusChangeTime"] = "",
                        ["ThreatStatus"] = Raw(t, "ThreatName"), ["CleaningAction"] = Text(t, "SeverityID"), ["Resources"] = Resources(t), ["ProcessName"] = "", ["DomainUser"] = "",
                    });
            }
            catch (Exception ex) when (WmiFailed(ex)) { errors.Add("MSFT_MpThreat: " + ex.Message); }
            if (errors.Count > 0)
            {
                if (rows.Count == 0) throw new InvalidOperationException("Detection history could not be read (not the same as no detections): " + string.Join("; ", errors));
                s.Errors.Add(new ErrorRow { Task = "defender_detections", Error = "Partial: " + string.Join("; ", errors) });
            }
            return rows;
        }

        static object Hardening() => HardeningChecks.All.Select(c =>
        {
            var raw = Reg.Value(c.Path, c.Name);
            var text = raw == null ? null : BaselineDocument.PsString(raw);
            return new Dictionary<string, object?>
            {
                ["Setting"] = c.Name, ["Key"] = c.Path, ["Value"] = text ?? "(not set)", ["RecommendedValue"] = c.Expected, ["Meaning"] = c.Note,
                // PowerShell -eq on strings: case-insensitive.
                ["MatchesRecommended"] = text != null && string.Equals(text, c.Expected, StringComparison.OrdinalIgnoreCase),
            };
        }).ToList();

        /// <summary>Win32_OptionalFeature InstallState in Get-WindowsOptionalFeature's words; NotPresent when the feature is not listed.</summary>
        static string FeatureState(string feature)
        {
            var f = First(Cimv2, $"SELECT InstallState FROM Win32_OptionalFeature WHERE Name = '{WqlString(feature)}'");
            if (f == null) return "NotPresent";
            switch (Convert.ToInt32(Raw(f, "InstallState") ?? 0))
            {
                case 1: return "Enabled";
                case 2: return "Disabled";
                case 3: return "DisabledWithPayloadRemoved";
                default: return "Unknown";
            }
        }

        static string ServiceTable(string name)
        {
            try
            {
                using (var svc = new ServiceController(name))
                    return string.Join("\r\n", Table(new[] { "Name", "Status", "StartType" }, new[] { new[] { svc.ServiceName, svc.Status.ToString(), svc.StartType.ToString() } }));
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception) { return ""; }
        }

        static object SmbAndWinRm()
        {
            var lines = new List<string> { "--- Get-SmbServerConfiguration ---" };
            try
            {
                var cfg = First(@"root\Microsoft\Windows\SMB", "SELECT * FROM MSFT_SmbServerConfiguration");
                if (cfg != null) lines.AddRange(PropertyList(cfg));
            }
            catch (Exception ex) when (WmiFailed(ex)) { lines.Add("Error: " + ex.Message); }
            lines.Add("--- SMB1 optional feature ---");
            // Win32_OptionalFeature is readable by any token; Get-WindowsOptionalFeature needed Administrator.
            try { lines.AddRange(Table(new[] { "FeatureName", "State" }, new[] { new[] { "SMB1Protocol", FeatureState("SMB1Protocol") } })); }
            catch (Exception ex) when (WmiFailed(ex)) { lines.Add("SMB1 feature query unavailable"); }
            lines.Add("--- winrm enumerate winrm/config/listener ---");
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var winrm = new[] { "winrm.cmd", "winrm.exe" }.FirstOrDefault(n => File.Exists(Path.Combine(sys, n)));
            lines.Add(winrm != null ? Exec.System32(winrm, "enumerate winrm/config/listener")
                : "winrm client not present in System32 (common on some Windows editions). WinRM service status still recorded below.");
            lines.Add("--- WinRM service ---");
            lines.Add(ServiceTable("WinRM"));
            lines.Add("--- PSRemoting trusted hosts (registry) ---");
            // The registry value, never the WSMan: drive: with WinRM stopped that provider prompts to START the service.
            var th = BaselineDocument.PsString(Reg.Value(@"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client", "trusted_hosts"));
            lines.Add(th.Length == 0 ? "trusted_hosts: (not set)" : "trusted_hosts: " + th);
            return lines;
        }

        const string PsPolicies = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell";
        const string ShellId = @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell";

        /// <summary>
        /// Windows PowerShell on the host, read from the registry. 1.38.x recorded properties of its own PowerShell
        /// process (its version, its -ExecutionPolicy Bypass process scope, its language mode), which described the
        /// collector rather than the host; the v2 collector is not a PowerShell host.
        /// </summary>
        static object PowerShellEnvironment()
        {
            string Policy(string root, string key, string value)
            {
                var v = BaselineDocument.PsString(Reg.Value(root + key, value));
                return v.Length == 0 ? "Undefined" : v;
            }
            var scopes = new[]
            {
                new[] { "MachinePolicy", Policy(@"HKLM:\", PsPolicies, "ExecutionPolicy") },
                new[] { "UserPolicy", Policy(@"HKCU:\", PsPolicies, "ExecutionPolicy") },
                new[] { "Process", Environment.GetEnvironmentVariable("PSExecutionPolicyPreference") is string pp && pp.Length > 0 ? pp : "Undefined" },
                new[] { "CurrentUser", Policy(@"HKCU:\", ShellId, "ExecutionPolicy") },
                new[] { "LocalMachine", Policy(@"HKLM:\", ShellId, "ExecutionPolicy") },
            };
            string psv2;
            try { psv2 = FeatureState("MicrosoftWindowsPowerShellV2"); }
            catch (Exception ex) when (WmiFailed(ex)) { psv2 = "Unknown"; }
            var lockdown = Environment.GetEnvironmentVariable("__PSLockdownPolicy", EnvironmentVariableTarget.Machine);
            return new Dictionary<string, object?>
            {
                ["CurrentVersion"] = BaselineDocument.PsString(Reg.Value(@"HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine", "PowerShellVersion")),
                ["ExecutionPolicyList"] = string.Join("\r\n", Table(new[] { "Scope", "ExecutionPolicy" }, scopes)),
                ["PSv2FeatureState"] = psv2,
                ["ScriptBlockLogging"] = Reg.Value(@"HKLM:\" + PsPolicies + @"\ScriptBlockLogging", "EnableScriptBlockLogging"),
                ["ModuleLogging"] = Reg.Value(@"HKLM:\" + PsPolicies + @"\ModuleLogging", "EnableModuleLogging"),
                ["Transcription"] = Reg.Value(@"HKLM:\" + PsPolicies + @"\Transcription", "EnableTranscripting"),
                ["TranscriptOutputDir"] = Reg.Value(@"HKLM:\" + PsPolicies + @"\Transcription", "OutputDirectory"),
                ["LanguageMode"] = lockdown == "4" ? "ConstrainedLanguage (__PSLockdownPolicy = 4)"
                    : "Not measured (the v2 collector is not a PowerShell host; WDAC and AppLocker script enforcement is in applocker_wdac_and_policy)",
            };
        }

        static object Certificates()
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var name in new[] { "Root", "CA", "TrustedPublisher" })
            {
                var store = new X509Store(name, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    foreach (var c in store.Certificates)
                        using (c)
                            rows.Add(new Dictionary<string, object?>
                            {
                                ["Store"] = @"Cert:\LocalMachine\" + name, ["Subject"] = c.Subject, ["Issuer"] = c.Issuer, ["Thumbprint"] = c.Thumbprint,
                                ["NotBefore"] = c.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                                ["NotAfter"] = c.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                                ["SelfSigned"] = string.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase),
                                ["FriendlyName"] = c.FriendlyName,
                            });
                }
                catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException || ex is UnauthorizedAccessException) { }
                finally { store.Close(); }
            }
            // Same-subject certificates (renewals, cross-signs) are ordered by thumbprint so the file is the same on every run.
            return rows.OrderBy(r => (string)r["Store"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["Subject"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["Thumbprint"]!, StringComparer.Ordinal).ToList();
        }

        static object AppControl()
        {
            var lines = new List<string> { "--- AppLocker effective policy ---" };
            lines.Add(AppLocker.EffectiveXml() ?? "AppLocker policy unavailable: no effective policy could be read.");
            lines.Add("--- Device Guard / WDAC status ---");
            try
            {
                var cols = new[] { "SecurityServicesConfigured", "SecurityServicesRunning", "VirtualizationBasedSecurityStatus", "CodeIntegrityPolicyEnforcementStatus" };
                string Cell(object? v) => v is Array a && !(v is string) ? "{" + string.Join(", ", a.Cast<object?>().Select(x => Convert.ToString(x, CultureInfo.InvariantCulture))) + "}"
                    : Convert.ToString(v, CultureInfo.InvariantCulture) ?? "";
                lines.AddRange(Table(cols, Wmi.Query(@"root\Microsoft\Windows\DeviceGuard", "SELECT " + string.Join(", ", cols) + " FROM Win32_DeviceGuard")
                    .Select(d => cols.Select(c => Cell(Raw(d, c))).ToArray())));
            }
            catch (Exception ex) when (WmiFailed(ex)) { lines.Add("DeviceGuard WMI class unavailable"); }
            lines.Add("--- gpresult /r ---");
            lines.Add(Exec.System32("gpresult.exe", "/r"));
            return lines;
        }

        /// <summary>
        /// The Resultant Set of Policy twice: HTML for a person, XML for tools and the console's tree view. Both come from
        /// the endpoint, so the console shows the HTML as text and never renders it.
        /// </summary>
        static object GpResultHtml(FotonSession s) => new[]
        {
            GpResult(s, "/h", "gpresult.html", "gpresult /h written into package. Applied GPO HTML, not Intune MDM report."),
            GpResult(s, "/x", "gpresult.xml", "gpresult /x written into package. The same Resultant Set of Policy as the HTML, as XML."),
        };

        static ToolOutputRow GpResult(FotonSession s, string format, string fileName, string copiedNote)
        {
            var dest = Path.Combine(s.Dir(Cat), fileName);
            var row = new ToolOutputRow
            {
                SourcePath = "gpresult.exe " + format, DestRelative = Path.Combine(CaseCategories.FolderOf(Cat), fileName), Status = "CopyError",
            };
            Exec.System32("gpresult.exe", $"{format} \"{dest}\" /f");
            if (File.Exists(dest))
            {
                row.SizeBytes = new FileInfo(dest).Length;
                row.SHA256 = Hashing.SafeHash(dest, s.Options.SkipHashing);
                row.Status = "Copied";
                row.Note = copiedNote;
            }
            else
            {
                row.Status = "Missing";
                row.Note = $"gpresult {format} produced no file. Visibility gap (policy, elevation, or gpresult failure).";
            }
            return row;
        }
    }
}
