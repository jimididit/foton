using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using Foton.Win;
using static Foton.Baseline.Capture.R;

namespace Foton.Baseline.Capture
{
    // The CDXML enums Get-NetFirewallRule rendered through [string] (NetSecurity module, same names and values).
    enum FwDirection { Inbound = 1, Outbound = 2 }
    enum FwAction { NotConfigured = 0, Allow = 2, Block = 4 }
    enum FwEnabled { True = 1, False = 2 }
    [Flags] enum FwProfile { Any = 0, Domain = 1, Private = 2, Public = 4, NotApplicable = 65535 }

    /// <summary>Providers read through WMI (the classes behind the 1.38.x CIM cmdlets).</summary>
    static class WmiProviders
    {
        static string Enum<T>(object? v) where T : struct
        {
            if (v == null || v == Wmi.NotReported) return "";
            try { return System.Enum.ToObject(typeof(T), Convert.ToInt32(v)).ToString(); }
            catch (Exception) { return S(v); }
        }

        /// <summary>
        /// A Defender switch as 1.38.x [string] rendered it, except a property this Defender platform no
        /// longer reports is "(not reported)" (1.14.0 wrote "", which read like "not configured").
        /// </summary>
        static string DefenderValue(ManagementBaseObject p, string name)
        {
            var v = Wmi.Prop(p, name);
            return v == Wmi.NotReported ? "(not reported)" : S(v);
        }

        public static Provider DefenderPreference => new Provider
        {
            RecordType = "DefenderPreference", IdentityFields = new[] { "Kind", "Name" }, ComparedFields = new[] { "Value" },
            FalsePositives = "Intune, GPO, and tamper-protection UI change these. An exclusion add is a new row (Kind + path), not proof of compromise.",
            SortKeys = new[] { "Kind", "Name" },
            Collect = ctx => ctx.Safe(() =>
            {
                var p = Wmi.Query(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpPreference").FirstOrDefault();
                if (p == null) return Enumerable.Empty<Dictionary<string, object?>>();
                var rows = new[]
                {
                    "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableScriptScanning", "DisableArchiveScanning",
                    "DisableIOAVProtection", "DisableIntrusionPreventionSystem", "DisableBlockAtFirstSeen", "MAPSReporting",
                    "SubmitSamplesConsent", "PUAProtection", "EnableControlledFolderAccess",
                }.Select(n => Row("Kind", "Switch", "Name", n, "Value", DefenderValue(p, n))).ToList();
                foreach (var kind in new[] { "ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress" })
                {
                    var items = (Wmi.Prop(p, kind) as string[] ?? new string[0]).Where(s => !string.IsNullOrEmpty(s))
                        .Distinct(StringComparer.InvariantCultureIgnoreCase).OrderBy(s => s, StringComparer.InvariantCultureIgnoreCase);
                    rows.AddRange(items.Select(s => Row("Kind", kind, "Name", s, "Value", "listed")));
                }
                return rows;
            }),
        };

        public static Provider Driver => new Provider
        {
            RecordType = "Driver", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "DisplayName", "StartMode", "PathName" },
            FalsePositives = "Windows Update replaces driver PathName. Catalog-signed drivers still show odd signature status in Collect; this snapshot does not include signature.",
            SortKeys = new[] { "Name" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\cimv2", "SELECT Name, DisplayName, StartMode, PathName FROM Win32_SystemDriver").Select(d =>
            {
                var path = Wmi.Str(d, "PathName");
                if (path.Length > 0) path = Environment.ExpandEnvironmentVariables(path.Trim('"'));
                return Row("Name", Wmi.Str(d, "Name"), "DisplayName", Wmi.Str(d, "DisplayName"), "StartMode", Wmi.Str(d, "StartMode"), "PathName", path);
            })),
        };

        public static Provider FirewallRule => new Provider
        {
            RecordType = "FirewallRule", IdentityFields = new[] { "Name", "Direction" }, ComparedFields = new[] { "Action", "Enabled", "Profile" },
            FalsePositives = "Windows and vendor installers add allow rules. A new inbound Allow is worth review; a new outbound Allow is common.",
            SortKeys = new[] { "Name", "Direction" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\StandardCimv2", "SELECT * FROM MSFT_NetFirewallRule").Select(r => Row(
                // Get-NetFirewallRule's Name and Profile are CDXML aliases for InstanceID and Profiles.
                "Name", Wmi.Str(r, "InstanceID"),
                "Direction", Enum<FwDirection>(Wmi.Prop(r, "Direction")),
                "Action", Enum<FwAction>(Wmi.Prop(r, "Action")),
                "Enabled", Enum<FwEnabled>(Wmi.Prop(r, "Enabled")),
                "Profile", Enum<FwProfile>(Wmi.Prop(r, "Profiles"))))),
        };

        public static Provider Listener => new Provider
        {
            RecordType = "Listener", IdentityFields = new[] { "Protocol", "LocalAddress", "LocalPort" }, ComparedFields = new string[0],
            FalsePositives = "New TCP listeners from debug servers and WinRM. UDP above 49151 is omitted on purpose. Wildcard 0.0.0.0 vs a specific bind looks like remove+add.",
            SortKeys = new[] { "Protocol", "LocalPort", "LocalAddress" },
            Collect = ctx =>
            {
                // State 2 = Listen. Ephemeral UDP (49152-65535) is process-lifetime noise, not stable config.
                var rows = ctx.Safe(() => Wmi.Query(@"root\StandardCimv2", "SELECT LocalAddress, LocalPort FROM MSFT_NetTCPConnection WHERE State = 2")
                    .Select(c => Row("Protocol", "TCP", "LocalAddress", Wmi.Str(c, "LocalAddress"), "LocalPort", Wmi.Str(c, "LocalPort")))).ToList();
                rows.AddRange(ctx.Safe(() => Wmi.Query(@"root\StandardCimv2", "SELECT LocalAddress, LocalPort FROM MSFT_NetUDPEndpoint")
                    .Where(u => !(int.TryParse(Wmi.Str(u, "LocalPort"), out var port) && port >= 49152))
                    .Select(u => Row("Protocol", "UDP", "LocalAddress", Wmi.Str(u, "LocalAddress"), "LocalPort", Wmi.Str(u, "LocalPort")))));
                return rows;
            },
        };

        public static Provider LocalAccount => new Provider
        {
            RecordType = "LocalAccount", IdentityFields = new[] { "SID" }, ComparedFields = new[] { "Name", "Enabled", "PasswordRequired", "PasswordExpires" },
            FalsePositives = "Built-in accounts differ by Windows edition. Enabled Guest is unusual; a renamed Administrator SID is still S-1-5-21-*-500.",
            SortKeys = new[] { "SID" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\cimv2", "SELECT SID, Name, Disabled, PasswordRequired, PasswordExpires FROM Win32_UserAccount WHERE LocalAccount = True").Select(u => Row(
                "SID", Wmi.Str(u, "SID"),
                "Name", Wmi.Str(u, "Name"),
                "Enabled", !(Wmi.Prop(u, "Disabled") is bool d && d),
                "PasswordRequired", Wmi.Prop(u, "PasswordRequired") is bool r && r,
                "PasswordExpires", Wmi.Prop(u, "PasswordExpires") is bool x && x))),
        };

        public static Provider NetworkShare => new Provider
        {
            RecordType = "NetworkShare", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "Path", "Type", "Description" },
            FalsePositives = "Print and scan shares, OneDrive/File History, and C$/ADMIN$/IPC$ are normal. Type is the Win32_Share numeric type, not a verdict.",
            SortKeys = new[] { "Name" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\cimv2", "SELECT Name, Path, Type, Description FROM Win32_Share").Select(s => Row(
                "Name", Wmi.Str(s, "Name"), "Path", Wmi.Str(s, "Path"), "Type", Wmi.Str(s, "Type"), "Description", Wmi.Str(s, "Description")))),
        };

        static readonly string[] RunLevels = { "Limited", "Highest" };

        public static Provider ScheduledTask => new Provider
        {
            RecordType = "ScheduledTask", IdentityFields = new[] { "TaskPath", "TaskName" }, ComparedFields = new[] { "Actions", "RunAsUser", "RunLevel", "Triggers" },
            FalsePositives = "Vendor software registers tasks after install. Root-folder SYSTEM tasks are more interesting than nested Microsoft\\Windows tasks, but still often legitimate.",
            SortKeys = new[] { "TaskPath", "TaskName" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\Microsoft\Windows\TaskScheduler", "SELECT TaskPath, TaskName, Actions, Triggers, Principal FROM MSFT_ScheduledTask").Select(t =>
            {
                var actions = new List<string>();
                foreach (var a in Wmi.Prop(t, "Actions") as ManagementBaseObject[] ?? new ManagementBaseObject[0])
                {
                    var exe = Wmi.Str(a, "Execute");
                    if (exe.Length > 0) actions.Add(exe + " " + Wmi.Str(a, "Arguments"));
                    else
                    {
                        var cls = Wmi.Str(a, "ClassId");
                        if (cls.Length > 0) actions.Add("COM:" + cls);
                    }
                }
                var triggers = (Wmi.Prop(t, "Triggers") as ManagementBaseObject[] ?? new ManagementBaseObject[0])
                    .Where(x => x != null).Select(x => x.ClassPath.ClassName);
                var principal = Wmi.Prop(t, "Principal") as ManagementBaseObject;
                var runLevel = "";
                if (principal != null && Wmi.Prop(principal, "RunLevel") is object rl && rl != Wmi.NotReported)
                {
                    var i = Convert.ToInt32(rl);
                    runLevel = i >= 0 && i < RunLevels.Length ? RunLevels[i] : i.ToString();
                }
                return Row(
                    "TaskPath", Wmi.Str(t, "TaskPath"),
                    "TaskName", Wmi.Str(t, "TaskName"),
                    "Actions", string.Join(" | ", actions),
                    "RunAsUser", principal == null ? "" : Wmi.Str(principal, "UserId"),
                    "RunLevel", runLevel,
                    "Triggers", string.Join(",", triggers));
            })),
        };

        public static Provider Service => new Provider
        {
            RecordType = "Service", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "DisplayName", "StartMode", "StartName", "PathName" },
            FalsePositives = "Patch Tuesday can replace PathName for the same service. Third-party updaters change StartMode. Compare against a provisioning snapshot, not a post-compromise one.",
            SortKeys = new[] { "Name" },
            Collect = ctx => ctx.Safe(() => Wmi.Query(@"root\cimv2", "SELECT Name, DisplayName, StartMode, StartName, PathName FROM Win32_Service").Select(s => Row(
                "Name", Wmi.Str(s, "Name"), "DisplayName", Wmi.Str(s, "DisplayName"), "StartMode", Wmi.Str(s, "StartMode"),
                "StartName", Wmi.Str(s, "StartName"), "PathName", Wmi.Str(s, "PathName")))),
        };

        public static Provider WmiPermanentEvent => new Provider
        {
            RecordType = "WmiPermanentEvent", IdentityFields = new[] { "Kind", "Name" }, ComparedFields = new[] { "Detail" },
            FalsePositives = "ConfigMgr, Defender, and backup agents register WMI consumers. Empty on many home images. Unelevated capture may return zero rows (visibility gap, not proof of absence).",
            SortKeys = new[] { "Kind", "Name" },
            Collect = ctx =>
            {
                const string ns = @"root\subscription";
                var rows = ctx.Safe(() => Wmi.Query(ns, "SELECT Name, Query FROM __EventFilter").Select(f => Row("Kind", "EventFilter", "Name", Wmi.Str(f, "Name"), "Detail", Wmi.Str(f, "Query")))).ToList();
                rows.AddRange(ctx.Safe(() => Wmi.Query(ns, "SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer").Select(c => Row("Kind", "CommandLineConsumer", "Name", Wmi.Str(c, "Name"), "Detail", Wmi.Str(c, "CommandLineTemplate")))));
                rows.AddRange(ctx.Safe(() => Wmi.Query(ns, "SELECT Name, ScriptText FROM ActiveScriptEventConsumer").Select(c =>
                {
                    var text = Wmi.Str(c, "ScriptText");
                    return Row("Kind", "ActiveScriptConsumer", "Name", Wmi.Str(c, "Name"), "Detail", text.Length > 400 ? text.Substring(0, 400) : text);
                })));
                rows.AddRange(ctx.Safe(() => Wmi.Query(ns, "SELECT Filter, Consumer FROM __FilterToConsumerBinding").Select(b =>
                {
                    var f = Wmi.CimRefString(Wmi.Str(b, "Filter"));
                    var c = Wmi.CimRefString(Wmi.Str(b, "Consumer"));
                    return Row("Kind", "Binding", "Name", f + "=>" + c, "Detail", f + " => " + c);
                })));
                return rows;
            },
        };
    }
}
