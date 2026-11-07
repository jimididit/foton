using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using static Foton.Analyze.Ps;

namespace Foton.Analyze
{
    /// <summary>Service and account event normalisation (Get-FotonEventSummaryHelpers).</summary>
    static class EventHelpers
    {
        static readonly string[] PerUserTemplates =
        {
            "AarSvc", "BcastDVRUserService", "BluetoothUserService", "CaptureService", "cbdhsvc",
            "CDPUserSvc", "CloudBackupRestoreSvc", "ConsentUxUserSvc", "CredentialEnrollmentManagerUserSvc",
            "DeviceAssociationBrokerSvc", "DevicePickerUserSvc", "DevicesFlowUserSvc", "LxssManagerUser",
            "MessagingService", "NPSMSvc", "OneSyncSvc", "P9RdrService", "PenService",
            "PimIndexMaintenanceSvc", "PrintWorkflowUserSvc", "UdkUserSvc", "UnistoreSvc", "UserDataSvc",
            "webthreatdefusersvc", "WpnUserService",
        };

        /// <summary>
        /// A per-user instance (OneSyncSvc_1701f8): a known Microsoft template plus a hex logon-session suffix. A bare
        /// Name_hex shape is attacker-choosable, so the base name must be a known template.
        /// </summary>
        public static bool PerUserServiceName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return false;
            var m = Regex.Match(name!.Trim(), "^(?<base>[A-Za-z][A-Za-z0-9]*)_[0-9a-fA-F]{4,8}$");
            return m.Success && In(m.Groups["base"].Value, PerUserTemplates);
        }

        const string NameEnd = @"(?=\s{2,}|\s+Service File Name:|\s+Service Type:|\s+Image Path:|\r|\n|$)";

        /// <summary>Service name from a 7045/4697 row: EvtxECmd PayloadData1 or the native Message.</summary>
        public static string ServiceName(object? row)
        {
            foreach (var field in new[] { "PayloadData1", "Message" })
            {
                var text = Str(Get(row, field));
                if (text.Length == 0) continue;
                // "Service Name:" first: a native 4697 names the subject account ("Account Name:") before the service.
                var m = Regex.Match(text, @"(?i)Service\s?Name:\s+(?<n>.+?)" + NameEnd);
                if (m.Success) return m.Groups["n"].Value.Trim();
                m = Regex.Match(text, @"(?i)^\s*Name:\s+(?<n>.+?)" + NameEnd);
                if (m.Success) return m.Groups["n"].Value.Trim();
            }
            return "";
        }

        static string ServiceImage(object? row)
        {
            var exe = Str(Get(row, "ExecutableInfo"));
            if (exe.Trim().Length > 0) return exe.Trim();
            foreach (var field in new[] { "PayloadData2", "Message" })
            {
                var m = Regex.Match(Str(Get(row, field)), @"(?i)Service\s?File\s?Name:\s+(?<p>.+?)(?=\s{2,}|\s+Service Type:|\r|\n|$)");
                if (m.Success) return m.Groups["p"].Value.Trim();
            }
            return "";
        }

        /// <summary>
        /// System32 as the event may write it: the environment forms, plus the host's own SystemDirectory from
        /// os_info (C:\Windows\System32 when the package does not record one). 1.38.x accepted any drive letter, and
        /// a user can create D:\Windows\System32 on a writable data drive.
        /// </summary>
        static string System32Roots(string systemDirectory)
        {
            var roots = new List<string> { @"%SystemRoot%\\System32", @"%windir%\\System32", @"\\SystemRoot\\System32" };
            roots.Add(systemDirectory.Length > 0 ? Regex.Escape(systemDirectory.TrimEnd('\\')) : @"C:\\Windows\\System32");
            return "(?:" + string.Join("|", roots) + ")";
        }

        /// <summary>
        /// The image is System32's own svchost.exe (any written form of System32), optionally followed by arguments.
        /// 1.38.x accepted any System32 launcher whose arguments ended in svchost.exe.
        /// </summary>
        static bool System32Svchost(string image, string systemDirectory) =>
            Regex.IsMatch(image.Trim(), @"(?i)^""?" + System32Roots(systemDirectory) + @"\\svchost\.exe""?(?:\s|$)", RegexOptions.IgnoreCase);

        /// <summary>
        /// A DLL path that is a file directly in System32, nothing after it. 1.38.x stopped at the first space, so
        /// "System32\Sub Folder\x.dll" passed as a System32 file.
        /// </summary>
        static bool System32Dll(string dll, string systemDirectory) =>
            !dll.Contains("..") && Regex.IsMatch(dll.Trim(), @"(?i)^""?" + System32Roots(systemDirectory) + @"\\[^\\/""]+\.dll""?$", RegexOptions.IgnoreCase);

        /// <summary>
        /// True only for a known per-user template instance hosted by System32 svchost.exe; with services.csv, an
        /// instance whose own ServiceDll is suspect is counted. Unknown is not proof of benign.
        /// </summary>
        public static bool PerUserServiceEvent(object? row, Dictionary<string, object?> serviceIndex, string systemDirectory)
        {
            var name = ServiceName(row);
            if (!PerUserServiceName(name)) return false;
            if (!System32Svchost(ServiceImage(row), systemDirectory)) return false;
            if (serviceIndex.TryGetValue(name, out var svc))
            {
                var dll = Str(Get(svc, "ServiceDll"));
                if (dll.Length > 0)
                {
                    var src = Str(Get(svc, "ServiceDllSource"));
                    if (src.Length > 0 && !Like(src, "Template:*")) return false;
                    if (!System32Dll(dll, systemDirectory)) return false;
                    if (Eq(Str(Get(svc, "ServiceDllUserWritablePath")), "True")) return false;
                    if (In(Str(Get(svc, "ServiceDllSignatureStatus")), "NotSigned", "HashMismatch")) return false;
                }
            }
            return true;
        }

        /// <summary>Name -> services.csv row (first wins), case-insensitive like the PowerShell hashtable.</summary>
        public static Dictionary<string, object?> ServiceIndex(object? services)
        {
            var idx = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in Items(services))
            {
                var n = Get(s, "Name");
                if (s != null && IsTrue(n) && !idx.ContainsKey(Str(n))) idx[Str(n)] = s;
            }
            return idx;
        }

        public sealed class AccountFact
        {
            public string EventId = "";
            public DateTime? TimeUtc;
            public string AccountSid = "", AccountName = "", GroupSid = "", GroupName = "";
        }

        /// <summary>4720 / 4726 / 4728 / 4732 / 4756 from native Message text or EvtxECmd PayloadData columns.</summary>
        public static List<AccountFact> AccountFacts(object? rows)
        {
            var output = new List<AccountFact>();
            foreach (var r in Items(rows))
            {
                if (r == null) continue;
                var eid = Str(Get(r, "EventId"));
                if (eid.Length == 0) eid = Str(Get(r, "EventID"));
                if (!In(eid, "4720", "4726", "4728", "4732", "4756")) continue;
                var tsRaw = Get(r, "TimeCreatedUtc");
                if (!IsTrue(tsRaw)) tsRaw = Get(r, "TimeCreated");
                DateTime? ts = null;
                var tsText = Str(tsRaw);
                if (tsText.Length >= 19 && DateTime.TryParseExact(tsText.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)) ts = d;
                var f = new AccountFact { EventId = eid, TimeUtc = ts };
                var msg = Str(Get(r, "Message"));
                if (msg.Length > 0)
                {
                    // Rendered messages show "Security ID:" as a SID or a resolved DOMAIN\Name; names may contain spaces.
                    if (In(eid, "4720", "4726"))
                    {
                        var m = Regex.Match(msg, @"(?:New Account|Target Account):\s+Security ID:\s+(?<sid>.+?)\s+Account Name:\s+(?<n>.+?)\s+Account Domain:");
                        if (m.Success) { f.AccountSid = m.Groups["sid"].Value.Trim(); f.AccountName = m.Groups["n"].Value.Trim(); }
                    }
                    else
                    {
                        var m = Regex.Match(msg, @"Member:\s+Security ID:\s+(?<sid>.+?)\s+Account Name:");
                        if (m.Success) f.AccountSid = m.Groups["sid"].Value.Trim();
                        var g = Regex.Match(msg, @"Group:\s+Security ID:\s+(?<sid>.+?)\s+Group Name:\s+(?<n>.+?)\s+Group Domain:");
                        if (g.Success) { f.GroupSid = g.Groups["sid"].Value.Trim(); f.GroupName = g.Groups["n"].Value.Trim(); }
                    }
                }
                else
                {
                    var t = Regex.Match(Str(Get(r, "PayloadData1")), @"Target:\s+(?<n>[^(]+?)\s+\((?<sid>S-[\d-]+)\)");
                    if (In(eid, "4720", "4726"))
                    {
                        if (t.Success) { f.AccountName = t.Groups["n"].Value.Split('\\').Last().Trim(); f.AccountSid = t.Groups["sid"].Value; }
                    }
                    else
                    {
                        if (t.Success) { f.GroupName = t.Groups["n"].Value.Split('\\').Last().Trim(); f.GroupSid = t.Groups["sid"].Value; }
                        foreach (var pf in new[] { "PayloadData2", "PayloadData3" })
                        {
                            var ms = Regex.Match(Str(Get(r, pf)), @"MemberSid:\s+(?<sid>S-[\d-]+)");
                            if (ms.Success) f.AccountSid = ms.Groups["sid"].Value;
                        }
                    }
                }
                output.Add(f);
            }
            return output;
        }

        static readonly string[] PrivilegedNames =
        {
            "Administrators", "Power Users", "Account Operators", "Server Operators", "Print Operators",
            "Backup Operators", "Remote Desktop Users", "Distributed COM Users", "Event Log Readers",
            "Hyper-V Administrators", "Remote Management Users", "Domain Admins", "Cert Publishers",
            "Schema Admins", "Enterprise Admins", "Group Policy Creator Owners", "Key Admins", "Enterprise Key Admins",
        };

        /// <summary>Groups granting administrative or remote-access rights (SID first; English names as fallback).</summary>
        static bool PrivilegedGroup(string sid, string name)
        {
            if (Regex.IsMatch(sid, @"^S-1-5-32-(544|547|548|549|550|551|555|562|573|578|580)$", RegexOptions.IgnoreCase)) return true;
            // 517 is Cert Publishers, which the name list already treated as privileged (1.38.x missed it by SID).
            if (Regex.IsMatch(sid, @"^S-1-5-21-[\d-]+-(512|517|518|519|520|526|527)$", RegexOptions.IgnoreCase)) return true;
            foreach (var candidate in new[] { name, sid.Split('\\').Last() })
                if (candidate.Length > 0 && In(candidate.Trim(), PrivilegedNames)) return true;
            return false;
        }

        public sealed class AccountSummary
        {
            public List<AccountFact> Transient = new List<AccountFact>(), Persistent = new List<AccountFact>(), PrivilegedAdds = new List<AccountFact>();
        }

        /// <summary>
        /// Create-then-delete pairs (same SID, deleted within 60 s) are automation, not persistence; group adds
        /// split into privileged and default groups.
        /// </summary>
        public static AccountSummary AccountChanges(List<AccountFact> facts, int transientSeconds = 60)
        {
            var s = new AccountSummary();
            var deletes = facts.Where(f => f.EventId == "4726").ToList();
            foreach (var c in facts.Where(f => f.EventId == "4720"))
            {
                bool paired = deletes.Any(d => d.AccountSid.Length > 0 && Eq(d.AccountSid, c.AccountSid) && c.TimeUtc.HasValue && d.TimeUtc.HasValue
                    && (d.TimeUtc.Value - c.TimeUtc.Value).TotalSeconds >= 0 && (d.TimeUtc.Value - c.TimeUtc.Value).TotalSeconds <= transientSeconds);
                (paired ? s.Transient : s.Persistent).Add(c);
            }
            s.PrivilegedAdds.AddRange(facts.Where(f => In(f.EventId, "4728", "4732", "4756") && PrivilegedGroup(f.GroupSid, f.GroupName)));
            return s;
        }
    }
}
