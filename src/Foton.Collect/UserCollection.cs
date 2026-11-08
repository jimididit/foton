using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>Accounts, groups, sessions, RDP, and credentials (Invoke-FotonUserCollection).</summary>
    public static class UserCollection
    {
        const string Cat = "Users", Cimv2 = @"root\cimv2";
        const string Ts = @"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server";
        const string RdpTcp = Ts + @"\WinStations\RDP-Tcp";
        static readonly SecurityIdentifier RemoteDesktopUsers = new SecurityIdentifier("S-1-5-32-555");

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting accounts, groups, sessions, and access configuration", StatusLevel.Step);
            // Local account SIDs from whichever read worked: they give this machine's account domain for PrincipalSource.
            var sids = new List<string>();
            var msa = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Task(s, Cat, "local_users", "Local user accounts and password state", TaskFormat.Csv, () => Users(sids, msa));
            Task(s, Cat, "local_group_membership", "Members of every local group (privilege mapping)", TaskFormat.Csv, () => GroupMembership(sids, msa));
            Task(s, Cat, "user_profiles", "Profiles present on disk with SID mapping", TaskFormat.Csv, () => HostInfo.Profiles(s.IsElevated).Select(p => new Dictionary<string, object?>
            {
                ["SID"] = p.Sid, ["UserName"] = p.UserName, ["ProfilePath"] = p.ProfilePath, ["Exists"] = p.Exists,
                ["HiveLoaded"] = Reg.Exists(@"Registry::HKEY_USERS\" + p.Sid),
            }).ToList());
            Task(s, Cat, "logged_on_sessions", "Current interactive and remote sessions", TaskFormat.Txt, Sessions);
            Task(s, Cat, "password_and_lockout_policy", "Local account policy (net accounts)", TaskFormat.Txt, () => Exec.System32("net.exe", "accounts"));
            Task(s, Cat, "user_rights_and_secpol", "Security policy export (secedit)", TaskFormat.Txt, SecurityPolicy, elevated: true);
            Task(s, Cat, "rdp_configuration", "Remote Desktop enablement and NLA state", TaskFormat.Json, Rdp);
            Task(s, Cat, "stored_credentials_and_trusts", "Credential manager entries and domain trust state", TaskFormat.Txt, Credentials);
        }

        static object Users(List<string> sids, ISet<string> msa)
        {
            string When(DateTime? t) => t.HasValue ? FotonTime.Format(t.Value) : "Never";
            List<LocalUser> read;
            try { read = LocalUsers.All(); }
            catch (InvalidOperationException)
            {
                // The SAM read failed: fall back to WMI, which has no logon or password times. Win32_UserAccount's
                // PasswordExpires is a yes/no flag, not the expiry date this column holds, so it is left blank.
                var rows = Wmi.Query(Cimv2, "SELECT Name, Disabled, SID, Description, PasswordRequired, PasswordChangeable FROM Win32_UserAccount WHERE LocalAccount=True")
                    .Select(u => new Dictionary<string, object?>
                    {
                        ["Name"] = Raw(u, "Name"), ["Enabled"] = !(Raw(u, "Disabled") as bool? ?? false), ["SID"] = Raw(u, "SID"), ["Description"] = Raw(u, "Description"),
                        ["LastLogon"] = "", ["PasswordLastSet"] = "", ["PasswordRequired"] = Raw(u, "PasswordRequired"), ["PasswordExpires"] = "",
                        ["UserMayChangePassword"] = Raw(u, "PasswordChangeable"), ["AccountExpires"] = "",
                    }).ToList();
                sids.AddRange(rows.Select(r => r["SID"] as string ?? "").Where(v => v.Length > 0));
                return rows;
            }
            sids.AddRange(read.Select(u => u.Sid));
            foreach (var u in read.Where(u => u.MicrosoftAccount)) msa.Add(u.Sid);
            return read.Select(u => new Dictionary<string, object?>
            {
                ["Name"] = u.Name, ["Enabled"] = u.Enabled, ["SID"] = u.Sid, ["Description"] = u.Description,
                ["LastLogon"] = When(u.LastLogonUtc), ["PasswordLastSet"] = When(u.PasswordLastSetUtc), ["PasswordRequired"] = u.PasswordRequired,
                ["PasswordExpires"] = u.PasswordExpiresUtc.HasValue ? FotonTime.Format(u.PasswordExpiresUtc.Value) : "",
                ["UserMayChangePassword"] = u.UserMayChangePassword,
                ["AccountExpires"] = u.AccountExpiresUtc.HasValue ? u.AccountExpiresUtc.Value.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) : "Never",
            }).ToList();
        }

        /// <summary>
        /// Every local group's members. A member SID that cannot be resolved stays a row (Get-LocalGroupMember failed the
        /// whole group with error 1789 and lost it, Administrators included); a group that cannot be read is an error row.
        /// </summary>
        static object GroupMembership(IReadOnlyList<string> localSids, ISet<string> msa)
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, object?> Row(string g, string m, string cls, string src, string sid) =>
                new Dictionary<string, object?> { ["Group"] = g, ["Member"] = m, ["ObjectClass"] = cls, ["PrincipalSource"] = src, ["SID"] = sid };
            var machine = localSids.Select(v => Sid(v)?.AccountDomainSid).FirstOrDefault(d => d != null);
            List<string> groups;
            try { groups = LocalGroups.Groups(); }
            catch (InvalidOperationException ex)
            {
                rows.Add(Row("ERROR", ex.Message, "", "", ""));
                return rows;
            }
            // Get-LocalGroup order: this machine's groups, then the built-in (S-1-5-32) groups, each in SAM order.
            groups = groups.Where(g => !IsBuiltin(g)).Concat(groups.Where(IsBuiltin)).ToList();
            foreach (var g in groups)
            {
                List<GroupMember> members;
                try { members = LocalGroups.Members(g); }
                catch (InvalidOperationException ex)
                {
                    rows.Add(Row(g, $"(error: {ex.Message})", "", "", ""));
                    continue;
                }
                if (members.Count == 0) rows.Add(Row(g, "(none)", "", "NetApi", ""));
                foreach (var m in members.OrderBy(m => m.Member, StringComparer.InvariantCultureIgnoreCase))
                    rows.Add(Row(g, m.Member, ObjectClass(m.SidUsage), PrincipalSource(m.Sid, machine, msa), m.Sid));
            }
            return rows;
        }

        static bool IsBuiltin(string group)
        {
            try { return ((SecurityIdentifier)new NTAccount(group).Translate(typeof(SecurityIdentifier))).Value.StartsWith("S-1-5-32-", StringComparison.Ordinal); }
            catch (Exception ex) when (ex is IdentityNotMappedException || ex is SystemException) { return true; }
        }

        internal static string ObjectClass(int sidUsage) => sidUsage == 1 ? "User" : sidUsage == 2 || sidUsage == 4 || sidUsage == 5 ? "Group" : sidUsage == 9 ? "Computer" : "";

        /// <summary>Get-LocalGroupMember's PrincipalSource: Entra (S-1-12-1), this machine's accounts, a domain, or a well-known principal.</summary>
        internal static string PrincipalSource(string sid, SecurityIdentifier? machine, ISet<string> msa)
        {
            if (sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)) return "AzureAD";
            var domain = Sid(sid)?.AccountDomainSid;
            // Without this machine's account domain, local and domain accounts cannot be told apart: say so, never guess.
            if (domain == null || machine == null) return "Unknown";
            if (domain.Equals(machine)) return msa.Contains(sid) ? "MicrosoftAccount" : "Local";
            return "ActiveDirectory";
        }

        static SecurityIdentifier? Sid(string value)
        {
            try { return value.Length == 0 ? null : new SecurityIdentifier(value); }
            catch (ArgumentException) { return null; }
        }

        static readonly Regex AccountRef = new Regex(@"Domain=""(?<d>(?:[^""\\]|\\.)*)"",Name=""(?<n>(?:[^""\\]|\\.)*)""");

        static object Sessions()
        {
            var lines = new List<string>
            {
                "--- query user ---", Exec.System32("query.exe", "user"),
                "--- query session ---", Exec.System32("query.exe", "session"),
                "--- Win32_LogonSession (interactive/remote) ---",
            };
            try
            {
                lines.AddRange(Table(new[] { "LogonId", "LogonType", "AuthenticationPackage", "StartTimeUtc" },
                    Wmi.Query(Cimv2, "SELECT LogonId, LogonType, AuthenticationPackage, StartTime FROM Win32_LogonSession")
                        .Select(l => new[] { Wmi.Str(l, "LogonId"), Wmi.Str(l, "LogonType"), Wmi.Str(l, "AuthenticationPackage"), Dmtf(Raw(l, "StartTime")) })));
            }
            catch (Exception ex) when (WmiFailed(ex)) { lines.Add("Error: " + ex.Message); }
            lines.Add("--- Logged on users (Win32_LoggedOnUser) ---");
            try
            {
                var accounts = Wmi.Query(Cimv2, "SELECT Antecedent FROM Win32_LoggedOnUser")
                    .Select(r => AccountRef.Match(Wmi.Str(r, "Antecedent"))).Where(m => m.Success)
                    .Select(m => new[] { m.Groups["d"].Value.Replace(@"\\", @"\"), m.Groups["n"].Value.Replace(@"\\", @"\") })
                    .GroupBy(a => a[0] + "\\" + a[1], StringComparer.OrdinalIgnoreCase).Select(g => g.First());
                lines.AddRange(Table(new[] { "Domain", "Name" }, accounts));
            }
            catch (Exception ex) when (WmiFailed(ex)) { lines.Add("Error: " + ex.Message); }
            return lines;
        }

        static object SecurityPolicy()
        {
            var tmp = Path.Combine(Path.GetTempPath(), "foton_secpol_" + Guid.NewGuid().ToString("N") + ".inf");
            try
            {
                Exec.System32("secedit.exe", $"/export /cfg \"{tmp}\" /quiet");
                return File.Exists(tmp) ? File.ReadAllText(tmp) : "secedit export unavailable (requires elevation).";
            }
            finally { try { File.Delete(tmp); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { } }
        }

        static object Rdp()
        {
            // The group is resolved by its well-known SID; its name is localized on non-English Windows.
            string rdpUsers = "unavailable";
            try
            {
                var name = ((NTAccount)RemoteDesktopUsers.Translate(typeof(NTAccount))).Value;
                rdpUsers = string.Join("; ", LocalGroups.Members(name.Substring(name.IndexOf('\\') + 1)).Select(m => m.Member));
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is IdentityNotMappedException || ex is SystemException) { }
            var deny = Reg.Value(Ts, "fDenyTSConnections");
            return new Dictionary<string, object?>
            {
                ["DenyTSConnections"] = deny,
                ["RdpEnabled"] = deny is int d && d == 0,
                ["UserAuthentication"] = Reg.Value(RdpTcp, "UserAuthentication"),
                ["SecurityLayer"] = Reg.Value(RdpTcp, "SecurityLayer"),
                ["PortNumber"] = Reg.Value(RdpTcp, "PortNumber"),
                ["AllowRemoteRPC"] = Reg.Value(Ts, "AllowRemoteRPC"),
                ["RemoteDesktopUsers"] = rdpUsers,
                ["ShadowSetting"] = Reg.Value(RdpTcp, "Shadow"),
            };
        }

        static object Credentials()
        {
            var lines = new List<string>
            {
                "--- cmdkey /list ---", Exec.System32("cmdkey.exe", "/list"),
                "--- nltest /domain_trusts ---", Exec.System32("nltest.exe", "/domain_trusts"),
                "--- Vault directories present ---",
            };
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            foreach (var p in new[] { Path.Combine(local, @"Microsoft\Vault"), Path.Combine(roaming, @"Microsoft\Credentials"), Path.Combine(local, @"Microsoft\Credentials") })
            {
                if (!HostInfo.Accessible(p)) continue;
                lines.Add("PATH: " + p);
                var entries = new List<string[]>();
                try
                {
                    foreach (var e in new DirectoryInfo(p).EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
                        entries.Add(new[] { e.FullName, e is FileInfo f ? f.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) : "", FotonTime.Format(e.LastWriteTimeUtc) });
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                lines.AddRange(Table(new[] { "FullName", "Length", "LastWriteTimeUtc" }, entries));
            }
            return lines;
        }
    }
}
