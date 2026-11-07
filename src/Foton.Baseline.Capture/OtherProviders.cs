using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Baseline.Capture.R;

namespace Foton.Baseline.Capture
{
    /// <summary>Providers read from COM, certificate stores, files, and netapi32.</summary>
    static class OtherProviders
    {
        public static Provider BitsJob => new Provider
        {
            RecordType = "BitsJob", IdentityFields = new[] { "JobId" }, ComparedFields = new[] { "DisplayName", "TransferType", "OwnerAccount", "Priority", "ProxyUsage", "NotifyCmdLine" },
            FalsePositives = "Windows Update and Store use BITS. Added/Removed JobIds between captures are common. A new or changed NotifyCmdLine (bitsadmin /SetNotifyCmdLine) is the usual review item, not BytesTransferred.",
            SortKeys = new[] { "JobId" },
            Collect = ctx => ctx.Safe(() => Bits.Jobs().Where(j => j.JobId.Length > 0).Select(j => Row(
                "JobId", j.JobId,
                "DisplayName", j.DisplayName.Length > 0 ? j.DisplayName : "(not set)",
                "TransferType", j.TransferType.Length > 0 ? j.TransferType : "(not set)",
                "OwnerAccount", j.OwnerAccount.Length > 0 ? j.OwnerAccount : "(not set)",
                "Priority", j.Priority.Length > 0 ? j.Priority : "(not set)",
                "ProxyUsage", j.ProxyUsage.Length > 0 ? j.ProxyUsage : "(not set)",
                // 1.14.0 wrote the program and parameters joined by a space, so an unset command read " ".
                "NotifyCmdLine", j.NotifyProgram.Length == 0 && j.NotifyParameters.Length == 0 ? "(not set)" : j.NotifyProgram + " " + j.NotifyParameters))),
        };

        static readonly KeyValuePair<string, StoreName>[] Stores =
        {
            new KeyValuePair<string, StoreName>(@"Cert:\LocalMachine\Root", StoreName.Root),
            new KeyValuePair<string, StoreName>(@"Cert:\LocalMachine\CA", StoreName.CertificateAuthority),
            new KeyValuePair<string, StoreName>(@"Cert:\LocalMachine\TrustedPublisher", StoreName.TrustedPublisher),
        };

        public static Provider Certificate => new Provider
        {
            RecordType = "Certificate", IdentityFields = new[] { "Store", "Thumbprint" }, ComparedFields = new[] { "Subject", "Issuer", "NotAfter" },
            FalsePositives = "Enterprise Root CA rollout and Intune add roots. A new Root thumbprint that is not Microsoft/your org CA is the usual review item. Renewal changes NotAfter for the same thumbprint only if the cert is reissued with the same key - often a new thumbprint (Added+Removed).",
            SortKeys = new[] { "Store", "Thumbprint" },
            Collect = ctx => Stores.SelectMany(s => ctx.Safe(() =>
            {
                var rows = new List<Dictionary<string, object?>>();
                using (var store = new X509Store(s.Value, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    foreach (var c in store.Certificates)
                        rows.Add(Row("Store", s.Key, "Thumbprint", c.Thumbprint ?? "", "Subject", c.Subject, "Issuer", c.Issuer, "NotAfter", FotonTime.Format(c.NotAfter.ToUniversalTime())));
                }
                return rows;
            })),
        };

        static readonly Regex Whitespace = new Regex(@"\s+");

        public static Provider HostsEntry => new Provider
        {
            RecordType = "HostsEntry", IdentityFields = new[] { "Address", "Hostname" }, ComparedFields = new string[0],
            FalsePositives = "Local development (localhost, kubernetes.docker.internal), ad-block lists, and MDM-managed hosts files. IPv6 localhost (::1) is expected.",
            SortKeys = new[] { "Address", "Hostname" },
            Collect = ctx => ctx.Safe(() =>
            {
                var rows = new List<Dictionary<string, object?>>();
                var path = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"System32\drivers\etc\hosts");
                if (!File.Exists(path)) return rows;
                // Windows PowerShell 5.1 Get-Content read a BOM-less file as the ANSI code page.
                using (var r = new StreamReader(path, Encoding.Default, detectEncodingFromByteOrderMarks: true))
                    for (var line = r.ReadLine(); line != null; line = r.ReadLine())
                    {
                        var t = line.Trim();
                        if (t.Length == 0 || t.StartsWith("#", StringComparison.Ordinal)) continue;
                        int hash = t.IndexOf('#');
                        if (hash >= 0) t = t.Substring(0, hash).Trim();
                        var parts = Whitespace.Split(t).Where(p => p.Length > 0).ToArray();
                        for (int i = 1; i < parts.Length; i++) rows.Add(Row("Address", parts[0], "Hostname", parts[i]));
                    }
                return rows;
            }),
        };

        public static Provider LocalGroupMember => new Provider
        {
            RecordType = "LocalGroupMember", IdentityFields = new[] { "Group", "SID" }, ComparedFields = new[] { "Member" },
            FalsePositives = "Domain join adds Domain Admins. Intune/LAPS may add a local admin. Compare to the role golden image, not a random workstation.",
            SortKeys = new[] { "Group", "SID" },
            Collect = ctx => ctx.Safe(() => LocalGroups.Groups().SelectMany(g => ctx.Safe(() => LocalGroups.Members(g)
                .Select(m => Row("Group", m.Group, "SID", m.Sid, "Member", m.Member))))),
        };

        public static Provider StartupFile => new Provider
        {
            RecordType = "StartupFile", IdentityFields = new[] { "Scope", "FileName" }, ComparedFields = new[] { "Sha256", "Length" },
            FalsePositives = "Vendor updaters drop .lnk files here. Per-user rows follow who has a profile on disk, not who is logged on. desktop.ini is omitted.",
            SortKeys = new[] { "Scope", "FileName" },
            Collect = ctx =>
            {
                var dirs = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("Common", Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData", @"Microsoft\Windows\Start Menu\Programs\StartUp")),
                };
                dirs.AddRange(ctx.Profiles.Where(p => p.Exists).Select(p => new KeyValuePair<string, string>(p.Sid, Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))));
                return dirs.SelectMany(d => ctx.Safe(() =>
                    !HostInfo.Accessible(d.Value) ? Enumerable.Empty<Dictionary<string, object?>>()
                    : Directory.GetFiles(d.Value).Select(f => new FileInfo(f))
                        .Where(f => !string.Equals(f.Name, "desktop.ini", StringComparison.OrdinalIgnoreCase))
                        .Select(f => Row("Scope", d.Key, "FileName", f.Name, "Path", f.FullName, "Length", f.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), "Sha256", Hashing.SafeHash(f.FullName, false)))));
            },
        };

        static readonly string[] SystemBinaries =
        {
            "ntdll.dll", "kernel32.dll", "cmd.exe", "powershell.exe", "pwsh.exe",
            "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe",
            "explorer.exe", "userinit.exe", "svchost.exe", "conhost.exe",
            "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
            "mmc.exe", "netsh.exe", "taskhostw.exe",
        };

        public static Provider SystemBinary => new Provider
        {
            RecordType = "SystemBinary", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "Sha256", "Length" },
            FalsePositives = "Patch Tuesday and servicing stack replace these binaries. Missing optional files (pwsh.exe) appear as Added when first installed, not as FileNotFound rows.",
            SortKeys = new[] { "Name" },
            Collect = ctx =>
            {
                var root = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32");
                return SystemBinaries.Select(n => Path.Combine(root, n)).Where(File.Exists).Select(p =>
                {
                    string len;
                    try { len = new FileInfo(p).Length.ToString(System.Globalization.CultureInfo.InvariantCulture); } catch (Exception) { len = ""; }
                    return Row("Name", Path.GetFileName(p), "Path", p, "Length", len, "Sha256", Hashing.SafeHash(p, false));
                });
            },
        };

        public static Provider WdacApplockerPolicy => new Provider
        {
            RecordType = "WdacApplockerPolicy", IdentityFields = new[] { "Kind", "Name" }, ComparedFields = new[] { "PolicyHash", "Path" },
            FalsePositives = "Windows Update and WDAC/AppLocker MDM refresh change PolicyHash without a local operator edit. Compare is change between snapshots, not who published the policy.",
            SortKeys = new[] { "Kind", "Name" },
            Collect = ctx =>
            {
                var ci = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", @"System32\CodeIntegrity");
                var si = Path.Combine(ci, "SiPolicy.p7b");
                var rows = new List<Dictionary<string, object?>>
                {
                    Row("Kind", "Wdac", "Name", "SiPolicy.p7b", "Path", si, "PolicyHash", File.Exists(si) ? Hashing.SafeHash(si, false) : "(not present)"),
                };
                rows.AddRange(ctx.Safe(() => Directory.Exists(ci)
                    ? Directory.GetFiles(ci, "*.cip").Select(f => Row("Kind", "WdacCip", "Name", Path.GetFileName(f), "Path", f, "PolicyHash", Hashing.SafeHash(f, false)))
                    : Enumerable.Empty<Dictionary<string, object?>>()));
                var xml = AppLocker.EffectiveXml();
                // Path names the source 1.38.x read; it is a compared field, so the label stays the same.
                rows.Add(Row("Kind", "AppLocker", "Name", "EffectiveXml", "Path", "Get-AppLockerPolicy -Effective -Xml",
                    "PolicyHash", string.IsNullOrEmpty(xml) ? "(not present)" : Hashing.Sha256Hex(Encoding.UTF8.GetBytes(xml))));
                return rows;
            },
        };
    }
}
