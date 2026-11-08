using System;
using System.IO;
using System.Linq;
using Foton.Analyze;
using Foton.Collect;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    /// <summary>The collect orchestrator on this host (no categories are needed to exercise the package lifecycle).</summary>
    public class CollectTests
    {
        static StatusLog Quiet() => new StatusLog(new StringWriter());

        [Fact]
        public void A_run_writes_a_hashed_case_package_whose_findings_a_workstation_reproduces()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, Examiner = "examiner", CaseNumber = "CASE-0001" }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);

                var col = Path.Combine(r.CaseRoot, "00_Collection");
                foreach (var f in new[] { "chain_of_custody.txt", "collection_coverage.json", "collection_manifest.csv", "collection.log", "findings.csv", "hashes.csv", "hashes.txt" })
                    Assert.True(File.Exists(Path.Combine(col, f)), f);
                Assert.True(File.Exists(r.ReportPath));
                Assert.Contains("CASE-0001", File.ReadAllText(Path.Combine(col, "chain_of_custody.txt")));
                if (Categories.InOrder.Count < CaseCategories.All.Count - 1)
                {
                    Assert.Contains("does not collect yet", File.ReadAllText(Path.Combine(col, "collection.log")));
                    Assert.NotEmpty(r.NotCollected);
                }
                Assert.Contains(Csv.Read(Path.Combine(col, "hashes.csv")), h => h["RelativePath"] == "Foton_Report.html");
                Assert.Equal(r.ZipPath, r.CaseRoot + ".zip");
                Assert.True(File.Exists(r.CaseRoot + "_PACKAGE_HASH.txt"));
                Assert.Equal(Hashing.Sha256Hex(r.ZipPath!), r.ZipSha256);

                // Endpoint analysis reads the written case, so the workstation (given the same empty pattern list) agrees.
                Assert.Contains(s.Findings, f => f.Title == "Suspicious-command pattern matching did not run");
                var again = Analyzer.RunPackage(r.CaseRoot, Quiet(), new string[0]);
                Assert.Equal(File.ReadAllBytes(Path.Combine(col, "findings.csv")), File.ReadAllBytes(again.FindingsPath!));
            }
        }

        [Fact]
        public void System_and_Users_run_every_task_on_this_host_without_task_errors()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                CollectRun.Run(s, only: new[] { "System", "Users" });
                var tasks = s.Manifest.Select(m => m.Task).ToList();
                foreach (var name in new[] { "os_info", "entra_workplace_join", "time_sync", "hotfixes", "boot_and_firmware", "disks_and_volumes", "environment_variables",
                    "system_restore_and_shadowcopies", "local_users", "local_group_membership", "user_profiles", "logged_on_sessions", "password_and_lockout_policy",
                    "user_rights_and_secpol", "rdp_configuration", "stored_credentials_and_trusts" })
                    Assert.Contains(name, tasks);
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.Error || m.Status == TaskStatus.WriteError);
                Assert.Equal(s.Hostname, ((System.Collections.Generic.Dictionary<string, object?>)s.Data["os_info"]!)["Hostname"]);
                Assert.Contains(s.Manifest, m => m.Task == "local_users" && m.Records > 0);
            }
        }

        [Fact]
        public void Group_members_get_Get_LocalGroupMember_class_and_source()
        {
            var machine = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3");
            var msa = new System.Collections.Generic.HashSet<string> { "S-1-5-21-1-2-3-1002" };
            Assert.Equal("Local", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1001", machine, msa));
            Assert.Equal("MicrosoftAccount", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1002", machine, msa));
            Assert.Equal("ActiveDirectory", UserCollection.PrincipalSource("S-1-5-21-9-9-9-1105", machine, msa));
            Assert.Equal("AzureAD", UserCollection.PrincipalSource("S-1-12-1-111-222-333-444", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("S-1-5-4", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("not a sid", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1001", null, msa));
            Assert.True(CloudJoin.IsJoinKeyName("0123456789ABCDEF0123456789abcdef01234567"));
            Assert.True(CloudJoin.IsJoinKeyName("{8F3A1B2C-0000-4D5E-9F10-123456789ABC}"));
            Assert.False(CloudJoin.IsJoinKeyName("Status"));
            var table = CollectText.Table(new[] { "A", "B" }, new[] { new[] { "1", "2", "extra" }, new[] { "only" } }).ToList();
            Assert.Equal(new[] { "", "A    B", "---- -", "1    2", "only", "" }, table);
            Assert.Null(CollectText.DmtfTime("2026-not-a-dmtf"));
            Assert.Equal("", CollectText.Dmtf("99999999999999.999999+999"));
            Assert.Equal(new[] { "User", "Group", "Group", "Group", "" }, new[] { 1, 2, 4, 5, 6 }.Select(UserCollection.ObjectClass));
        }

        [Fact]
        public void Software_runs_every_task_on_this_host_without_task_errors()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true, SkipHashing = true }, Quiet());
                CollectRun.Run(s, only: new[] { "Software" });
                foreach (var name in new[] { "installed_software", "drivers", "browser_extensions", "remote_access_tool_indicators", "appx_packages" })
                    Assert.Contains(s.Manifest, m => m.Task == name);
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.Error || m.Status == TaskStatus.WriteError);
                Assert.Contains(s.Manifest, m => m.Task == "drivers" && m.Records > 0);
                Assert.Contains(s.Manifest, m => m.Task == "appx_packages" && m.Records > 0);
            }
        }

        [Fact]
        public void Authenticode_reads_catalog_and_embedded_signatures_like_Get_AuthenticodeSignature()
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var notepad = Foton.Win.Authenticode.Check(Path.Combine(sys, "notepad.exe"));
            Assert.Equal("Valid", notepad.Status);
            Assert.Contains("Microsoft", notepad.Signer);
            Assert.True(notepad.IsOSBinary);
            using (var t = new TempDir())
            {
                // Reference values from Get-AuthenticodeSignature: a script with no signature, and a type with no signature format.
                File.WriteAllText(t.File("plain.ps1"), "Write-Output 1");
                File.WriteAllText(t.File("plain.txt"), "not signed");
                Assert.Equal("NotSigned", Foton.Win.Authenticode.Check(t.File("plain.ps1")).Status);
                Assert.Equal("UnknownError", Foton.Win.Authenticode.Check(t.File("plain.txt")).Status);
                Assert.Equal("FileNotFound", Foton.Win.Authenticode.Check(t.File("missing.sys")).Status);
            }
            Assert.Equal("Unknown", Foton.Win.Authenticode.Check("").Status);
            Assert.Equal(new[] { "NotSigned", "UnknownError", "NotSigned", "HashMismatch", "HashMismatch", "Valid", "Valid", "NotTrusted", "UnknownError" },
                Enumerable.Range(0, 9).Select(i => Foton.Win.Authenticode.StatusOf((uint)i)));
            Assert.Equal(@"C:\Program Files\x.sys", Foton.Win.Authenticode.Openable(@"\??\C:\Program Files\x.sys"));
            Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\drivers\y.sys"),
                Foton.Win.Authenticode.Openable(@"\SystemRoot\System32\drivers\y.sys"));
            Assert.Equal(@"C:\Windows\z.sys", Foton.Win.Authenticode.Openable(@"C:\Windows\z.sys"));
            Assert.Equal(@"C:\Program Files\q.sys", Foton.Win.Authenticode.Openable(@"""\??\C:\Program Files\q.sys"""));
            Assert.Equal(@"\\server\share\d.sys", Foton.Win.Authenticode.Openable(@"\??\UNC\server\share\d.sys"));
            // Host-supplied paths that are not plainly local are never opened: no SMB connection, no credential offer.
            foreach (var other in new[]
            {
                @"\\server\share\d.sys", @"\\?\UNC\server\share\d.sys", @"\??\UNC\server\share\d.sys", @"""\\10.0.0.5\c$\x.sys""", "//server/share/x.sys",
                @"\??\GLOBALROOT\Device\Mup\server\share\x.sys", @"\\?\GLOBALROOT\Device\Mup\server\share\x.sys", @"\\.\PhysicalDrive0",
            })
            {
                Assert.False(Hashing.IsLocalPath(other), other);
                Assert.Equal("SkippedNonLocalPath", Hashing.SafeHash(other, false));
                Assert.Equal("NonLocalPathNotChecked", Foton.Win.Authenticode.Check(other).Status);
            }
            foreach (var local in new[] { @"C:\Windows\x.sys", @"\\?\C:\Windows\x.sys", @"\\.\C:\x.sys", @"\??\C:\x.sys", @"\\?\Volume{0a1b2c3d-0000-0000-0000-000000000000}\x.sys", @"System32\drivers\x.sys", @"\Windows\x.sys" })
                Assert.True(Hashing.IsLocalPath(local), local);
        }

        [Fact]
        public void Remote_access_matching_reads_dictionary_and_object_rows()
        {
            Assert.Equal("AnyDesk", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, object?> { ["DisplayName"] = "AnyDesk" }, "DisplayName"));
            Assert.Equal("", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, object?>(), "DisplayName"));
            Assert.Equal("svc", SoftwareCollection.Field(new { Name = "svc" }, "Name"));
            Assert.Equal("x", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, string> { ["Path"] = "x" }, "Path"));
        }

        [Fact]
        public void Standard_modules_and_internal_addresses_are_anchored()
        {
            var win = Foton.Win.HostInfo.WindowsDir.TrimEnd('\\');
            Assert.True(ProcessCollection.IsStandardModule(win + @"\System32\kernel32.dll"));
            Assert.True(ProcessCollection.IsStandardModule(Environment.GetEnvironmentVariable("ProgramFiles") + @"\App\x.dll"));
            Assert.False(ProcessCollection.IsStandardModule(@"C:\Users\x\Windows\System32\evil.dll"));
            Assert.False(ProcessCollection.IsStandardModule(@"C:\Users\x\Program Files Fake\evil.dll"));
            foreach (var internalAddress in new[] { "10.1.2.3", "192.168.0.5", "172.20.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "::1", "fe80::1", "ff02::fb", "fd12:3456::1" })
                Assert.False(NetworkCollection.IsExternal(internalAddress), internalAddress);
            foreach (var external in new[] { "8.8.8.8", "172.32.0.1", "2001:4860:4860::8888", "::1:5" })
                Assert.True(NetworkCollection.IsExternal(external), external);
        }

        [Fact]
        public void Process_owner_comes_from_the_token()
        {
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            Assert.Equal(me, new Foton.Win.ProcessOwner().Of(System.Diagnostics.Process.GetCurrentProcess().Id), StringComparer.OrdinalIgnoreCase);
            Assert.Equal("", new Foton.Win.ProcessOwner().Of(-1));
        }

        [Fact]
        public void A_password_never_set_reads_as_never()
        {
            var now = new DateTime(2026, 11, 8, 0, 0, 0, DateTimeKind.Utc);
            Assert.True(Foton.Win.LocalUsers.NeverSet(0, now));
            Assert.True(Foton.Win.LocalUsers.NeverSet(uint.MaxValue, now));
            Assert.False(Foton.Win.LocalUsers.NeverSet(86400, now));
        }

        [Fact]
        public void NoZip_leaves_only_the_case_folder()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);
                Assert.Null(r.ZipPath);
                Assert.Single(Directory.GetFileSystemEntries(t.Path));
            }
        }
    }
}
