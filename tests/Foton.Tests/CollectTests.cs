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
