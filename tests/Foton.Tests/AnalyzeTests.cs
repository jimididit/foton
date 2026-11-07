using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Foton.Analyze;
using Foton.Core;
using Foton.Patterns;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Analysis matches 1.38.x Invoke-FotonAnalysis on the same packages (golden findings.csv).</summary>
    public class AnalyzeTests
    {
        static readonly StatusLog Quiet = new StatusLog(new StringWriter());
        static string Kitchen => Path.Combine(TestPaths.Root, "testdata", "analyze", "Foton_KITCHEN_20260115-120000Z");

        static string Copy(TempDir t, string source)
        {
            var dst = Path.Combine(t.Path, Path.GetFileName(source));
            foreach (var f in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                var to = Path.Combine(dst, f.Substring(source.Length + 1));
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                File.Copy(f, to);
            }
            return dst;
        }

        [Theory]
        [InlineData("kitchen")]
        [InlineData("fixture")]
        public void Findings_are_byte_identical_to_1_38(string tag)
        {
            using (var t = new TempDir())
            {
                var root = Copy(t, tag == "kitchen" ? Kitchen : TestPaths.Fixture);
                var run = Analyzer.RunPackage(root, Quiet, WorkstationPatterns.SuspiciousCommands);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden($"analyze-{tag}-findings.csv")), File.ReadAllBytes(run.FindingsPath!));
            }
        }

        [Fact]
        public void Without_the_pattern_list_the_gap_is_stated_and_pattern_rules_stay_quiet()
        {
            using (var t = new TempDir())
            {
                var root = Copy(t, Kitchen);
                var titles = Analyzer.RunPackage(root, Quiet, new string[0]).Findings.Select(f => f.Title).ToList();
                Assert.Contains("Suspicious-command pattern matching did not run", titles);
                Assert.DoesNotContain("Running process command lines contain high-risk patterns", titles);
                Assert.DoesNotContain("PowerShell console history contains high-risk commands", titles);
                Assert.DoesNotContain("PowerShell script block logs contain high-risk content", titles);
            }
        }

        [Fact]
        public void Zip_package_writes_findings_beside_the_zip()
        {
            using (var t = new TempDir())
            {
                var zip = t.File("Foton_KITCHEN_20260115-120000Z.zip");
                ZipFile.CreateFromDirectory(Kitchen, zip, CompressionLevel.Fastest, includeBaseDirectory: true);
                var run = Analyzer.RunPackage(zip, Quiet, WorkstationPatterns.SuspiciousCommands);
                Assert.Equal(t.File("Foton_KITCHEN_20260115-120000Z_findings.csv"), run.BesideZipPath);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden("analyze-kitchen-findings.csv")), File.ReadAllBytes(run.BesideZipPath!));
            }
        }

        static AnalysisContext Context(PackageData data, string? caseRoot = null) =>
            new AnalysisContext(data, new List<Dictionary<string, string?>>(), caseRoot, WorkstationPatterns.SuspiciousCommands, PatternLists.UserWritable);

        static object?[] Csv(params Dictionary<string, string?>[] rows) => rows.Select(r => (object?)PackageData.CsvRow(r)).ToArray();

        static List<string> Titles(PackageData d, string? caseRoot = null)
        {
            var c = Context(d, caseRoot);
            Analyzer.Run(c);
            return c.Findings.Select(f => f.Title).ToList();
        }

        [Fact]
        public void Quiet_side_of_firewall_sysmon_and_wdigest()
        {
            var d = new PackageData();
            d.Set("firewall_profiles", Csv(new Dictionary<string, string?> { ["Name"] = "Domain", ["Enabled"] = "True" }));
            d.Set("event_log_configuration", Csv(new Dictionary<string, string?> { ["LogName"] = "Microsoft-Windows-Sysmon/Operational", ["IsEnabled"] = "True" }));
            d.Set("hardening_registry_settings", Csv(new Dictionary<string, string?> { ["Setting"] = "UseLogonCredential", ["Value"] = "0" }));
            d.Set("services", Csv(new Dictionary<string, string?> { ["Name"] = "Sysmon64", ["StartMode"] = "Auto", ["State"] = "Running" }));
            var titles = Titles(d);
            Assert.DoesNotContain("One or more firewall profiles are disabled", titles);
            Assert.DoesNotContain("Sysmon is not installed on this host", titles);
            Assert.DoesNotContain("WDigest cleartext credential storage is enabled", titles);
            Assert.DoesNotContain("Sysmon is installed but not running", titles);
        }

        [Fact]
        public void A_bare_Foton_case_path_is_not_collector_noise()
        {
            using (var t = new TempDir())
            {
                var hay = Path.Combine(t.Path, "analysis", "external", "hayabusa");
                Directory.CreateDirectory(hay);
                File.WriteAllLines(Path.Combine(hay, "hayabusa.csv"), new[]
                {
                    "\"Timestamp\",\"RuleTitle\",\"Level\",\"Computer\",\"Channel\",\"EventID\",\"RecordID\",\"Details\",\"ExtraFieldInfo\",\"RuleID\"",
                    "\"2026-01-01 00:00:00 +00:00\",\"EncodedCommand\",\"high\",\"H\",\"Sec\",4104,1,\"powershell -enc ABC path C:\\Cases\\Foton_HOST_Z\\x\",\"x\",\"id1\"",
                });
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);
                var hi = c.Findings.Single(f => f.Title.Contains("high-level"));
                Assert.Contains("EncodedCommand", hi.Observation);
                Assert.DoesNotContain("Excludes", hi.Observation);
            }
        }

        [Fact]
        public void A_copied_template_name_on_another_binary_is_counted()
        {
            var d = new PackageData();
            d.Set("system_service_and_driver", Csv(new Dictionary<string, string?>
            {
                ["EventId"] = "7045", ["TimeCreatedUtc"] = "2026-01-14 03:01:00",
                ["Message"] = @"A service was installed in the system.  Service Name:  OneSyncSvc_1a2b3c  Service File Name:  C:\Users\Public\x.exe  Service Type:  user mode service",
            }));
            var c = Context(d);
            Analyzer.Run(c);
            Assert.Contains("Services: OneSyncSvc_1a2b3c.", c.Findings.Single(f => f.Title == "Service install events in the exported logs").Observation);
        }

        static string Install(string image, string? dll = null, string? dllSource = null)
        {
            var d = new PackageData();
            d.Set("system_service_and_driver", Csv(new Dictionary<string, string?>
            {
                ["EventId"] = "7045", ["TimeCreatedUtc"] = "2026-01-14 03:01:00",
                ["Message"] = $"A service was installed in the system.  Service Name:  OneSyncSvc_1a2b3c  Service File Name:  {image}  Service Type:  user mode service",
            }));
            if (dll != null)
                d.Set("services", Csv(new Dictionary<string, string?> { ["Name"] = "OneSyncSvc_1a2b3c", ["ServiceDll"] = dll, ["ServiceDllSource"] = dllSource }));
            var c = Context(d);
            Analyzer.Run(c);
            return c.Findings.SingleOrDefault(f => f.Title == "Service install events in the exported logs")?.Observation ?? "";
        }

        [Fact]
        public void Per_user_filter_requires_System32_svchost_itself()
        {
            Assert.Equal("", Install(@"%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup"));
            // 1.38.x filtered these: a System32 launcher whose arguments end in svchost.exe.
            Assert.Contains("OneSyncSvc_1a2b3c", Install(@"C:\Windows\System32\cmd.exe /c C:\Users\Public\svchost.exe"));
            // ...and a ServiceDll in a System32 subfolder whose name contains a space.
            Assert.Contains("OneSyncSvc_1a2b3c", Install(@"%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup", @"C:\Windows\System32\Sub Folder\x.dll", "Template:OneSyncSvc"));
            Assert.Equal("", Install(@"%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup", @"C:\Windows\System32\APHostService.dll", "Template:OneSyncSvc"));
        }

        [Fact]
        public void Cert_Publishers_add_is_privileged_by_SID()
        {
            var d = new PackageData();
            d.Set("security_account_management", Csv(new Dictionary<string, string?>
            {
                ["EventId"] = "4732", ["TimeCreatedUtc"] = "2026-01-14 05:00:05",
                ["Message"] = "A member was added.  Member:  Security ID:  S-1-5-21-1-2-3-1011  Account Name:  -  Group:  Security ID:  S-1-5-21-1-2-3-517  Group Name:  Gruppe  Group Domain:  DOMAIN",
            }));
            var c = Context(d);
            Analyzer.Run(c);
            Assert.Contains("1 addition(s) to privileged groups", c.Findings.Single(f => f.Title == "Accounts created or privileged groups changed in the exported logs").Observation);
        }

        [Fact]
        public void A_failing_rule_group_is_a_stated_gap_and_the_rest_still_run()
        {
            var c = Context(new PackageData());
            Analyzer.Guard(c, "Example", () => throw new InvalidCastException("bad value"));
            var f = c.Findings.Single();
            Assert.Equal("An analysis rule group stopped on unexpected package data", f.Title);
            Assert.Contains("The Example rules stopped", f.Observation);
            Assert.Contains("InvalidCastException: bad value", f.Observation);
        }

        [Fact]
        public void False_positive_text_matches_the_capture_providers()
        {
            foreach (var p in Foton.Baseline.Capture.Providers.All)
                Assert.Equal(p.FalsePositives, BaselineFalsePositives.Of(p.RecordType));
            Assert.Equal(Foton.Baseline.Capture.Providers.All.Count, BaselineFalsePositives.ByRecordType.Count);
        }

        [Fact]
        public void PowerShell_comparison_semantics()
        {
            Assert.True(Ps.Eq("False", false));
            Assert.False(Ps.Eq("", false));
            Assert.True(Ps.Eq(true, "False"));
            Assert.True(Ps.Eq(0, false));
            Assert.True(Ps.Eq("1102", 1102));
            Assert.True(Ps.Eq(1102, "1102"));
            Assert.False(Ps.Eq(null, false));
            Assert.False(Ps.Gt("10", 7));
            Assert.True(Ps.Gt(12, 7));
            Assert.False(Ps.IsTrue(new object?[] { "" }));
            Assert.Equal("System.Object[]|3", Ps.F("{0}|{1}", new object?[] { "x", "y" }, 3));
            Assert.Equal("x", Ps.F("{0}", (object)new object?[] { "x", "y" }));
        }
    }
}
