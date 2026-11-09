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

        // Goldens are 1.38.x output with deliberate v2 changes only: the collector-footprint finding names the v2
        // collector as well as the PowerShell one (Phase 5a).
        [Theory]
        [InlineData("kitchen")]
        [InlineData("fixture")]
        public void Findings_are_byte_identical_to_the_golden_output(string tag)
        {
            using (var t = new TempDir())
            {
                var root = Copy(t, tag == "kitchen" ? Kitchen : TestPaths.Fixture);
                var run = Analyzer.RunPackage(root, Quiet, WorkstationPatterns.SuspiciousCommands);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden($"analyze-{tag}-findings.csv")), File.ReadAllBytes(run.FindingsPath!));
            }
        }

        [Theory]
        [InlineData("kitchen")]
        [InlineData("fixture")]
        public void Triage_report_matches_the_golden_output_byte_for_byte(string tag)
        {
            using (var t = new TempDir())
            {
                var root = Copy(t, tag == "kitchen" ? Kitchen : TestPaths.Fixture);
                var run = Analyzer.RunPackage(root, Quiet, WorkstationPatterns.SuspiciousCommands, reportVersion: "1.38.1");
                // The one intended difference: 1.38.x printed "system''s" (single-quoted here-string); v2 prints "system's".
                var expected = TestPaths.GoldenText($"analyze-{tag}-report.html").Replace("''", "'");
                Assert.Equal(expected, File.ReadAllText(run.ReportPath!, System.Text.Encoding.UTF8));
                Assert.Equal(0xEF, File.ReadAllBytes(run.ReportPath!)[0]);
            }
        }

        [Theory]
        [InlineData("WinFoton_FIXTURE_20260115-120000Z", "lab-iocs.txt", "fixture-txt")]
        [InlineData("WinFoton_FIXTURE_20260115-120000Z", "lab-iocs.csv", "fixture-csv")]
        [InlineData("kitchen", "kitchen-iocs.txt", "kitchen")]
        public void Ioc_hits_match_1_38(string package, string iocFile, string tag)
        {
            using (var t = new TempDir())
            {
                var pkg = package == "kitchen" ? Kitchen : TestPaths.Fixture;
                var ioc = package == "kitchen" ? Path.Combine(TestPaths.Root, "testdata", "analyze", iocFile)
                    : Path.Combine(TestPaths.Root, "testdata", "ioc", iocFile);
                var root = Copy(t, pkg);
                var run = Analyzer.RunIoc(root, ioc, Quiet);
                var sorted = run.Hits.OrderBy(h => h.Artifact, StringComparer.InvariantCultureIgnoreCase).ThenBy(h => h.Property, StringComparer.InvariantCultureIgnoreCase)
                    .ThenBy(h => h.IocKind, StringComparer.InvariantCultureIgnoreCase).ThenBy(h => h.IocValue, StringComparer.InvariantCultureIgnoreCase)
                    .ThenBy(h => h.Sample, StringComparer.InvariantCultureIgnoreCase).ToList();
                Foton.Core.Csv.Write(t.File("hits.csv"), sorted);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden($"ioc-{tag}-hits.csv")), File.ReadAllBytes(t.File("hits.csv")));
                Assert.True(File.Exists(Path.Combine(root, "analysis", "ioc_matches.csv")));
            }
        }

        [Fact]
        public void Collector_names_cover_both_the_powershell_and_v2_collectors()
        {
            Assert.True(Foton.Analyze.Rules.EventLogRules.NamesCollector("ScriptBlock: Get-FotonRegValue -Path HKLM:\\x"));
            Assert.True(Foton.Analyze.Rules.EventLogRules.NamesCollector(@"Parent Process Name: C:\Tools\foton-collect.exe New Process Name: C:\Windows\System32\reg.exe"));
            Assert.True(Foton.Analyze.Rules.EventLogRules.NamesCollector("ParentImage=foton-baseline.exe"));
            Assert.False(Foton.Analyze.Rules.EventLogRules.NamesCollector(@"C:\Cases\Foton_HOST_20260101-000000Z\analysis\x.csv"));
            Assert.False(Foton.Analyze.Rules.EventLogRules.NamesCollector(@"C:\Users\x\notfoton-collect.exe"));
        }

        [Fact]
        public void Ioc_json_list_loads_as_an_array_or_one_object()
        {
            using (var t = new TempDir())
            {
                File.WriteAllText(t.File("a.json"), "[{\"Kind\":\"SHA256\",\"Value\":\"abc\"},{\"Kind\":\"path\",\"Value\":\"payload.exe\"}]");
                File.WriteAllText(t.File("b.json"), "{\"Kind\":\"\",\"Value\":\"x\"}");
                var a = IocMatcher.Load(t.File("a.json"));
                Assert.Equal(new[] { ("sha256", "ABC"), ("path", "payload.exe") }, a.Select(i => (i.Kind, i.Value)));
                Assert.Equal(("text", "x"), IocMatcher.Load(t.File("b.json")).Select(i => (i.Kind, i.Value)).Single());
            }
        }

        [Fact]
        public void Ioc_text_lines_are_matched_and_empty_indicators_are_dropped()
        {
            using (var t = new TempDir())
            {
                var list = t.File("iocs.txt");
                File.WriteAllLines(list, new[] { "path:", "text:", "text:update.vendor.example" });
                Assert.Single(IocMatcher.Load(list));
                var root = Copy(t, Kitchen);
                var hits = Analyzer.RunIoc(root, list, Quiet).Hits;
                // 1.38.x saw only a string's Length property, so text-file artifacts like hosts_file never matched.
                var h = Assert.Single(hits);
                Assert.Equal(("hosts_file", "Line"), (h.Artifact, h.Property));
            }
        }

        [Fact]
        public void Triage_report_renders_a_package_with_no_optional_artifacts()
        {
            var html = TriageReport.Render(new TriageReportInput());
            Assert.Contains("(unknown host)", html);
            Assert.Contains("(not recorded)", html);
        }

        [Fact]
        public void Report_shows_case_and_examiner_from_custody_encoded()
        {
            var html = TriageReport.Render(new TriageReportInput { CaseNumber = "CASE-0001", Examiner = "<b>A. Examiner</b>" });
            Assert.Contains("<div><b>Case</b>CASE-0001</div>", html);
            Assert.Contains("<div><b>Examiner</b>&lt;b&gt;A. Examiner&lt;/b&gt;</div>", html);
            Assert.Contains("by &lt;b&gt;A. Examiner&lt;/b&gt; &middot;", html);
            Assert.DoesNotContain("(not supplied)", html);
        }

        [Fact]
        public void Package_values_cannot_inject_markup_or_script_links_into_the_report()
        {
            var html = TriageReport.Render(new TriageReportInput
            {
                Findings = new[]
                {
                    new Finding { Severity = "High\"><script>", Category = "X", Title = "T", Observation = "o", Artifact = "javascript:alert(1)" },
                    new Finding { Severity = "Low", Category = "X", Title = "T2", Observation = "o", Artifact = "java\tscript:alert(2)" },
                    new Finding { Severity = "Low", Category = "X", Title = "T3", Observation = "o", Artifact = "java\nscript&#58;alert(3)" },
                    new Finding { Severity = "Low", Category = "X", Title = "T4", Observation = "o", Artifact = "  //evil.example/x" },
                    new Finding { Severity = "Low", Category = "X", Title = "T5", Observation = "o", Artifact = " \\\\evil\\share" },
                    new Finding { Severity = "Low", Category = "X", Title = "T6", Observation = "o", Artifact = "06_x/../../evil/x.html" },
                },
                Manifest = new[]
                {
                    new Dictionary<string, string?> { ["Category"] = "System", ["File"] = @"\\attacker\share\x.json", ["Records"] = "<img src=x onerror=alert(1)>", ["Status"] = "Success" },
                    new Dictionary<string, string?> { ["Category"] = "System", ["File"] = @"01_System\os_info.json", ["Records"] = "1", ["Status"] = "Success" },
                },
            });
            Assert.DoesNotContain("<script>", html.Replace("<script>\r\n(function", ""));
            Assert.DoesNotContain("href=\"javascript:", html);
            Assert.DoesNotContain("href=\"java", html);
            Assert.DoesNotMatch("href=\"[^\"]*evil", html);
            Assert.DoesNotContain("href=\"//attacker", html);
            Assert.DoesNotContain("<img src=x", html);
            Assert.Contains("<a href=\"01_System/os_info.json\">os_info.json</a>", html);
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
        public void RECmd_batch_output_becomes_overview_writable_path_and_deleted_findings()
        {
            using (var t = new TempDir())
            {
                var dest = Path.Combine(t.Path, "analysis", "external", "RECmd");
                var src = Path.Combine(TestPaths.Root, "testdata", "analyze", "recmd");
                foreach (var f in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
                {
                    var to = Path.Combine(dest, f.Substring(src.Length + 1));
                    Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                    File.Copy(f, to);
                }
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var overview = c.Findings.Single(f => f.Title == "RECmd batch rows present in compose output");
                Assert.Equal("Info", overview.Severity);
                Assert.Contains("RECmd wrote 5 row(s)", overview.Observation);   // the plugin detail CSV in the subfolder is not counted
                Assert.Contains("Autoruns (3)", overview.Observation);
                Assert.Contains("Windows Defender Exclusions (1)", overview.Observation);

                var writable = c.Findings.Single(f => f.Title == "RECmd persistence entries reference user-writable paths");
                Assert.Equal("Medium", writable.Severity);
                Assert.Contains("2 distinct path(s)", writable.Observation);
                Assert.Contains(@"C:\Users\Public\Downloads\updater.exe", writable.Observation);
                Assert.Contains(@"C:\Users\user1\AppData\Roaming\svc", writable.Observation);
                Assert.DoesNotContain("tool.exe", writable.Observation);   // Program Execution is not a persistence category
                Assert.DoesNotContain("OneDriveSetup", writable.Observation);

                var deleted = c.Findings.Single(f => f.Title == "RECmd recovered deleted registry keys or values");
                Assert.Contains("1 row(s)", deleted.Observation);
                Assert.Contains("Run (NTUSER) (1)", deleted.Observation);
            }
        }

        [Fact]
        public void Chainsaw_hunt_output_becomes_an_overview_without_the_collectors_own_rows()
        {
            using (var t = new TempDir())
            {
                var dest = Directory.CreateDirectory(Path.Combine(t.Path, "analysis", "external", "Chainsaw")).FullName;
                File.Copy(Path.Combine(TestPaths.Root, "testdata", "analyze", "chainsaw", "sigma.csv"), Path.Combine(dest, "sigma.csv"));
                File.WriteAllText(Path.Combine(dest, "notes.csv"), "a,b\r\n1,2\r\n");   // not a hunt CSV: ignored
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var f = c.Findings.Single(x => x.Title == "Chainsaw hunt detections present in compose output");
                Assert.Equal("Info", f.Severity);
                Assert.Contains("2 detection row(s)", f.Observation);
                Assert.Contains("sigma.csv (2)", f.Observation);
                Assert.Contains("Suspicious Service Installation (1)", f.Observation);   // the collector's own install row is not counted
                Assert.Contains("Windows Update Error (1)", f.Observation);               // two titles in one cell are both counted
                Assert.Contains("Excludes 1 row(s) attributable to the Foton collection", f.Observation);
            }
        }

        static void CopyFixture(string fixture, string caseRoot, string tool)
        {
            var dest = Directory.CreateDirectory(Path.Combine(caseRoot, "analysis", "external", tool)).FullName;
            foreach (var f in Directory.GetFiles(Path.Combine(TestPaths.Root, "testdata", "analyze", fixture)))
                File.Copy(f, Path.Combine(dest, Path.GetFileName(f)));
        }

        [Fact]
        public void LECmd_output_becomes_overview_writable_code_and_argument_findings()
        {
            using (var t = new TempDir())
            {
                CopyFixture("lecmd", t.Path, "LECmd");
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var overview = c.Findings.Single(f => f.Title == "LECmd shortcut (LNK) rows present in compose output");
                Assert.Equal("Info", overview.Severity);
                Assert.Contains("6 shortcut (LNK) row(s)", overview.Observation);
                Assert.Contains("1 on removable media, 1 on network paths", overview.Observation);
                Assert.Contains(@"E:\payroll.xlsx (1)", overview.Observation);
                Assert.Contains(@"\\fileserver\share (1)", overview.Observation);

                var writable = c.Findings.Single(f => f.Title == "LECmd shortcut (LNK) targets are code in user-writable paths");
                Assert.Equal("Medium", writable.Severity);
                Assert.Contains(@"1 distinct executable or script target(s)", writable.Observation);
                Assert.Contains(@"C:\Users\user1\Downloads\setup.exe", writable.Observation);
                Assert.DoesNotContain("report.pdf", writable.Observation);   // a document in Downloads is not code

                var args = c.Findings.Single(f => f.Title == "LECmd shortcut (LNK) arguments matched suspicious-command patterns");
                Assert.Equal("Medium", args.Severity);
            }
        }

        [Fact]
        public void JLECmd_output_reads_automatic_and_custom_destinations()
        {
            using (var t = new TempDir())
            {
                CopyFixture("jlecmd", t.Path, "JLECmd");
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var overview = c.Findings.Single(f => f.Title == "JLECmd jump list rows present in compose output");
                Assert.Contains("3 jump list row(s)", overview.Observation);
                Assert.Contains("3 distinct target(s); 0 on removable media, 0 on network paths", overview.Observation);
                var writable = c.Findings.Single(f => f.Title == "JLECmd jump list targets are code in user-writable paths");
                Assert.Contains(@"C:\Users\user1\AppData\Roaming\tool\agent.exe", writable.Observation);
                Assert.DoesNotContain(c.Findings, f => f.Title.StartsWith("JLECmd") && f.Title.Contains("arguments"));
            }
        }

        [Fact]
        public void AmcacheParser_output_becomes_overview_writable_code_and_unsigned_driver_findings()
        {
            using (var t = new TempDir())
            {
                CopyFixture("amcacheparser", t.Path, "AmcacheParser");
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var overview = c.Findings.Single(f => f.Title == "AmcacheParser rows present in compose output");
                Assert.Contains("7 row(s)", overview.Observation);   // the header-only DevicePnps file adds nothing
                Assert.Contains("UnassociatedFileEntries (4)", overview.Observation);
                Assert.Contains("DriverBinaries (3)", overview.Observation);

                var writable = c.Findings.Single(f => f.Title == "AmcacheParser inventory lists code in user-writable paths");
                Assert.Contains("1 distinct executable or script path(s)", writable.Observation);
                Assert.Contains(@"c:\users\user1\appdata\local\temp\x1\update.exe", writable.Observation);
                Assert.DoesNotContain("dismhost.exe", writable.Observation);   // IsOsComponent rows are left out
                Assert.DoesNotContain("readme.txt", writable.Observation);

                var drivers = c.Findings.Single(f => f.Title == "AmcacheParser lists unsigned drivers that did not ship with Windows");
                Assert.Equal("Software", drivers.Category);
                Assert.Contains("1 distinct driver(s)", drivers.Observation);
                Assert.Contains("vulnkit.sys", drivers.Observation);
                Assert.DoesNotContain("oldinbox.sys", drivers.Observation);
            }
        }

        [Fact]
        public void AppCompatCacheParser_output_becomes_overview_and_writable_code_findings()
        {
            using (var t = new TempDir())
            {
                CopyFixture("appcompatcacheparser", t.Path, "AppCompatCacheParser");
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var overview = c.Findings.Single(f => f.Title == "AppCompatCacheParser Shimcache rows present in compose output");
                Assert.Equal("Info", overview.Severity);
                Assert.Contains("6 Shimcache entr(ies)", overview.Observation);
                Assert.Contains("1 (5); 2 (1)", overview.Observation);
                Assert.Contains("3 marked Executed", overview.Observation);
                Assert.Contains("1 without a drive path", overview.Observation);

                var writable = c.Findings.Single(f => f.Title == "AppCompatCacheParser Shimcache lists code in user-writable paths");
                Assert.Equal("Medium", writable.Severity);
                Assert.Contains("2 distinct executable or script path(s)", writable.Observation);   // tool.exe once across both control sets
                Assert.Contains("1 of them marked Executed", writable.Observation);
                Assert.Contains(@"C:\Users\user1\AppData\Local\Temp\x1\setup.ps1", writable.Observation);
                Assert.DoesNotContain("report.pdf", writable.Observation);
                Assert.DoesNotContain("notepad.exe", writable.Observation);
            }
        }

        [Fact]
        public void SBECmd_output_becomes_a_shellbag_overview_with_devices_drives_and_shares()
        {
            using (var t = new TempDir())
            {
                CopyFixture("sbecmd", t.Path, "SBECmd");
                var c = Context(new PackageData(), t.Path);
                Analyzer.Run(c);

                var f = c.Findings.Single(x => x.Title == "SBECmd shellbag rows present in compose output");
                Assert.Equal("Info", f.Severity);
                Assert.Contains("8 shellbag row(s) from 2 hive(s)", f.Observation);
                Assert.Contains("user1_NTUSER", f.Observation);
                Assert.Contains("naming 8 distinct folder(s)", f.Observation);
                Assert.Contains("(MTP) entries: 2", f.Observation);
                Assert.Contains("Network paths: 1", f.Observation);
                Assert.Contains("Archive contents browsed: 1", f.Observation);
                Assert.Contains("system drive: E: (2)", f.Observation);   // C: is the system drive and is not listed
                Assert.DoesNotContain(c.Findings, x => x.Title.StartsWith("SBECmd") && x.Severity != "Info");
            }
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
            // Forward-slash traversal out of System32, and a look-alike System32 on another drive.
            Assert.Contains("OneSyncSvc_1a2b3c", Install(@"%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup", @"C:\Windows\System32\../../Users/Public/x.dll", "Template:OneSyncSvc"));
            Assert.Contains("OneSyncSvc_1a2b3c", Install(@"E:\Windows\System32\svchost.exe -k UnistackSvcGroup"));
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
