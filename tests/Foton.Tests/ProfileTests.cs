using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Analyze;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class ProfileTests
    {
        static CollectionProfile Profile(TempDir t, string json)
        {
            var path = t.File("profile.json");
            File.WriteAllText(path, json);
            return CollectionProfile.Load(path);
        }

        [Fact]
        public void A_profile_selects_categories_in_package_order_and_applies_its_options_under_explicit_switches()
        {
            using (var t = new TempDir())
            {
                var p = Profile(t, "{\"Name\":\"Quick\",\"Categories\":[\"persistence\",\"Processes\"],\"ExcludeTasks\":[\"named_pipes\"],\"Options\":{\"EventLogDays\":3,\"LoadUserHives\":true,\"Deep\":true}}");
                Assert.Equal("Quick", p.Name);
                Assert.Equal(new[] { "Processes", "Persistence" }, p.Categories);
                Assert.True(p.Selects("Processes", "running_processes"));
                Assert.False(p.Selects("Processes", "NAMED_PIPES"));
                Assert.False(p.Selects("EventLogs", "sysmon_operational"));
                Assert.Equal(64, p.Sha256.Length);

                var o = new SessionOptions { EventLogDays = 30 };
                p.ApplyTo(o, new HashSet<string> { "EventLogDays" });
                Assert.Equal(30, o.EventLogDays);   // given on the command line, so it wins
                Assert.True(o.LoadUserHives);
                Assert.True(o.Deep);
                Assert.Same(p, o.Profile);

                // Without Categories every category is selected; -Category replaces the file's list and keeps the rest.
                var all = Profile(t, "{\"ExcludeTasks\":[\"evtx_export\"]}");
                Assert.Equal(CollectionProfile.AllCategories, all.Categories);
                Assert.Equal("profile", all.Name);
                var narrowed = all.WithCategories("Users, System");
                Assert.Equal(new[] { "System", "Users" }, narrowed.Categories);
                Assert.Equal(new[] { "evtx_export" }, narrowed.ExcludeTasks);
                Assert.Contains("\"Users\"", System.Text.Encoding.UTF8.GetString(narrowed.Bytes));

                // Keys match without regard to case, as they are validated: lowercase still selects.
                var lower = Profile(t, "{\"categories\":[\"Users\"],\"excludetasks\":[\"local_users\"],\"options\":{\"eventlogdays\":5}}");
                Assert.Equal(new[] { "Users" }, lower.Categories);
                Assert.Equal(new[] { "local_users" }, lower.ExcludeTasks);
                Assert.Equal(5, lower.Options["EventLogDays"]);
            }
        }

        [Theory]
        [InlineData("[]", "JSON object")]
        [InlineData("{\"Categorys\":[\"System\"]}", "Unknown profile key")]
        [InlineData("{\"Categories\":[\"Systems\"]}", "Unknown category")]
        [InlineData("{\"Categories\":[]}", "selects no categories")]
        [InlineData("{\"Categories\":\"System\"}", "list of names")]
        [InlineData("{\"Options\":{\"EventLogDays\":-1}}", "whole number")]
        [InlineData("{\"Options\":{\"Deep\":\"yes\"}}", "true or false")]
        [InlineData("{\"Options\":{\"OutputPath\":\"x\"}}", "Unknown Options key")]
        [InlineData("not json", "not valid JSON")]
        [InlineData("{\"Categories\":[\"System\"],\"categories\":[\"Users\"]}", "appears more than once")]
        [InlineData("{\"Options\":{\"Deep\":true,\"deep\":false}}", "appears more than once")]
        public void A_profile_with_a_mistake_is_refused_before_anything_runs(string json, string message)
        {
            using (var t = new TempDir())
                Assert.Contains(message, Assert.Throws<InvalidDataException>(() => Profile(t, json)).Message);
        }

        [Fact]
        public void A_task_the_profile_does_not_select_is_recorded_and_never_run()
        {
            using (var t = new TempDir())
            {
                var profile = CollectionProfile.FromCategories("System");
                var s = Sessions.New(Directory.CreateDirectory(t.File("cases")).FullName, elevated: false, new SessionOptions { Profile = profile });
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "Security", Name = "auditpol", Format = TaskFormat.Txt, RequiresElevation = true }, () => throw new InvalidOperationException("must not run"));
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "System", Name = "os_info" }, () => new Dictionary<string, object?> { ["Caption"] = "Windows" });

                // Not selected wins over not elevated: the task was not requested at all.
                Assert.Equal(new[] { TaskStatus.NotSelected, TaskStatus.Success }, s.Manifest.Select(m => m.Status));
                Assert.Equal(TaskRunner.NotSelectedText("auditpol", profile.Name) + "\r\n", File.ReadAllText(Path.Combine(s.Dir("Security"), "auditpol.txt")));
                Assert.Empty(s.Errors);

                var cov = Coverage.Build(s);
                Assert.Equal(new[] { "auditpol", CollectionProfile.EvtxExport }, cov.NotSelectedTasks);
                Assert.Equal(new[] { "System" }, cov.ProfileCategories);
                Assert.Equal(profile.Sha256, cov.ProfileSha256);

                // A sentinel artifact loads as absent, like a SkippedNotElevated one.
                Assert.False(FotonPackage.Open(s.CaseRoot!).Artifacts.ContainsKey("auditpol"));
            }
        }

        [Fact]
        public void Excluded_names_no_task_carried_are_reported()
        {
            using (var t = new TempDir())
            {
                var p = Profile(t, "{\"ExcludeTasks\":[\"os_info\",\"os_infos\",\"evtx_export\"]}");
                var s = Sessions.New(Directory.CreateDirectory(t.File("cases")).FullName, options: new SessionOptions { Profile = p });
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "System", Name = "os_info" }, () => "x");
                Assert.Equal(new[] { "os_infos" }, Coverage.UnknownExcluded(s));
            }
        }

        [Fact]
        public void Custody_records_the_profile_inside_the_parameters()
        {
            using (var t = new TempDir())
            {
                var p = Profile(t, "{\"Name\":\"Quick\",\"Categories\":[\"Persistence\"],\"ExcludeTasks\":[\"bits_jobs\"]}");
                var s = Sessions.New(Directory.CreateDirectory(t.File("cases")).FullName, options: new SessionOptions { Profile = p });
                var lines = ChainOfCustody.Lines(s, new CustodyFacts()).ToList();
                var at = lines.FindIndex(l => l.StartsWith("  RequireAdministrator", StringComparison.Ordinal));
                Assert.Equal("  Profile             = Quick", lines[at + 1]);
                Assert.Equal("  ProfileSha256       = " + p.Sha256, lines[at + 2]);
                Assert.Equal("  Categories          = Persistence", lines[at + 3]);
                Assert.Equal("  ExcludeTasks        = bits_jobs", lines[at + 4]);
                Assert.Contains(lines, l => l.Contains("Status=NotSelected"));

                // Without a profile the parameters are unchanged.
                var plain = ChainOfCustody.Lines(Sessions.New(Directory.CreateDirectory(t.File("plain")).FullName), new CustodyFacts());
                Assert.DoesNotContain(plain, l => l.StartsWith("  Profile", StringComparison.Ordinal));
            }
        }

        [Fact]
        public void Analyze_names_the_profile_and_draws_no_conclusion_from_tasks_that_did_not_run()
        {
            Dictionary<string, string?> Row(string task, string status) => new Dictionary<string, string?> { ["Task"] = task, ["Status"] = status };
            List<Finding> Run(params Dictionary<string, string?>[] manifest)
            {
                var c = new AnalysisContext(new PackageData(), manifest.ToList(), null, new string[0], PatternLists.UserWritable);
                Analyzer.Run(c);
                return c.Findings;
            }
            const string noEvents = "No process creation events (4688) were collected";
            Assert.Contains(Run(Row("security_process_creation", "NoData")), f => f.Title == noEvents);
            Assert.Contains(Run(), f => f.Title == noEvents);   // older packages without a manifest row keep the old behavior
            Assert.DoesNotContain(Run(Row("security_process_creation", "SkippedNotElevated")), f => f.Title == noEvents);
            Assert.DoesNotContain(Run(Row("os_info", "Success")), f => f.Title == noEvents);   // a manifest without the task's row: it never started

            // No manifest row: the artifact's own sentinel says whether the task ran.
            using (var t = new TempDir())
            {
                var file = Path.Combine(t.Path, "07_Event_Logs", "security_process_creation.csv");
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                List<Finding> RunIn(string firstLines)
                {
                    File.WriteAllText(file, firstLines);
                    var c = new AnalysisContext(new PackageData(), new List<Dictionary<string, string?>> { Row("os_info", "Success") }, t.Path, new string[0], PatternLists.UserWritable);
                    Analyzer.Run(c);
                    return c.Findings;
                }
                Assert.Contains(RunIn(TaskRunner.NoDataText("security_process_creation", "NoData", "")), f => f.Title == noEvents);
                Assert.DoesNotContain(RunIn(TaskRunner.NotSelectedText("security_process_creation", "p")), f => f.Title == noEvents);
                Assert.DoesNotContain(RunIn(TaskRunner.SkippedText("security_process_creation")), f => f.Title == noEvents);
            }

            var findings = Run(Row("security_process_creation", "NotSelected"), Row("bits_jobs", "NotSelected"));
            Assert.DoesNotContain(findings, f => f.Title == noEvents);
            var info = findings.Single(f => f.Title == "A collection profile limited what was collected");
            Assert.StartsWith("Profile '(unnamed)' left out 2 task(s): security_process_creation ; bits_jobs", info.Observation);
            Assert.Equal("Info", info.Severity);
        }

        [Fact]
        public void Profile_text_from_the_editor_is_validated_like_a_profile_file()
        {
            var json = "{\"Name\":\"Quick\",\"Categories\":[\"Persistence\"],\"ExcludeTasks\":[\"bits_jobs\"],\"Options\":{\"Deep\":true}}";
            var p = CollectionProfile.FromJson(json, "profile");
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes(json), p.Bytes);
            Assert.Equal(new[] { "Persistence" }, p.Categories);
            Assert.Throws<InvalidDataException>(() => CollectionProfile.FromJson("{\"Categorys\":[\"Users\"]}", "profile"));
            Assert.Throws<InvalidDataException>(() => CollectionProfile.FromJson("{\"Description\":\"" + new string('x', 70000) + "\"}", "profile"));
        }

        /// <summary>The foton-collect.exe this build produced (same configuration as the tests).</summary>
        static string BuiltCollect()
        {
            var config = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')).Parent!.Name;
            var exe = Path.Combine(TestPaths.Root, "cli", "Foton.Collect.Cli", "bin", config, "net462", "foton-collect.exe");
            Assert.True(File.Exists(exe), "Build the solution first: " + exe);
            return exe;
        }

        [Fact]
        public void A_bundle_holds_collect_the_profile_the_command_and_their_hashes()
        {
            using (var t = new TempDir())
            {
                var src = Directory.CreateDirectory(t.File("release")).FullName;
                var exe = Path.Combine(src, "foton-collect.exe");
                File.Copy(BuiltCollect(), exe);
                var sha = Hashing.Sha256Hex(exe).ToLowerInvariant();
                File.WriteAllText(Path.Combine(src, "SHA256SUMS.txt"), "0000000000000000000000000000000000000000000000000000000000000000  foton.exe\n" + sha.ToUpperInvariant() + " *foton-collect.exe\n");
                var profile = CollectionProfile.FromJson("{\"Name\":\"Quick triage / RMM\",\"Categories\":[\"Persistence\"],\"Options\":{\"EventLogDays\":3}}", "profile");
                var when = new DateTime(2026, 11, 11, 9, 30, 0, DateTimeKind.Utc);

                var b = Foton.Tools.DeploymentBundle.Build(exe, profile, t.File("out"), when);
                Assert.Equal(t.File(@"out\Foton_Bundle_Quick_triage_RMM_20261111-093000Z"), b.Folder);
                Assert.True(b.CollectVerified);
                Assert.Equal(new[] { "RUN.txt", "SHA256SUMS.txt", "foton-collect.exe", "profile.json" }, Directory.GetFiles(b.Folder).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal));
                Assert.Equal(File.ReadAllBytes(exe), File.ReadAllBytes(Path.Combine(b.Folder, "foton-collect.exe")));
                Assert.Equal(profile.Bytes, File.ReadAllBytes(Path.Combine(b.Folder, "profile.json")));
                Assert.Equal(new[] { sha + "  foton-collect.exe", profile.Sha256.ToLowerInvariant() + "  profile.json" }, File.ReadAllLines(Path.Combine(b.Folder, "SHA256SUMS.txt")));
                var run = File.ReadAllText(Path.Combine(b.Folder, "RUN.txt"));
                Assert.Contains(@".\foton-collect.exe -Profile .\profile.json", run);
                Assert.Contains("Matches SHA256SUMS.txt", run);
                Assert.Contains("Options:      EventLogDays=3", run);
                Assert.Throws<IOException>(() => Foton.Tools.DeploymentBundle.Build(exe, profile, t.File("out"), when));

                // Without a release list it is built but says it is not verified; a list with another hash is refused.
                File.Delete(Path.Combine(src, "SHA256SUMS.txt"));
                var unverified = Foton.Tools.DeploymentBundle.Build(exe, profile, t.File("out2"), when);
                Assert.False(unverified.CollectVerified);
                Assert.Contains("NOT verified", File.ReadAllText(Path.Combine(unverified.Folder, "RUN.txt")));
                File.WriteAllText(Path.Combine(src, "SHA256SUMS.txt"), new string('a', 64) + "  foton-collect.exe\n");
                Assert.Contains("does not match", Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.Build(exe, profile, t.File("out3"), when)).Message);
                File.WriteAllText(Path.Combine(src, "SHA256SUMS.txt"), new string('a', 64) + "  foton.exe\n");
                Assert.Contains("does not list", Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.Build(exe, profile, t.File("out3"), when)).Message);
                Assert.False(Directory.Exists(t.File("out3")));
            }
        }

        [Fact]
        public void A_bundle_refuses_a_file_that_is_not_foton_collect_2_8_or_later()
        {
            Assert.Contains("not foton-collect.exe", Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.CheckCollect("foton.exe", "2.9.0.0")).Message);
            Assert.Contains("does not read collection profiles", Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.CheckCollect("foton-collect.exe", "2.7.1.0")).Message);
            Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.CheckCollect("foton-collect.exe", ""));
            Assert.Equal(new Version(2, 8, 0, 0), Foton.Tools.DeploymentBundle.CheckCollect("FOTON-COLLECT.EXE", "2.8.0.0"));
            Assert.Equal("profile", Foton.Tools.DeploymentBundle.SafeName(" .. "));
            using (var t = new TempDir())
            {
                File.WriteAllText(t.File("foton.exe"), "not a program");
                Assert.Throws<InvalidDataException>(() => Foton.Tools.DeploymentBundle.Build(t.File("foton.exe"), CollectionProfile.FromCategories("Users"), t.File("out"), DateTime.UtcNow));
            }
        }
    }
}
