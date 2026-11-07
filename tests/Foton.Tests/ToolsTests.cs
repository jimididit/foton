using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Foton.Core;
using Foton.Tools;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Tool catalog, registration, pinned install, and compose (Tools.Tests.ps1). No network: fake .cmd tools only.</summary>
    public class ToolsTests
    {
        static readonly string System32Only = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32");

        static StatusLog Quiet() => new StatusLog(new StringWriter());

        static void Write(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text, Encoding.ASCII);
        }

        static string Package(string dir, params string[] folders)
        {
            Directory.CreateDirectory(Path.Combine(dir, "00_Collection"));
            foreach (var f in folders) Directory.CreateDirectory(Path.Combine(dir, f));
            return dir;
        }

        static ComposeRun Compose(string pkg, string toolRoot, Dictionary<string, string>? toolPaths = null) =>
            ComposeRunner.Run(pkg, Quiet(), toolRoot, toolPaths, System32Only);

        // Records its arguments beside itself, then exits with the given code.
        static string ArgsRecorder(int exitCode) => "@echo %* > \"%~dp0args_%~n0.txt\"\r\n@exit /b " + exitCode + "\r\n";

        [Fact]
        public void Catalog_pins_Hayabusa_by_SHA256()
        {
            var h = ToolCatalog.Entry("hayabusa");
            Assert.Equal("Hayabusa", h.Name);
            Assert.Equal(64, h.ExpectedSha256.Length);
            Assert.StartsWith("https://", h.DownloadUrl);
            Assert.Contains("unknown", Assert.Throws<ArgumentException>(() => ToolCatalog.Entry("unknown")).Message);
        }

        [Fact]
        public void List_shows_catalog_and_registered_tools_once_each()
        {
            using (var t = new TempDir())
            {
                var root = t.File("tools");
                var rows = ToolInstaller.List(root);
                var only = Assert.Single(rows);
                Assert.Equal("Catalog", only.Source);
                Assert.EndsWith("hayabusa-4.0.0-win-x64.zip", only.Location);

                Write(t.File(@"ez\PECmd.exe"), "x");
                ToolRegistry.Register("PECmd", t.File(@"ez\PECmd.exe"), root);
                rows = ToolInstaller.List(root);
                var pe = Assert.Single(rows, r => r.Name == "PECmd");
                Assert.Equal("Registered", pe.Source);
                Assert.EndsWith(@"\ez\PECmd.exe", pe.Location);
                Assert.False(pe.Verified);
                Assert.Equal("Catalog", rows.Single(r => r.Name == "Hayabusa").Source);
            }
        }

        [Fact]
        public void A_registered_catalog_tool_is_listed_as_registered_not_verified()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"hb\hayabusa.exe"), "x");
                ToolRegistry.Register("Hayabusa", t.File("hb"), t.File("tools"));
                var hb = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "Hayabusa");
                Assert.Equal("Registered", hb.Source);
                Assert.False(hb.Verified);
                Assert.Contains("not verified", hb.Notes);
            }
        }

        [Fact]
        public void Version_is_read_from_the_tool_when_the_binary_has_no_version_resource()
        {
            using (var t = new TempDir())
            {
                Write(t.File("chainsaw-ok.cmd"), "@echo chainsaw 2.17.1\r\n");
                Write(t.File("chainsaw-hang.cmd"), "@ping -n 6 127.0.0.1 >nul\r\n@echo chainsaw 9.9.9\r\n");
                // About 200 KB on stderr overflows an undrained pipe; the version is printed afterwards.
                Write(t.File("chainsaw-noisy.cmd"), "@for /l %%i in (1,1,2500) do @echo warning line %%i padding padding padding padding padding 1>&2\r\n@echo chainsaw 3.0.1\r\n");
                Write(t.File("chainsaw-stderr.cmd"), "@echo chainsaw 4.5.6 1>&2\r\n");
                Assert.Equal("2.17.1", ToolRegistry.CliVersion("Chainsaw", t.File("chainsaw-ok.cmd")));
                Assert.Equal("3.0.1", ToolRegistry.CliVersion("Chainsaw", t.File("chainsaw-noisy.cmd"), 15000));
                Assert.Equal("4.5.6", ToolRegistry.CliVersion("Chainsaw", t.File("chainsaw-stderr.cmd")));
                Assert.Equal("", ToolRegistry.CliVersion("Chainsaw", t.File("chainsaw-hang.cmd"), 500));
                // Tools without a known version flag are never executed.
                Assert.Equal("", ToolRegistry.CliVersion("PECmd", t.File("chainsaw-ok.cmd")));
                System.Threading.Thread.Sleep(200);
            }
        }

        [Fact]
        public void Installs_from_a_local_archive_only_when_the_hash_matches_the_pin()
        {
            using (var t = new TempDir())
            {
                // Real Hayabusa 4.x layout: a versioned exe name plus rules\.
                Write(t.File(@"payload\hayabusa-9.9.9-test-win-x64.exe"), "fake-hayabusa");
                Write(t.File(@"payload\rules\dummy.yml"), "title: test");
                var zip = t.File("hayabusa-fake.zip");
                ZipFile.CreateFromDirectory(t.File("payload"), zip);
                var hash = Hashing.Sha256Hex(zip);
                string Catalog(string file, string sha)
                {
                    File.WriteAllText(t.File(file), Json.Indented(new Dictionary<string, object?>
                    {
                        ["Tools"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["Name"] = "Hayabusa", ["Version"] = "9.9.9-test", ["AssetName"] = "hayabusa-fake.zip",
                                ["DownloadUrl"] = "https://example.invalid/hayabusa-fake.zip", ["ExpectedSha256"] = sha,
                                ["License"] = "AGPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                                ["ExecutableNames"] = new[] { "hayabusa.exe", "hayabusa-*.exe" }, ["RulesRelativePath"] = "rules", ["Notes"] = "test pin",
                            },
                        },
                    }));
                    return t.File(file);
                }
                var root = t.File("tools");
                var entry = ToolCatalog.Entry("Hayabusa", Catalog("catalog.json", hash));
                ToolInstaller.Install(entry, zip, root, Quiet());

                var installed = ToolManifest.Find("Hayabusa", root)!;
                Assert.Equal("9.9.9-test", ToolManifest.Get(installed, "Version"));
                Assert.True(File.Exists(ToolManifest.Get(installed, "ExecutablePath")));
                Assert.True(Directory.Exists(Path.Combine(root, "hayabusa", "rules")));
                Assert.Equal("bundled-9.9.9-test", ToolManifest.Get(installed, "RulesVersion"));
                Assert.True(File.Exists(Path.Combine(root, "install.log")));
                var resolved = ToolResolver.Resolve("Hayabusa", new[] { "hayabusa.exe" }, null, root, System32Only)!;
                Assert.Equal("Manifest", resolved.Source);
                Assert.Equal("9.9.9-test", resolved.Version);
                Assert.Equal("Installed", ToolInstaller.List(root, t.File("catalog.json")).Single().Source);

                var bad = hash.Substring(0, 63) + (hash[63] == '0' ? "1" : "0");
                var badEntry = ToolCatalog.Entry("Hayabusa", Catalog("catalog-bad.json", bad));
                Assert.Contains("SHA-256 mismatch", Assert.Throws<InvalidDataException>(() => ToolInstaller.Install(badEntry, zip, root, Quiet())).Message);
            }
        }

        [Fact]
        public void An_explicit_tool_path_wins_over_the_manifest_and_PATH()
        {
            using (var t = new TempDir())
            {
                Write(t.File("custom-hayabusa.exe"), "x");
                var r = ToolResolver.Resolve("Hayabusa", new[] { "hayabusa.exe" }, t.File("custom-hayabusa.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("ToolPath", r.Source);
                Assert.Equal(t.File("custom-hayabusa.exe"), r.Path);
                Assert.Null(ToolResolver.Resolve("Hayabusa", new[] { "hayabusa.exe" }, null, t.File("tools"), System32Only));
                Assert.Equal("PATH", ToolResolver.Resolve("Hayabusa", new[] { "custom-hayabusa" }, null, t.File("tools"), t.Path)!.Source);
            }
        }

        [Fact]
        public void Registers_an_EZ_Tools_folder_including_per_tool_subfolders()
        {
            using (var t = new TempDir())
            {
                foreach (var f in new[] { "PECmd.exe", "LECmd.exe", @"EvtxeCmd\EvtxECmd.exe", @"RECmd\RECmd.exe" }) Write(t.File(@"EZTools\" + f), "x");
                var root = t.File("tools");
                var rows = ToolRegistry.Register("eztools", t.File("EZTools"), root);
                Assert.Equal(6, rows.Count);
                Assert.Equal("Registered", rows.Single(r => r.Name == "EvtxECmd").Status);
                Assert.Equal("NotFound", rows.Single(r => r.Name == "AmcacheParser").Status);
                var r = ToolResolver.Resolve("EvtxECmd", new[] { "EvtxECmd.exe" }, null, root, System32Only)!;
                Assert.Equal("Manifest", r.Source);
                Assert.EndsWith(@"EvtxeCmd\EvtxECmd.exe", r.Path);
                var rec = ToolManifest.Find("RECmd", root)!;
                Assert.Equal("False", ToolManifest.Get(rec, "Verified"));
                Assert.Matches("^[0-9A-F]{64}$", ToolManifest.Get(rec, "ObservedSha256"));
            }
        }

        [Fact]
        public void Default_tool_root_is_under_LocalAppData()
        {
            Assert.Equal(Path.GetFullPath(Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA")!, "Foton", "tools")), ToolManifest.Root(null));
        }

        [Fact]
        public void Rejects_an_unknown_tool_name_for_registration()
        {
            Assert.Contains("Unknown tool", Assert.Throws<ArgumentException>(() => ToolRegistry.Register("NotATool", Path.GetTempPath(), null)).Message);
        }

        [Fact]
        public void Finds_RECmd_batches_and_Chainsaw_rules_beside_the_binary()
        {
            using (var t = new TempDir())
            {
                var recmd = t.File("RECmd.exe");
                Assert.Null(ComposeSupport.RecmdBatch(recmd));
                Write(t.File(@"BatchExamples\Kroll_Batch.reb"), "x");
                Assert.EndsWith("Kroll_Batch.reb", ComposeSupport.RecmdBatch(recmd));
                Write(t.File(@"BatchExamples\DFIRBatch.reb"), "x");
                Assert.EndsWith("DFIRBatch.reb", ComposeSupport.RecmdBatch(recmd));

                var cs = t.File("chainsaw.exe");
                var none = ComposeSupport.ChainsawRulesFor(cs);
                Assert.Null(none.RulesPath);
                Assert.Null(none.SigmaPath);
                Directory.CreateDirectory(t.File("sigma"));
                Assert.Null(ComposeSupport.ChainsawRulesFor(cs).SigmaPath);
                Write(t.File(@"mappings\sigma-event-logs-all.yml"), "x");
                var s = ComposeSupport.ChainsawRulesFor(cs);
                Assert.EndsWith("sigma", s.SigmaPath);
                Assert.EndsWith("sigma-event-logs-all.yml", s.MappingPath);
            }
        }

        [Fact]
        public void Detects_a_missing_NET_runtime_in_captured_tool_output()
        {
            using (var t = new TempDir())
            {
                var p = t.File("out.txt");
                Write(p, "You must install or update .NET to run this application.");
                Assert.True(ComposeSupport.MissingRuntime(p, @"C:\foton-no-such.txt"));
                Write(p, "It was not possible to find any compatible framework version\r\nThe framework 'Microsoft.NETCore.App', version '10.0.0' (x64) was not found.");
                Assert.True(ComposeSupport.MissingRuntime(p));
                Write(p, "Processed 12 files");
                Assert.False(ComposeSupport.MissingRuntime(p));
            }
        }

        [Fact]
        public void Quotes_arguments_so_paths_with_spaces_survive_the_command_line()
        {
            Assert.Equal(@"-d ""D:\My Cases\x"" -U", CommandLine.Join(new[] { "-d", @"D:\My Cases\x", "-U" }));
            Assert.Equal(@"""C:\a b\\"" """"", CommandLine.Join(new[] { @"C:\a b\", "" }));
            Assert.Equal(@"""say \""hi\""""", CommandLine.Join(new[] { "say \"hi\"" }));
            Assert.Equal(@"C:\plain\path.csv", CommandLine.Join(new[] { @"C:\plain\path.csv" }));
        }

        [Fact]
        public void Keeps_earlier_output_as_Retained_when_a_tool_does_not_run()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"));
                Write(Path.Combine(pkg, @"analysis\external\pecmd\pecmd.csv"), "old");
                var rows = Compose(pkg, t.File("empty")).Rows.Where(r => r.Tool == "PECmd").ToList();
                Assert.Contains(rows, r => r.Status == "NotOnPath");
                var kept = Assert.Single(rows, r => r.Status == "Retained");
                Assert.EndsWith(@"pecmd\pecmd.csv", kept.DestRelative);
                Assert.True(File.Exists(Path.Combine(pkg, @"analysis\external\pecmd\pecmd.csv")));
            }
        }

        [Fact]
        public void Runs_RECmd_with_a_batch_Hayabusa_in_UTC_and_records_Chainsaw_NoRules()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx", @"08_Filesystem\hives\machine");
                Write(t.File(@"bin\BatchExamples\DFIRBatch.reb"), "x");
                foreach (var n in new[] { "recmd", "hayabusa", "chainsaw" }) Write(t.File($@"bin\{n}.cmd"), ArgsRecorder(0));
                var run = Compose(pkg, t.File("empty"), new Dictionary<string, string>
                {
                    ["RECmd"] = t.File(@"bin\recmd.cmd"), ["Hayabusa"] = t.File(@"bin\hayabusa.cmd"), ["Chainsaw"] = t.File(@"bin\chainsaw.cmd"),
                });
                Assert.Matches(@"--bn .*DFIRBatch\.reb", File.ReadAllText(t.File(@"bin\args_recmd.txt")));
                Assert.Matches(@"(^| )-U( |$)", File.ReadAllText(t.File(@"bin\args_hayabusa.txt")).TrimEnd());
                Assert.Equal("NoRules", run.Rows.Single(r => r.Tool == "Chainsaw").Status);
                Assert.False(File.Exists(t.File(@"bin\args_chainsaw.txt")));
                Assert.True(File.Exists(run.InventoryPath));
                Assert.Equal(run.Rows.Count, Csv.Read(run.InventoryPath).Count);
            }
        }

        [Fact]
        public void Keeps_earlier_output_when_a_rerun_fails_and_quotes_a_spaced_case_path()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File(@"My Cases\Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                var old = Path.Combine(pkg, @"analysis\external\hayabusa\hayabusa.csv");
                Write(old, "old");
                Write(t.File(@"bin\hayabusa.cmd"), ArgsRecorder(1));
                var hb = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["Hayabusa"] = t.File(@"bin\hayabusa.cmd") })
                    .Rows.Where(r => r.Tool == "Hayabusa").ToList();
                Assert.Contains(hb, r => r.Status == "ToolError");
                Assert.EndsWith(@"hayabusa\hayabusa.csv", hb.Single(r => r.Status == "Retained").DestRelative);
                Assert.Equal("old", File.ReadAllText(old));
                Assert.Empty(Directory.GetFileSystemEntries(Path.Combine(pkg, @"analysis\external"), ".hayabusa.*"));
                Assert.Matches("\"[^\"]*My Cases[^\"]*\"", File.ReadAllText(t.File(@"bin\args_hayabusa.txt")));
            }
        }

        [Fact]
        public void Replaces_earlier_output_only_after_a_successful_run_leaving_no_staging_folders()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                var dir = Path.Combine(pkg, @"analysis\external\hayabusa");
                Write(Path.Combine(dir, "stale.csv"), "old");
                // Writes a file into the folder that follows -o (its parent is the staging folder).
                Write(t.File(@"bin\hayabusa.cmd"),
                    "@echo off\r\n:loop\r\nif \"%~1\"==\"\" exit /b 0\r\nif /i \"%~1\"==\"-o\" echo new> \"%~dp2fresh.csv\"\r\nshift\r\ngoto loop\r\n");
                var hb = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["Hayabusa"] = t.File(@"bin\hayabusa.cmd") })
                    .Rows.Where(r => r.Tool == "Hayabusa").ToList();
                var copied = Assert.Single(hb, r => r.Status == "Copied");
                Assert.Equal(@"analysis\external\hayabusa\fresh.csv", copied.DestRelative);
                Assert.Matches("^[0-9A-F]{64}$", copied.SHA256);
                Assert.True(File.Exists(Path.Combine(dir, "fresh.csv")));
                Assert.False(File.Exists(Path.Combine(dir, "stale.csv")));
                Assert.Empty(Directory.GetFileSystemEntries(Path.Combine(pkg, @"analysis\external"), ".hayabusa.*"));
            }
        }

        [Fact]
        public void First_compose_run_swaps_in_output_with_no_earlier_folder()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                Write(t.File(@"bin\hayabusa.cmd"),
                    "@echo off\r\n:loop\r\nif \"%~1\"==\"\" exit /b 0\r\nif /i \"%~1\"==\"-o\" echo new> \"%~dp2fresh.csv\"\r\nshift\r\ngoto loop\r\n");
                var hb = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["Hayabusa"] = t.File(@"bin\hayabusa.cmd") })
                    .Rows.Single(r => r.Tool == "Hayabusa");
                Assert.Equal("Copied", hb.Status);
                Assert.True(File.Exists(Path.Combine(pkg, @"analysis\external\hayabusa\fresh.csv")));
            }
        }

        [Fact]
        public void A_missing_Hayabusa_points_to_foton_tools()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                var rows = Compose(pkg, t.File("empty")).Rows;
                Assert.Contains("foton tools Hayabusa", rows.Single(r => r.Tool == "Hayabusa").Note);
                Assert.Equal("*", rows.Last().Tool);
            }
        }

        [Fact]
        public void Compose_refuses_a_ZIP_because_its_output_belongs_in_the_case_folder()
        {
            using (var t = new TempDir())
            {
                File.WriteAllBytes(t.File("case.zip"), new byte[] { 0x50, 0x4B, 5, 6 });
                Assert.Contains("Extract the ZIP", Assert.Throws<InvalidOperationException>(() => Compose(t.File("case.zip"), t.File("empty"))).Message);
            }
        }
    }
}
