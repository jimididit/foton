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
        public void Catalog_pins_the_Chainsaw_rules_release_with_its_support_folders()
        {
            var c = ToolCatalog.Entry("chainsaw");
            Assert.Equal("chainsaw_all_platforms+rules.zip", c.AssetName);
            Assert.Equal(64, c.ExpectedSha256.Length);
            Assert.StartsWith("https://github.com/WithSecureLabs/chainsaw/releases/download/v" + c.Version + "/", c.DownloadUrl);
            Assert.Equal(new[] { "rules", "sigma", "mappings" }, c.SupportFolders);
            Assert.Contains("chainsaw_x86_64-pc-windows-msvc.exe", c.ExecutableNames);
        }

        [Fact]
        public void A_tool_root_past_260_characters_still_installs_a_release_with_deep_rule_files()
        {
            // The Chainsaw Sigma tree is several folders deep. Under a long profile path the extracted and copied rule files
            // pass 260 characters, which net462 rejects unless the path carries the \\?\ prefix (LongPath). The zip is built
            // directly: writing the long payload with the test helper would hit the same limit.
            using (var t = new TempDir())
            {
                var deepRoot = t.File(new string('s', 60) + @"\" + new string('t', 60) + @"\tools");
                var deepFolders = string.Join(@"\", Enumerable.Repeat(new string('r', 60), 4));
                var zip = t.File("chainsaw-deep.zip");
                using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
                {
                    WriteEntry(archive, "chainsaw/chainsaw_x86_64-pc-windows-msvc.exe", "fake-chainsaw");
                    WriteEntry(archive, "chainsaw/sigma/" + deepFolders.Replace('\\', '/') + "/rule.yml", "title: deep");
                    WriteEntry(archive, "chainsaw/rules/evtx/log_tampering.yml", "title: test");
                    WriteEntry(archive, "chainsaw/mappings/sigma-event-logs-all.yml", "name: test");
                }
                File.WriteAllText(t.File("catalog.json"), Json.Indented(new Dictionary<string, object?>
                {
                    ["Tools"] = new[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["Name"] = "Chainsaw", ["Version"] = "9.9.9-test", ["AssetName"] = "chainsaw-deep.zip",
                            ["DownloadUrl"] = "https://example.invalid/chainsaw-deep.zip", ["ExpectedSha256"] = Hashing.Sha256Hex(zip),
                            ["License"] = "GPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                            ["ExecutableNames"] = new[] { "chainsaw_x86_64-pc-windows-msvc.exe", "chainsaw.exe" }, ["RulesRelativePath"] = "rules",
                            ["SupportFolders"] = new[] { "rules", "sigma", "mappings" },
                            ["Notes"] = "test pin",
                        },
                    },
                }));
                try
                {
                    var entry = ToolCatalog.Entry("Chainsaw", t.File("catalog.json"));
                    var record = ToolInstaller.Install(entry, zip, deepRoot, Quiet());
                    var exe = (string)record["ExecutablePath"]!;
                    // The record holds the normal form, never the prefix.
                    Assert.DoesNotContain(@"\\?\", exe);
                    Assert.Equal(Path.Combine(deepRoot, @"chainsaw\chainsaw_x86_64-pc-windows-msvc.exe"), exe);
                    Assert.True(File.Exists(LongPath.For(Path.Combine(deepRoot, @"chainsaw\sigma\" + deepFolders + @"\rule.yml"))));
                    // The installed executable hashes to the bytes the release shipped (the payload written into the zip above).
                    Assert.Equal(Hashing.Sha256Hex(Encoding.UTF8.GetBytes("fake-chainsaw")), Hashing.Sha256Hex(exe));
                    var rules = ComposeSupport.ChainsawRulesFor(exe);
                    Assert.NotNull(rules.RulesPath);
                    Assert.NotNull(rules.SigmaPath);
                    Assert.EndsWith("sigma-event-logs-all.yml", rules.MappingPath);
                    Assert.Equal("bundled with release 9.9.9-test", ToolInstaller.List(deepRoot).Single(r => r.Name == "Chainsaw").RulesVersion);
                }
                finally
                {
                    // TempDir cannot delete past 260 characters; remove the deep tool root here.
                    try { Directory.Delete(LongPath.For(deepRoot), true); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
            }
        }

        [Fact]
        public void LongPath_Full_normalizes_a_prefixed_long_path_instead_of_returning_it_with_dot_segments()
        {
            // A prefixed path is not normalized on disk, so Full resolves its . and .. from the normal form.
            var prefixed = @"\\?\C:\" + new string('a', 200) + @"\..\" + new string('b', 60) + @"\tool.exe";
            Assert.Equal(@"C:\" + new string('b', 60) + @"\tool.exe", LongPath.Full(prefixed));
        }

        [Fact]
        public void LongPath_For_maps_a_device_path_to_the_drive_form_not_a_share()
        {
            // \\.\C:\... names the drive; treating it as \\server\share would rewrite it as a UNC share and break the path.
            var drive = @"C:\" + string.Join(@"\", Enumerable.Repeat(new string('b', 60), 5));
            Assert.Equal(@"\\?\" + drive, LongPath.For(@"\\.\" + drive));
        }

        [Fact]
        public void LongPath_ParentOf_keeps_the_backslash_of_a_drive_root()
        {
            // Cut at the last backslash, the parent of C:\tool.exe is "C:", which is drive-relative (a different folder).
            Assert.Equal(@"C:\", LongPath.ParentOf(@"C:\tool.exe"));
            Assert.Equal(@"C:\a", LongPath.ParentOf(@"C:\a\tool.exe"));
            Assert.Equal(@"\\server\share", LongPath.ParentOf(@"\\server\share\tool.exe"));
            // A share root has no parent folder: \\server is not a valid path to hand to a file call.
            Assert.Equal("", LongPath.ParentOf(@"\\server\share"));
            // A prefixed drive root keeps its backslash too: \\?\C: is drive-relative, \\?\C:\ is the root.
            Assert.Equal(@"\\?\C:\", LongPath.ParentOf(@"\\?\C:\tool.exe"));
            Assert.Equal(@"\\?\C:\a", LongPath.ParentOf(@"\\?\C:\a\tool.exe"));
            // A prefixed share root has no parent; a file under it lies in the share root, not in \\?\UNC.
            Assert.Equal("", LongPath.ParentOf(@"\\?\UNC\server\share"));
            Assert.Equal(@"\\?\UNC\server\share", LongPath.ParentOf(@"\\?\UNC\server\share\tool.exe"));
            Assert.Equal(@"\\?\UNC\server\share\a", LongPath.ParentOf(@"\\?\UNC\server\share\a\tool.exe"));
            // A null path is an argument error, as in Full, not a NullReferenceException.
            Assert.Throws<ArgumentNullException>(() => LongPath.ParentOf(null!));

            // A root-relative long path (\folder\...) gets the current drive, so a later call can take the prefix.
            var drive = Path.GetPathRoot(Directory.GetCurrentDirectory()).TrimEnd('\\');
            var deep = new string('x', 250);
            Assert.Equal(drive + @"\" + deep + @"\tool.exe", LongPath.Full(@"\" + deep + @"\tool.exe"));
            // A drive-relative long path (E:folder\...) starts in that drive's current folder, which Windows keeps per drive.
            var driveCwd = Environment.GetEnvironmentVariable("=" + drive) ?? drive + @"\";
            Assert.Equal(driveCwd.TrimEnd('\\') + @"\" + deep + @"\tool.exe", LongPath.Full(drive + deep + @"\tool.exe"));
            Assert.Equal("", LongPath.ParentOf("tool.exe"));
        }

        [Fact]
        public void LongPath_Full_resolves_dot_segments_in_a_long_share_path_without_GetFullPath()
        {
            // The share is the root: .. steps are resolved in the rest of the path, and a long UNC path keeps its share.
            var share = @"\\server\share\";
            var full = LongPath.Full(share + new string('a', 200) + @"\..\" + new string('b', 60) + @"\.\tool.exe");
            Assert.Equal(share + new string('b', 60) + @"\tool.exe", full);
        }

        [Fact]
        public void SafeHash_hashes_a_local_file_past_260_characters_instead_of_reporting_HashError()
        {
            using (var t = new TempDir())
            {
                // One folder name of 210 characters puts the file past the limit that FileInfo enforces without the prefix.
                var deepDir = Path.Combine(t.Path, new string('h', 210));
                var file = Path.Combine(deepDir, "payload.bin");
                Directory.CreateDirectory(LongPath.For(deepDir));
                File.WriteAllBytes(LongPath.For(file), Encoding.UTF8.GetBytes("payload"));
                try
                {
                    Assert.True(file.Length > 259);
                    Assert.Equal(Hashing.Sha256Hex(Encoding.UTF8.GetBytes("payload")), Hashing.SafeHash(file, false));
                }
                finally
                {
                    try { Directory.Delete(LongPath.For(deepDir), true); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
            }
        }

        [Fact]
        public void LongPath_prefixes_only_long_local_paths_and_Plain_gives_the_normal_form_back()
        {
            // Short and relative paths pass through untouched; a long drive path gets the \\?\ prefix; Plain undoes it.
            Assert.Equal(@"C:\tools\x.exe", LongPath.For(@"C:\tools\x.exe"));
            Assert.Equal(@"relative\" + new string('a', 300), LongPath.For(@"relative\" + new string('a', 300)));
            Assert.Equal(@"\\?\UNC\server\share\" + new string('a', 300), LongPath.For(@"\\server\share\" + new string('a', 300)));
            var longPath = @"C:\" + string.Join(@"\", Enumerable.Repeat(new string('b', 60), 5));
            Assert.Equal(@"\\?\" + longPath, LongPath.For(longPath));
            Assert.Equal(longPath, LongPath.Plain(LongPath.For(longPath)));
            Assert.Equal(longPath, LongPath.Plain(longPath));
            Assert.Equal(@"\\?\" + longPath, LongPath.For(LongPath.For(longPath)));
        }

        [Fact]
        public void LongPath_Full_makes_a_long_relative_path_absolute_and_drops_dot_segments()
        {
            // GetFullPath throws at 260 characters under net462, so a long relative path (274 here) used to come back
            // unchanged, and a record match or existence check on it then failed.
            // The working folder is read, not changed: tests run in parallel, and another test may use a relative path.
            var relative = new string('a', 200) + @"\..\" + new string('b', 60) + @"\.\tool.exe";
            Assert.True(relative.Length >= 240);
            Assert.Equal(Path.Combine(Directory.GetCurrentDirectory(), new string('b', 60), "tool.exe"), LongPath.Full(relative));
            // A short relative name is joined the same way, and null is the documented ArgumentNullException.
            Assert.Equal(Path.Combine(Directory.GetCurrentDirectory(), "rule.yml"), LongPath.Full("rule.yml"));
            Assert.Throws<ArgumentNullException>(() => LongPath.Full(null!));
        }

        [Fact]
        public void LongPath_For_prefixes_a_forward_slash_drive_path_after_turning_the_slashes_into_backslashes()
        {
            var longPath = @"C:\" + string.Join(@"\", Enumerable.Repeat(new string('b', 60), 5));
            Assert.Equal(@"\\?\" + longPath, LongPath.For(longPath.Replace('\\', '/')));
            Assert.Equal(@"\\?\UNC\server\share\" + new string('a', 300), LongPath.For(@"//server/share/" + new string('a', 300)));
        }

        static void WriteEntry(ZipArchive archive, string name, string text)
        {
            using (var writer = new StreamWriter(archive.CreateEntry(name).Open()))
                writer.Write(text);
        }

        [Fact]
        public void A_Chainsaw_archive_installs_with_rules_sigma_and_mappings_beside_the_binary()
        {
            using (var t = new TempDir())
            {
                // The chainsaw_all_platforms+rules.zip layout: chainsaw\<per-platform binaries> with rules\, sigma\, mappings\.
                Write(t.File(@"payload\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe"), "fake-chainsaw");
                Write(t.File(@"payload\chainsaw\chainsaw_x86_64-unknown-linux-gnu"), "other platform");
                Write(t.File(@"payload\chainsaw\rules\evtx\log_tampering.yml"), "title: test");
                Write(t.File(@"payload\chainsaw\sigma\rules\windows\x.yml"), "title: test");
                Write(t.File(@"payload\chainsaw\mappings\sigma-event-logs-all.yml"), "name: test");
                Write(t.File(@"payload\chainsaw\sigma\regression_data\rules\windows\deep\x.json"), "{}");
                var zip = t.File("chainsaw-fake.zip");
                ZipFile.CreateFromDirectory(t.File("payload"), zip);
                File.WriteAllText(t.File("catalog.json"), Json.Indented(new Dictionary<string, object?>
                {
                    ["Tools"] = new[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["Name"] = "Chainsaw", ["Version"] = "9.9.9-test", ["AssetName"] = "chainsaw-fake.zip",
                            ["DownloadUrl"] = "https://example.invalid/chainsaw-fake.zip", ["ExpectedSha256"] = Hashing.Sha256Hex(zip),
                            ["License"] = "GPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                            ["ExecutableNames"] = new[] { "chainsaw_x86_64-pc-windows-msvc.exe", "chainsaw.exe" }, ["RulesRelativePath"] = "rules",
                            ["SupportFolders"] = new[] { "rules", "sigma", "mappings" }, ["SkipArchivePrefixes"] = new[] { "chainsaw/sigma/regression_data/" },
                            ["Notes"] = "test pin",
                        },
                    },
                }));
                var entry = ToolCatalog.Entry("Chainsaw", t.File("catalog.json"));
                var record = ToolInstaller.Install(entry, zip, t.File("tools"), new StatusLog(new StringWriter()));
                var exe = (string)record["ExecutablePath"]!;
                Assert.Equal(t.File(@"tools\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe"), exe);
                var rules = ComposeSupport.ChainsawRulesFor(exe);
                Assert.NotNull(rules.RulesPath);
                Assert.NotNull(rules.SigmaPath);
                Assert.EndsWith("sigma-event-logs-all.yml", rules.MappingPath);
                // A pinned install records the rule set as bundled with the release, so the list shows it.
                Assert.Equal("bundled with release 9.9.9-test", ToolInstaller.List(t.File("tools")).Single(r => r.Name == "Chainsaw").RulesVersion);
                Assert.False(Directory.Exists(t.File(@"tools\chainsaw\9.9.9-test\chainsaw\sigma\regression_data")));
                Assert.False(Directory.Exists(t.File(@"tools\chainsaw\sigma\regression_data")));

                // Reinstalling installs the pinned rules again and keeps a locally edited copy beside the tool.
                Write(t.File(@"tools\chainsaw\rules\local-tuning.yml"), "title: local");
                ToolInstaller.Install(entry, zip, t.File("tools"), new StatusLog(new StringWriter()));
                Assert.False(File.Exists(t.File(@"tools\chainsaw\rules\local-tuning.yml")));
                var keptDir = Directory.GetDirectories(t.File(@"tools\chainsaw"), "rules.replaced-*").Single();
                Assert.True(File.Exists(Path.Combine(keptDir, "local-tuning.yml")));

                // A support folder name that is empty, ".", nested, or the version folder is refused, and the install survives.
                foreach (var bad in new[] { "", ".", "..", @"rules\x", "9.9.9-test" })
                {
                    var badEntry = new CatalogTool
                    {
                        Name = entry.Name, Version = entry.Version, AssetName = entry.AssetName, DownloadUrl = entry.DownloadUrl, ExpectedSha256 = entry.ExpectedSha256,
                        ExecutableNames = entry.ExecutableNames, SupportFolders = new[] { bad },
                    };
                    Assert.Throws<InvalidDataException>(() => ToolInstaller.Install(badEntry, zip, t.File("tools"), new StatusLog(new StringWriter())));
                    Assert.True(Directory.Exists(t.File(@"tools\chainsaw")), bad);
                }
            }
        }

        [Fact]
        public void List_shows_catalog_and_registered_tools_once_each()
        {
            using (var t = new TempDir())
            {
                var root = t.File("tools");
                var rows = ToolInstaller.List(root);
                Assert.Equal(new[] { "Hayabusa", "Chainsaw" }, rows.Select(r => r.Name).ToArray());
                Assert.All(rows, r => Assert.Equal("Catalog", r.Source));
                Assert.EndsWith("hayabusa-4.0.0-win-x64.zip", rows[0].Location);

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
        public void Register_finds_a_tool_under_a_folder_past_260_characters()
        {
            // Directory.Exists and File.Exists answer "missing" past 260 characters without the prefix, so registration threw
            // before it searched. Here the tool sits at the end of a 200-character folder.
            using (var t = new TempDir())
            {
                var deepDir = Path.Combine(t.Path, new string('p', 200));
                var exe = Path.Combine(deepDir, "PECmd.exe");
                Directory.CreateDirectory(LongPath.For(deepDir));
                File.WriteAllText(LongPath.For(exe), "x");
                var root = t.File("tools");
                try
                {
                    Assert.True(exe.Length > 259);
                    ToolRegistry.Register("PECmd", exe, root);
                    var pe = Assert.Single(ToolInstaller.List(root), r => r.Name == "PECmd");
                    Assert.Equal("Registered", pe.Source);
                }
                finally
                {
                    try { Directory.Delete(LongPath.For(deepDir), true); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
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
        public void Damaged_or_hand_edited_rows_are_listed_as_registered_not_installed()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"ez\PECmd.exe"), "x");
                // Only an Install-shaped row (no Verified key, a recorded ArchiveSha256) is a pinned install. A present
                // but empty Verified, and a row with neither the key nor a hash, are damaged and must read as Registered.
                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "PECmd",
                    ["ExecutablePath"] = t.File(@"ez\PECmd.exe"),
                    ["Version"] = "1.0",
                    // A full-length hash, so the empty Verified value is the only reason this row is not a pin.
                    ["ArchiveSha256"] = new string('A', 64),
                    ["Verified"] = "",
                });
                var pe = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "PECmd");
                Assert.Equal("Registered", pe.Source);
                Assert.False(pe.Verified);

                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "PECmd",
                    ["ExecutablePath"] = t.File(@"ez\PECmd.exe"),
                    ["Version"] = "1.0",
                    ["ArchiveSha256"] = "",
                });
                pe = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "PECmd");
                Assert.Equal("Registered", pe.Source);
                Assert.False(pe.Verified);

                // An edited Verified = True without a recorded hash is not a pin either.
                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "PECmd",
                    ["ExecutablePath"] = t.File(@"ez\PECmd.exe"),
                    ["Version"] = "1.0",
                    ["ArchiveSha256"] = "",
                    ["Verified"] = "True",
                });
                pe = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "PECmd");
                Assert.Equal("Registered", pe.Source);
                Assert.False(pe.Verified);
            }
        }

        [Fact]
        public void A_registered_tool_with_a_rules_folder_reports_its_rule_set_in_the_list()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"hb\hayabusa.exe"), "x");
                Write(t.File(@"hb\rules\rule.yml"), "x");
                ToolRegistry.Register("Hayabusa", t.File("hb"), t.File("tools"));
                var hb = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "Hayabusa");
                // Unpinned local rules: the rule set is recorded as unversioned, not as a release number.
                Assert.Equal("local-unversioned", hb.RulesVersion);
            }
        }

        [Fact]
        public void A_catalog_tool_that_is_not_installed_shows_the_rule_set_its_install_would_bring()
        {
            using (var t = new TempDir())
            {
                var hb = ToolInstaller.List(t.File("tools")).Single(r => r.Name == "Hayabusa");
                Assert.Equal("Catalog", hb.Source);
                // No version is invented before install: only that the pinned release bundles its rules.
                Assert.Equal("bundled with release (on install)", hb.RulesVersion);
            }
        }

        [Fact]
        public void Install_under_a_root_that_is_itself_past_260_characters_writes_the_log_and_manifest()
        {
            // Not the rule files: the tool root itself is 260+ characters. Root, install.log, the archive path and tools.json all
            // go through LongPath, so every step of the install reaches the disk.
            using (var t = new TempDir())
            {
                var deepRoot = t.File(new string('s', 120) + @"\" + new string('t', 120) + @"\tools");
                Assert.True(deepRoot.Length >= 260);
                var zip = t.File("chainsaw-root.zip");
                using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
                    WriteEntry(archive, "chainsaw/chainsaw_x86_64-pc-windows-msvc.exe", "fake-chainsaw");
                File.WriteAllText(t.File("catalog.json"), Json.Indented(new Dictionary<string, object?>
                {
                    ["Tools"] = new[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["Name"] = "Chainsaw", ["Version"] = "9.9.9-test", ["AssetName"] = "chainsaw-root.zip",
                            ["DownloadUrl"] = "https://example.invalid/chainsaw-root.zip", ["ExpectedSha256"] = Hashing.Sha256Hex(zip),
                            ["License"] = "GPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                            ["ExecutableNames"] = new[] { "chainsaw_x86_64-pc-windows-msvc.exe", "chainsaw.exe" }, ["RulesRelativePath"] = "",
                            ["SupportFolders"] = new[] { "rules" },
                            ["Notes"] = "test pin",
                        },
                    },
                }));
                try
                {
                    var entry = ToolCatalog.Entry("Chainsaw", t.File("catalog.json"));
                    ToolInstaller.Install(entry, zip, deepRoot, Quiet());
                    Assert.True(File.Exists(LongPath.For(Path.Combine(deepRoot, "install.log"))));
                    var row = Assert.Single(ToolInstaller.List(deepRoot), r => r.Name == "Chainsaw");
                    Assert.Equal("9.9.9-test", row.Version);
                    Assert.Equal(Path.Combine(deepRoot, @"chainsaw\chainsaw_x86_64-pc-windows-msvc.exe"), row.Location);
                }
                finally
                {
                    // TempDir cannot delete past 260 characters; remove the deep tool root here.
                    try { Directory.Delete(LongPath.For(deepRoot), true); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
            }
        }

        [Fact]
        public void A_rules_git_ref_that_points_outside_refs_heads_is_not_read_as_a_commit()
        {
            // A rooted ref (C:\...) made Path.Combine return that file, and its first 12 characters became the rules version.
            using (var t = new TempDir())
            {
                var secret = t.File("not-a-commit.txt");
                File.WriteAllText(secret, "0123456789abcdef0123456789abcdef\n");
                var zip = t.File("chainsaw-ref.zip");
                using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
                {
                    WriteEntry(archive, "chainsaw/chainsaw_x86_64-pc-windows-msvc.exe", "fake-chainsaw");
                    WriteEntry(archive, "chainsaw/rules/.git/HEAD", "ref: refs/heads/" + secret + "\n");
                }
                File.WriteAllText(t.File("catalog.json"), Json.Indented(new Dictionary<string, object?>
                {
                    ["Tools"] = new[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["Name"] = "Chainsaw", ["Version"] = "9.9.9-test", ["AssetName"] = "chainsaw-ref.zip",
                            ["DownloadUrl"] = "https://example.invalid/chainsaw-ref.zip", ["ExpectedSha256"] = Hashing.Sha256Hex(zip),
                            ["License"] = "GPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                            ["ExecutableNames"] = new[] { "chainsaw_x86_64-pc-windows-msvc.exe", "chainsaw.exe" }, ["RulesRelativePath"] = "rules",
                            ["SupportFolders"] = new[] { "rules" },
                            ["Notes"] = "test pin",
                        },
                    },
                }));
                var entry = ToolCatalog.Entry("Chainsaw", t.File("catalog.json"));
                var record = ToolInstaller.Install(entry, zip, t.File("tools"), Quiet());
                Assert.Equal("bundled with release 9.9.9-test", record["RulesVersion"]);
            }
        }

        [Fact]
        public void A_tool_at_a_path_too_long_to_start_is_refused_with_a_row_and_never_launched()
        {
            using (var t = new TempDir())
            {
                // One folder name of 210 characters pushes the executable past the 259-character start limit.
                var deepDir = Path.Combine(t.Path, new string('d', 210));
                var exe = Path.Combine(deepDir, "evtxecmd.cmd");
                Directory.CreateDirectory(LongPath.For(deepDir));
                File.WriteAllText(LongPath.For(exe), ArgsRecorder(0), Encoding.ASCII);
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                Write(Path.Combine(pkg, @"07_Event_Logs\evtx\Security.evtx"), "x");
                try
                {
                    Assert.True(exe.Length > ToolProcess.MaxStartPath);
                    var run = ComposeRunner.Run(pkg, Quiet(), t.File("empty"),
                        new Dictionary<string, string> { ["EvtxECmd"] = exe }, System32Only, new[] { "EvtxECmd" });
                    var row = run.Rows.Single(r => r.Tool == "EvtxECmd");
                    Assert.Equal("TooLongToStart", row.Status);
                    Assert.Contains("shorter tool root", row.Note);
                    // Refused before anything ran: the recorder's arguments file was never written.
                    Assert.False(File.Exists(LongPath.For(Path.Combine(deepDir, "args_evtxecmd.txt"))));
                }
                finally
                {
                    try { Directory.Delete(LongPath.For(deepDir), true); } catch (IOException) { }
                }
            }
        }

        [Fact]
        public void Compose_names_the_selected_tools_that_are_missing_before_it_runs()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"));
                var log = new StringWriter();
                var run = ComposeRunner.Run(pkg, new StatusLog(log), t.File("empty"), new Dictionary<string, string>(), System32Only, new[] { "PECmd" });
                // Checked on the warning line itself, so no other line in the log can stand in for it.
                var warning = log.ToString().Split('\n').Single(l => l.Contains("selected tool(s) not found"));
                Assert.Contains("1 selected tool(s) not found: PECmd", warning);
                Assert.Contains("recorded as NotOnPath", warning);
                // A tool the operator left out is not named in the warning.
                Assert.DoesNotContain("Hayabusa", warning);
                // The inventory row the warning describes.
                Assert.Equal("NotOnPath", run.Rows.Single(r => r.Tool == "PECmd").Status);
            }
        }

        [Fact]
        public void The_missing_tool_warning_is_logged_before_a_selected_tool_runs()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                Write(Path.Combine(pkg, @"07_Event_Logs\evtx\Security.evtx"), "x");
                Write(t.File(@"bin\evtxecmd.cmd"), ArgsRecorder(0));
                var log = new StringWriter();
                ComposeRunner.Run(pkg, new StatusLog(log), t.File("empty"),
                    new Dictionary<string, string> { ["EvtxECmd"] = t.File(@"bin\evtxecmd.cmd") }, System32Only, new[] { "PECmd", "EvtxECmd" });
                var text = log.ToString();
                var warnAt = text.IndexOf("1 selected tool(s) not found: PECmd", StringComparison.Ordinal);
                // The run line is "<Tool>: <resolved path> <args>"; match the exact path so no other line can stand in for it.
                var runAt = text.IndexOf("EvtxECmd: " + t.File(@"bin\evtxecmd.cmd"), StringComparison.Ordinal);
                Assert.True(warnAt >= 0, text);
                Assert.True(runAt > warnAt, text);
                Assert.True(File.Exists(t.File(@"bin\args_evtxecmd.txt")));
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
                Assert.Equal("bundled with release 9.9.9-test", ToolManifest.Get(installed, "RulesVersion"));
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
        public void A_release_without_rules_moves_the_earlier_rules_aside_and_records_no_rule_set()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"v1\hayabusa-1.0.0.exe"), "v1");
                Write(t.File(@"v1\rules\dummy.yml"), "title: v1");
                ZipFile.CreateFromDirectory(t.File("v1"), t.File("v1.zip"));
                Write(t.File(@"v2\hayabusa-2.0.0.exe"), "v2");
                ZipFile.CreateFromDirectory(t.File("v2"), t.File("v2.zip"));
                var hash1 = Hashing.Sha256Hex(t.File("v1.zip"));
                var hash2 = Hashing.Sha256Hex(t.File("v2.zip"));

                string Catalog(string version, string sha)
                {
                    var file = t.File("catalog-" + version + ".json");
                    File.WriteAllText(file, Json.Indented(new Dictionary<string, object?>
                    {
                        ["Tools"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["Name"] = "Hayabusa", ["Version"] = version, ["AssetName"] = "x.zip",
                                ["DownloadUrl"] = "https://example.invalid/x.zip", ["ExpectedSha256"] = sha,
                                ["License"] = "AGPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                                ["ExecutableNames"] = new[] { "hayabusa.exe", "hayabusa-*.exe" }, ["RulesRelativePath"] = "rules", ["Notes"] = "test pin",
                            },
                        },
                    }));
                    return file;
                }
                var root = t.File("tools");
                ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("1.0.0", hash1)), t.File("v1.zip"), root, Quiet());
                Assert.True(Directory.Exists(Path.Combine(root, "hayabusa", "rules")));

                // The next release ships no rules folder: the earlier one must not stay beside the tool and be recorded.
                ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("2.0.0", hash2)), t.File("v2.zip"), root, Quiet());
                var installed = ToolManifest.Find("Hayabusa", root)!;
                Assert.Equal("2.0.0", ToolManifest.Get(installed, "Version"));
                Assert.False(Directory.Exists(Path.Combine(root, "hayabusa", "rules")));
                Assert.Single(Directory.GetDirectories(Path.Combine(root, "hayabusa"), "rules.replaced-*"));
                Assert.Equal("", ToolManifest.Get(installed, "RulesVersion"));
                Assert.Equal("", ToolManifest.Get(installed, "RulesPath"));
            }
        }

        [Fact]
        public void An_untracked_tool_reports_an_unversioned_rule_set_only_when_rules_sit_beside_it()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"bin\chainsaw.exe"), "x");
                Write(t.File(@"bin\rules\r.yml"), "x");
                var withRules = ToolResolver.Resolve("Chainsaw", new[] { "chainsaw.exe" }, t.File(@"bin\chainsaw.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("local-unversioned", withRules.RulesVersion);

                Write(t.File(@"bare\chainsaw.exe"), "x");
                var bare = ToolResolver.Resolve("Chainsaw", new[] { "chainsaw.exe" }, t.File(@"bare\chainsaw.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("", bare.RulesVersion);
            }
        }

        [Fact]
        public void An_explicit_path_to_a_tracked_install_reports_what_it_recorded_and_a_plain_file_is_no_rule_set()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"tools\hayabusa\hayabusa.exe"), "x");
                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "Hayabusa", ["Version"] = "4.0.0",
                    ["ExecutablePath"] = t.File(@"tools\hayabusa\hayabusa.exe"), ["RulesVersion"] = "bundled with release 4.0.0",
                });
                var r = ToolResolver.Resolve("Hayabusa", new[] { "hayabusa.exe" }, t.File(@"tools\hayabusa\hayabusa.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("ToolPath", r.Source);
                Assert.Equal("4.0.0", r.Version);
                Assert.Equal("bundled with release 4.0.0", r.RulesVersion);

                // A plain file named rules beside an executable is not a rule folder.
                Write(t.File(@"bare\chainsaw.exe"), "x");
                Write(t.File(@"bare\rules"), "not a folder");
                var bare = ToolResolver.Resolve("Chainsaw", new[] { "chainsaw.exe" }, t.File(@"bare\chainsaw.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("", bare.RulesVersion);

                // A damaged ExecutablePath with invalid path characters must not stop a valid explicit path.
                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "Chainsaw", ["Version"] = "2.0.0", ["ExecutablePath"] = "bad<|name.exe",
                });
                var ok = ToolResolver.Resolve("Chainsaw", new[] { "chainsaw.exe" }, t.File(@"bare\chainsaw.exe"), t.File("tools"), System32Only)!;
                Assert.Equal("ToolPath", ok.Source);
            }
        }

        [Fact]
        public void A_failed_reinstall_puts_back_the_earlier_folders_and_leaves_the_manifest_alone()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"v1\hayabusa-1.0.0.exe"), "v1");
                Write(t.File(@"v1\rules\dummy.yml"), "title: v1");
                ZipFile.CreateFromDirectory(t.File("v1"), t.File("v1.zip"));
                // The next release ships a valid rules folder, then a plain file where the sigma folder belongs.
                Write(t.File(@"v2\hayabusa-2.0.0.exe"), "v2");
                Write(t.File(@"v2\rules\dummy.yml"), "title: v2");
                Write(t.File(@"v2\sigma"), "a file, not a folder");
                ZipFile.CreateFromDirectory(t.File("v2"), t.File("v2.zip"));
                var hash1 = Hashing.Sha256Hex(t.File("v1.zip"));
                var hash2 = Hashing.Sha256Hex(t.File("v2.zip"));

                string Catalog(string version, string sha)
                {
                    var file = t.File("catalog-" + version + ".json");
                    File.WriteAllText(file, Json.Indented(new Dictionary<string, object?>
                    {
                        ["Tools"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["Name"] = "Hayabusa", ["Version"] = version, ["AssetName"] = "x.zip",
                                ["DownloadUrl"] = "https://example.invalid/x.zip", ["ExpectedSha256"] = sha,
                                ["License"] = "AGPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                                ["ExecutableNames"] = new[] { "hayabusa.exe", "hayabusa-*.exe" },
                                ["RulesRelativePath"] = "rules", ["SupportFolders"] = new[] { "rules", "sigma" }, ["Notes"] = "test pin",
                            },
                        },
                    }));
                    return file;
                }
                var root = t.File("tools");
                ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("1.0.0", hash1)), t.File("v1.zip"), root, Quiet());

                Assert.Throws<InvalidDataException>(() =>
                    ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("2.0.0", hash2)), t.File("v2.zip"), root, Quiet()));

                // The earlier rules folder is back with its own content, nothing was left behind, and tools.json still says 1.0.0.
                Assert.Equal("title: v1", File.ReadAllText(Path.Combine(root, "hayabusa", "rules", "dummy.yml")));
                Assert.Empty(Directory.GetDirectories(Path.Combine(root, "hayabusa"), "rules.replaced-*"));
                Assert.False(File.Exists(Path.Combine(root, "hayabusa", "hayabusa-2.0.0.exe")));
                Assert.False(Directory.Exists(Path.Combine(root, "hayabusa", "2.0.0")));
                Assert.Equal("1.0.0", ToolManifest.Get(ToolManifest.Find("Hayabusa", root)!, "Version"));
            }
        }

        [Fact]
        public void A_failed_reinstall_of_the_same_version_keeps_the_earlier_version_folder()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"v1\hayabusa-1.0.0.exe"), "v1");
                ZipFile.CreateFromDirectory(t.File("v1"), t.File("v1.zip"));
                // Same version, but the archive has no executable: the reinstall fails after the earlier folder was set aside.
                Write(t.File(@"bad\readme.txt"), "no program here");
                ZipFile.CreateFromDirectory(t.File("bad"), t.File("bad.zip"));
                var hash1 = Hashing.Sha256Hex(t.File("v1.zip"));
                var hashBad = Hashing.Sha256Hex(t.File("bad.zip"));

                string Catalog(string sha)
                {
                    var file = t.File("catalog-" + sha.Substring(0, 8) + ".json");
                    File.WriteAllText(file, Json.Indented(new Dictionary<string, object?>
                    {
                        ["Tools"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["Name"] = "Hayabusa", ["Version"] = "1.0.0", ["AssetName"] = "x.zip",
                                ["DownloadUrl"] = "https://example.invalid/x.zip", ["ExpectedSha256"] = sha,
                                ["License"] = "AGPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                                ["ExecutableNames"] = new[] { "hayabusa.exe", "hayabusa-*.exe" }, ["RulesRelativePath"] = "rules", ["Notes"] = "test pin",
                            },
                        },
                    }));
                    return file;
                }
                var root = t.File("tools");
                ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog(hash1)), t.File("v1.zip"), root, Quiet());

                Assert.Throws<InvalidDataException>(() =>
                    ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog(hashBad)), t.File("bad.zip"), root, Quiet()));

                // The earlier 1.0.0 folder is back with its executable, and no partial extraction is left behind.
                Assert.Equal("v1", File.ReadAllText(Path.Combine(root, "hayabusa", "1.0.0", "hayabusa-1.0.0.exe")));
                Assert.Empty(Directory.GetDirectories(Path.Combine(root, "hayabusa"), "1.0.0.replaced-*"));
                Assert.Equal("1.0.0", ToolManifest.Get(ToolManifest.Find("Hayabusa", root)!, "Version"));
            }
        }

        [Fact]
        public void A_damaged_tool_root_does_not_stop_a_valid_explicit_tool_path()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"bin\chainsaw.exe"), "x");
                var r = ToolResolver.Resolve("Chainsaw", new[] { "chainsaw.exe" }, t.File(@"bin\chainsaw.exe"), "bad<|root", System32Only)!;
                Assert.Equal("ToolPath", r.Source);
                Assert.Equal(t.File(@"bin\chainsaw.exe"), r.Path);
            }
        }

        [Fact]
        public void A_locked_manifest_undoes_the_swap_when_the_reinstall_cannot_record_it()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"v1\hayabusa-1.0.0.exe"), "v1");
                Write(t.File(@"v1\rules\dummy.yml"), "title: v1");
                ZipFile.CreateFromDirectory(t.File("v1"), t.File("v1.zip"));
                Write(t.File(@"v2\hayabusa-2.0.0.exe"), "v2");
                Write(t.File(@"v2\rules\dummy.yml"), "title: v2");
                ZipFile.CreateFromDirectory(t.File("v2"), t.File("v2.zip"));
                var hash1 = Hashing.Sha256Hex(t.File("v1.zip"));
                var hash2 = Hashing.Sha256Hex(t.File("v2.zip"));

                string Catalog(string version, string sha)
                {
                    var file = t.File("catalog-" + version + ".json");
                    File.WriteAllText(file, Json.Indented(new Dictionary<string, object?>
                    {
                        ["Tools"] = new[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["Name"] = "Hayabusa", ["Version"] = version, ["AssetName"] = "x.zip",
                                ["DownloadUrl"] = "https://example.invalid/x.zip", ["ExpectedSha256"] = sha,
                                ["License"] = "AGPL-3.0", ["ProjectUrl"] = "https://example.invalid",
                                ["ExecutableNames"] = new[] { "hayabusa.exe", "hayabusa-*.exe" }, ["RulesRelativePath"] = "rules", ["Notes"] = "test pin",
                            },
                        },
                    }));
                    return file;
                }
                var root = t.File("tools");
                ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("1.0.0", hash1)), t.File("v1.zip"), root, Quiet());

                // tools.json cannot be read or rewritten while held open, so the reinstall cannot record the new version.
                using (new FileStream(ToolManifest.PathOf(root), FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    Assert.ThrowsAny<IOException>(() =>
                        ToolInstaller.Install(ToolCatalog.Entry("Hayabusa", Catalog("2.0.0", hash2)), t.File("v2.zip"), root, Quiet()));
                }

                Assert.Equal("title: v1", File.ReadAllText(Path.Combine(root, "hayabusa", "rules", "dummy.yml")));
                Assert.Empty(Directory.GetDirectories(Path.Combine(root, "hayabusa"), "rules.replaced-*"));
                Assert.False(Directory.Exists(Path.Combine(root, "hayabusa", "2.0.0")));
                Assert.False(File.Exists(Path.Combine(root, "hayabusa", "hayabusa-2.0.0.exe")));
                Assert.Equal("1.0.0", ToolManifest.Get(ToolManifest.Find("Hayabusa", root)!, "Version"));
            }
        }

        [Fact]
        public void A_manifest_row_from_before_the_rules_field_reads_local_rules_beside_its_executable()
        {
            using (var t = new TempDir())
            {
                Write(t.File(@"tools\hayabusa\hayabusa.exe"), "x");
                Write(t.File(@"tools\hayabusa\rules\r.yml"), "x");
                // No RulesVersion key at all: written before the field existed.
                ToolManifest.Save(t.File("tools"), new Dictionary<string, object?>
                {
                    ["Name"] = "Hayabusa", ["Version"] = "4.0.0", ["ExecutablePath"] = t.File(@"tools\hayabusa\hayabusa.exe"),
                });
                var r = ToolResolver.Resolve("Hayabusa", new[] { "hayabusa.exe" }, null, t.File("tools"), System32Only)!;
                Assert.Equal("Manifest", r.Source);
                Assert.Equal("local-unversioned", r.RulesVersion);
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
                Assert.Equal(10, rows.Count);
                Assert.Equal("Registered", rows.Single(r => r.Name == "EvtxECmd").Status);
                Assert.Equal("NotFound", rows.Single(r => r.Name == "AmcacheParser").Status);
                Assert.Equal("NotFound", rows.Single(r => r.Name == "SBECmd").Status);
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
        public void A_tool_found_on_PATH_is_recorded_with_its_file_version_and_a_missing_journal_names_the_switch()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"08_Filesystem\usn");
                var bin = Directory.CreateDirectory(t.File("bin")).FullName;
                var source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "whoami.exe");
                File.Copy(source, Path.Combine(bin, "MFTECmd.exe"));
                var row = ComposeRunner.Run(pkg, Quiet(), t.File("empty"), null, bin, new[] { "MFTECmd" }).Rows.Single(r => r.Tool == "MFTECmd");
                Assert.Equal("NoInput", row.Status);
                var expected = System.Diagnostics.FileVersionInfo.GetVersionInfo(Path.Combine(bin, "MFTECmd.exe")).FileVersion;
                Assert.False(string.IsNullOrEmpty(expected));
                Assert.Equal(expected, row.Version);
                Assert.Contains("-IncludeUsnJournal", row.Note);
                Assert.DoesNotContain("Re-collect elevated", row.Note);
            }
        }

        [Fact]
        public void Compose_tools_match_compose_jobs_and_unselected_tools_are_NotSelected()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"));
                Write(Path.Combine(pkg, @"analysis\external\pecmd\pecmd.csv"), "old");
                var all = Compose(pkg, t.File("empty")).Rows.Where(r => r.Status != "Retained" && r.Tool != "*").Select(r => r.Tool).ToList();
                Assert.Equal(ComposeTools.All.Select(c => c.Name), all);

                var rows = ComposeRunner.Run(pkg, Quiet(), t.File("empty"), null, System32Only, new[] { "hayabusa" }).Rows;
                Assert.Equal("NotOnPath", rows.Single(r => r.Tool == "Hayabusa").Status);
                var pecmd = rows.Where(r => r.Tool == "PECmd").ToList();
                Assert.Equal("NotSelected", pecmd[0].Status);
                Assert.EndsWith(@"pecmd\pecmd.csv", Assert.Single(pecmd, r => r.Status == "Retained").DestRelative);
                Assert.Equal(ComposeTools.All.Count - 1, rows.Count(r => r.Status == "NotSelected"));
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
        public void Output_from_a_run_that_exits_with_an_error_is_kept_but_marked_partial()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"07_Event_Logs\evtx");
                Write(t.File(@"bin\hayabusa.cmd"),
                    "@echo off\r\n:loop\r\nif \"%~1\"==\"\" exit /b 3\r\nif /i \"%~1\"==\"-o\" echo new> \"%~dp2fresh.csv\"\r\nshift\r\ngoto loop\r\n");
                var tools = new Dictionary<string, string> { ["Hayabusa"] = t.File(@"bin\hayabusa.cmd") };
                var hb = Compose(pkg, t.File("empty"), tools).Rows.Single(r => r.Tool == "Hayabusa");
                Assert.Equal("Copied", hb.Status);
                Assert.Contains("exited with code 3", hb.Note);

                // With complete earlier output present, a failed run's partial output is discarded.
                var dir = Path.Combine(pkg, @"analysis\external\hayabusa");
                File.Delete(Path.Combine(dir, "fresh.csv"));
                Write(Path.Combine(dir, "complete.csv"), "old");
                var rows = Compose(pkg, t.File("empty"), tools).Rows.Where(r => r.Tool == "Hayabusa").ToList();
                Assert.Contains("earlier output was kept", rows.Single(r => r.Status == "ToolError").Note);
                Assert.EndsWith("complete.csv", rows.Single(r => r.Status == "Retained").DestRelative);
                Assert.False(File.Exists(Path.Combine(dir, "fresh.csv")));
                Assert.Empty(Directory.GetFileSystemEntries(Path.Combine(pkg, @"analysis\external"), ".hayabusa.*"));
            }
        }

        [Fact]
        public void A_log_the_run_did_not_write_is_not_left_from_an_earlier_run()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"08_Filesystem\prefetch");
                var stale = Path.Combine(pkg, @"analysis\external\pecmd\tool_stdout.txt");
                Write(stale, "You must install or update .NET to run this application.");
                // Not a valid executable, so the start fails and only tool_stderr.txt is written.
                Write(t.File(@"bin\PECmd.exe"), "not a program");
                var row = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["PECmd"] = t.File(@"bin\PECmd.exe") })
                    .Rows.Single(r => r.Tool == "PECmd");
                Assert.Equal("ToolError", row.Status);
                Assert.False(File.Exists(stale));
            }
        }

        [Fact]
        public void A_tool_missing_its_NET_runtime_is_reported_with_its_logs_kept()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"08_Filesystem\prefetch");
                Write(t.File(@"bin\pecmd.cmd"), "@echo You must install or update .NET to run this application.\r\n@exit /b 2147516566\r\n");
                var row = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["PECmd"] = t.File(@"bin\pecmd.cmd") })
                    .Rows.Single(r => r.Tool == "PECmd");
                Assert.Equal("MissingRuntime", row.Status);
                Assert.Contains("You must install", File.ReadAllText(Path.Combine(pkg, @"analysis\external\pecmd\tool_stdout.txt")));
            }
        }

        [Fact]
        public void AmcacheParser_without_the_hive_is_NoInput_and_is_not_run()
        {
            using (var t = new TempDir())
            {
                var pkg = Package(t.File("Foton_HOST_20260101-000000Z"), @"08_Filesystem\amcache");
                Write(t.File(@"bin\amcacheparser.cmd"), ArgsRecorder(0));
                var row = Compose(pkg, t.File("empty"), new Dictionary<string, string> { ["AmcacheParser"] = t.File(@"bin\amcacheparser.cmd") })
                    .Rows.Single(r => r.Tool == "AmcacheParser");
                Assert.Equal("NoInput", row.Status);
                Assert.Contains("Amcache.hve", row.Note);
                Assert.False(File.Exists(t.File(@"bin\args_amcacheparser.txt")));
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
        public void Compose_on_a_ZIP_writes_into_its_extraction_and_refuses_a_single_file()
        {
            using (var t = new TempDir())
            {
                var src = Package(t.File(@"src\Foton_HOST_20260115-120000Z"));
                System.IO.Compression.ZipFile.CreateFromDirectory(src, t.File("case.zip"), System.IO.Compression.CompressionLevel.Fastest, includeBaseDirectory: true);
                var run = Compose(t.File("case.zip"), t.File("empty"));
                Assert.Equal(t.File(@"case-extracted\Foton_HOST_20260115-120000Z\analysis\external\external_parse_inventory.csv"), run.InventoryPath);
                Assert.True(File.Exists(run.InventoryPath));

                File.WriteAllText(t.File("notes.txt"), "x");
                Assert.Contains("not a single file", Assert.Throws<InvalidOperationException>(() => Compose(t.File("notes.txt"), t.File("empty"))).Message);
            }
        }
    }
}
