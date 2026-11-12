using System;
using System.IO;
using Foton.Tools;
using Xunit;

namespace Foton.Tests
{
    public class AcquireTests
    {
        [Fact]
        public void Arguments_quote_values_and_refuse_ones_a_command_line_could_misread()
        {
            var args = CollectorLauncher.Arguments(new AcquireRequest
            {
                Kind = CollectorKind.Collect, OutputPath = @"D:\My Cases\", CaseNumber = "CASE-0001", Examiner = "Jane Doe", ProfilePath = @"C:\t\p.json",
            });
            Assert.Equal(@"-OutputPath ""D:\My Cases\\"" -CaseNumber CASE-0001 -Examiner ""Jane Doe"" -Profile C:\t\p.json", args);
            Assert.Equal("", CollectorLauncher.Arguments(new AcquireRequest { Kind = CollectorKind.Collect }));
            Assert.Equal("-LoadUserHives", CollectorLauncher.Arguments(new AcquireRequest { Kind = CollectorKind.Baseline, LoadUserHives = true, CaseNumber = "ignored" }));
            foreach (var bad in new[] { "a\"b", "-Deep", "a\r\nb", "a\tb" })
                Assert.Throws<ArgumentException>(() => CollectorLauncher.Arguments(new AcquireRequest { Kind = CollectorKind.Collect, CaseNumber = bad }));
        }

        [Fact]
        public void Check_refuses_another_program_an_old_collector_or_a_hash_list_mismatch()
        {
            Assert.Contains("not foton-baseline.exe", Assert.Throws<InvalidDataException>(() => DeploymentBundle.CheckExecutable("foton-baseline.exe", new Version(2, 6, 0), "foton.exe", "2.10.0.0")).Message);
            Assert.Contains("2.6.0 or later", Assert.Throws<InvalidDataException>(() => DeploymentBundle.CheckExecutable("foton-baseline.exe", new Version(2, 6, 0), "foton-baseline.exe", "2.5.0.0")).Message);
            Assert.Equal(new Version(2, 10, 0, 0), DeploymentBundle.CheckExecutable("foton-baseline.exe", new Version(2, 6, 0), "FOTON-BASELINE.EXE", "2.10.0.0"));
            Assert.Equal(new Version(2, 8, 0), CollectorLauncher.MinimumVersion(CollectorKind.Collect));
            // A two-part version resource is compared and named without throwing anything but InvalidDataException.
            Assert.Equal(new Version(2, 9), DeploymentBundle.CheckExecutable("foton-baseline.exe", new Version(2, 6, 0), "foton-baseline.exe", "2.9"));
            Assert.Contains("2.5 is too old", Assert.Throws<InvalidDataException>(() => DeploymentBundle.CheckExecutable("foton-baseline.exe", new Version(2, 6, 0), "foton-baseline.exe", "2.5")).Message);
            Assert.Contains("foton-collect 2.7 does not read", Assert.Throws<InvalidDataException>(() => DeploymentBundle.CheckCollect("foton-collect.exe", "2.7")).Message);
            foreach (var full in new[] { @"D:\Cases", @"\\server\share\Cases" }) Assert.True(CollectorLauncher.IsFullPath(full), full);
            foreach (var rel in new[] { "Cases", @".\Cases", @"C:Cases", @"\Cases" }) Assert.False(CollectorLauncher.IsFullPath(rel), rel);
            using (var t = new TempDir())
            {
                File.WriteAllText(t.File("foton-collect.exe"), "not a program");
                Assert.Throws<InvalidDataException>(() => CollectorLauncher.Check(t.File("foton-collect.exe"), CollectorKind.Collect));
                Assert.Throws<FileNotFoundException>(() => CollectorLauncher.Check(t.File("foton-baseline.exe"), CollectorKind.Baseline));
            }
        }

        [Fact]
        public void Check_accepts_the_built_collector_and_reads_the_release_list_beside_it()
        {
            var config = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')).Parent!.Name;
            var built = Path.Combine(TestPaths.Root, "cli", "Foton.Collect.Cli", "bin", config, "net462", "foton-collect.exe");
            Assert.True(File.Exists(built), "Build the solution first: " + built);
            using (var t = new TempDir())
            {
                var exe = t.File("foton-collect.exe");
                File.Copy(built, exe);
                var unverified = CollectorLauncher.Check(exe, CollectorKind.Collect);
                Assert.False(unverified.Verified);
                File.WriteAllText(t.File("SHA256SUMS.txt"), unverified.Sha256 + "  foton-collect.exe\n");
                Assert.True(CollectorLauncher.Check(exe, CollectorKind.Collect).Verified);
                File.WriteAllText(t.File("SHA256SUMS.txt"), new string('a', 64) + "  foton-collect.exe\n");
                Assert.Throws<InvalidDataException>(() => CollectorLauncher.Check(exe, CollectorKind.Collect));
            }
        }

        [Fact]
        public void A_new_run_is_the_package_folder_created_after_the_start()
        {
            using (var t = new TempDir())
            {
                var started = DateTime.UtcNow.AddSeconds(-1);
                Directory.CreateDirectory(t.File("Foton_HOST_20260101-000000Z"));
                Directory.SetCreationTimeUtc(t.File("Foton_HOST_20260101-000000Z"), started.AddHours(-1));
                Directory.CreateDirectory(t.File("Foton_HOST_20261111-120000Z"));
                Directory.CreateDirectory(t.File("FotonBaseline_HOST_20261111-120000Z"));
                Directory.CreateDirectory(t.File("Foton_HOST_20261111-120000Z-extracted"));
                Assert.Equal(t.File("Foton_HOST_20261111-120000Z"), CollectorLauncher.FindNewRun(t.Path, CollectorKind.Collect, started));
                Assert.Equal(t.File("FotonBaseline_HOST_20261111-120000Z"), CollectorLauncher.FindNewRun(t.Path, CollectorKind.Baseline, started));
                Assert.Null(CollectorLauncher.FindNewRun(t.File("missing"), CollectorKind.Collect, started));
                Assert.Equal(Path.Combine(t.File("Foton_HOST_20261111-120000Z"), "00_Collection", "collection.log"), CollectorLauncher.LogPath(CollectorKind.Collect, t.File("Foton_HOST_20261111-120000Z")));
                Assert.Equal(Path.Combine(t.File("FotonBaseline_HOST_20261111-120000Z"), "baseline.log"), CollectorLauncher.LogPath(CollectorKind.Baseline, t.File("FotonBaseline_HOST_20261111-120000Z")));
            }
        }

        [Fact]
        public void The_earlier_baseline_is_the_newest_older_one_of_the_same_host()
        {
            using (var t = new TempDir())
            {
                foreach (var d in new[] { "FotonBaseline_HOST_20261101-000000Z", "FotonBaseline_HOST_20261105-000000Z", "FotonBaseline_OTHER_20261110-000000Z", "FotonBaseline_HOST_20261111-000000Z" })
                {
                    Directory.CreateDirectory(t.File(d));
                    File.WriteAllText(Path.Combine(t.File(d), "baseline.json"), "{}");
                }
                Directory.CreateDirectory(t.File("FotonBaseline_HOST_20261108-000000Z"));   // no baseline.json: not a baseline
                Assert.Equal(t.File("FotonBaseline_HOST_20261105-000000Z"), CollectorLauncher.EarlierBaseline(t.Path, t.File("FotonBaseline_HOST_20261111-000000Z")));
                Assert.Null(CollectorLauncher.EarlierBaseline(t.Path, t.File("FotonBaseline_HOST_20261101-000000Z")));
            }
        }

        [Fact]
        public void A_log_tail_returns_each_complete_new_line_once()
        {
            using (var t = new TempDir())
            {
                var path = t.File("collection.log");
                var tail = new LogTail(path);
                Assert.Empty(tail.ReadNewLines());
                File.WriteAllText(path, "one\r\ntwo\r\nthr");
                Assert.Equal(new[] { "one", "two" }, tail.ReadNewLines());
                File.AppendAllText(path, "ee\r\n");
                Assert.Equal(new[] { "three" }, tail.ReadNewLines());
                Assert.Empty(tail.ReadNewLines());
                using (var writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                {
                    var bytes = System.Text.Encoding.UTF8.GetBytes("four\r\n");
                    writer.Write(bytes, 0, bytes.Length);
                    writer.Flush();
                    Assert.Equal(new[] { "four" }, tail.ReadNewLines());   // readable while the writer holds it open

                    // A UTF-8 character written in two pieces is decoded once it is whole.
                    var word = System.Text.Encoding.UTF8.GetBytes("caf\u00e9\r\n");
                    writer.Write(word, 0, 4); writer.Write(word, 4, 1); writer.Flush();   // "caf" + the first byte of the e-acute
                    Assert.Empty(tail.ReadNewLines());
                    writer.Write(word, 5, word.Length - 5); writer.Flush();
                    Assert.Equal(new[] { "caf\u00e9" }, tail.ReadNewLines());
                }

                // A log replaced by a new file (here as long as the old one) is read from its start.
                File.Delete(path);
                System.Threading.Thread.Sleep(50);
                File.WriteAllText(path, new string('x', 30) + "\r\nnew\r\n");
                File.SetCreationTimeUtc(path, DateTime.UtcNow.AddMinutes(1));
                Assert.Equal(new[] { new string('x', 30), "new" }, tail.ReadNewLines());
            }
        }
    }
}
