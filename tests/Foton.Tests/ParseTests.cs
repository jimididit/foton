using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Foton.Core;
using Foton.Parse;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Parsers match 1.38.x Invoke-FotonParse on synthetic fixtures (golden files), and fail closed.</summary>
    public class ParseTests
    {
        static string Fixture(string name) => Path.Combine(TestPaths.Root, "testdata", "parse", name);
        const string Case = "Foton_PARSEHOST_20260115-120000Z";
        static readonly StatusLog Quiet = new StatusLog(new StringWriter());

        static string CopyCase(TempDir t, string name)
        {
            var dst = Path.Combine(t.Path, name);
            foreach (var f in Directory.GetFiles(Fixture(name), "*", SearchOption.AllDirectories))
            {
                var to = Path.Combine(dst, f.Substring(Fixture(name).Length + 1));
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                File.Copy(f, to);
            }
            return dst;
        }

        [Theory]
        [InlineData(Case, "parse")]
        [InlineData("Foton_EMPTYHOST_20260115-120000Z", "parse-empty")]
        public void Package_csv_and_html_are_byte_identical_to_1_38(string caseName, string tag)
        {
            using (var t = new TempDir())
            {
                var root = CopyCase(t, caseName);
                var run = ParseRunner.Run(root, Quiet);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden(tag + "-records.csv")), File.ReadAllBytes(Path.Combine(root, "analysis", "parsed_records.csv")));
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden(tag + "-report.html")), File.ReadAllBytes(Path.Combine(root, "analysis", "Foton_Parse.html")));
            }
        }

        [Fact]
        public void Synthetic_fields_parse_as_expected()
        {
            var fs = Path.Combine(Fixture(Case), "08_Filesystem");
            var pf = PrefetchParser.Parse(Path.Combine(fs, "prefetch", "NOTEPAD.EXE-11111111.pf"));
            Assert.Equal(("SCCA", true, "NOTEPAD.EXE"), (pf.Format, pf.Supported, pf.Identity));
            Assert.Equal("C:\\Tools\\caf\u00e9.exe", LnkParser.Parse(Path.Combine(fs, "lnk", "cafe.lnk")).Identity);
            var jl = JumplistParser.Parse(Path.Combine(fs, "jumplists", "1a2b3c.automaticDestinations-ms"));
            var dest = jl.Single(r => r.Format == "DestList");
            Assert.Equal("C:\\Windows\\notepad.exe", dest.Identity);
            Assert.Equal("2020-01-15 12:00:00", dest.Field("LastAccessUtc"));
            Assert.Equal("Unpinned", dest.Field("PinStatus"));
            Assert.Equal("HOST", dest.Field("Hostname"));
            var am = AmcacheParser.Parse(Path.Combine(fs, "amcache", "Amcache.hve")).Single();
            Assert.Equal(("AmcacheFile", "c:\\windows\\notepad.exe", "2020-01-15 12:00:00"), (am.Format, am.Field("LowerCaseLongPath"), am.Field("KeyLastWriteUtc")));
        }

        [Fact]
        public void An_empty_ole_stream_before_others_does_not_drop_them()
        {
            // 1.38.x cast the empty stream's ENDOFCHAIN start (-2) to uint32 and lost every stream after it.
            var b = File.ReadAllBytes(Path.Combine(Fixture(Case), "08_Filesystem", "jumplists", "1a2b3c.automaticDestinations-ms"));
            const int dir = 512 + 512, entry = 128;
            var destList = new byte[entry];
            Array.Copy(b, dir + entry, destList, 0, entry);
            Array.Copy(b, dir + 3 * entry, b, dir + entry, entry);
            Array.Copy(destList, 0, b, dir + 3 * entry, entry);
            var names = OleCompound.Streams(b).Select(s => s.Name).ToList();
            Assert.Equal(new[] { "Empty", "1", "DestList" }, names);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Every_lnk_in_a_custom_destinations_category_is_parsed(bool clsidPrefixed)
        {
            // 1.38.x stopped each entry only at the category footer, so the second LNK here was skipped.
            var one = File.ReadAllBytes(Path.Combine(Fixture(Case), "08_Filesystem", "jumplists", "4d5e6f.customDestinations-ms"));
            var lnk = File.ReadAllBytes(Path.Combine(Fixture(Case), "08_Filesystem", "z-top.lnk"));
            var entry = one.Skip(12).Take(16).ToArray();
            var body = one.Take(one.Length - 4);
            if (!clsidPrefixed) body = one.Take(12).Concat(one.Skip(28).Take(one.Length - 32));
            var two = body.Concat(clsidPrefixed ? entry : new byte[0]).Concat(lnk).Concat(one.Skip(one.Length - 4)).ToArray();
            using (var t = new TempDir())
            {
                var path = t.File("two.customDestinations-ms");
                File.WriteAllBytes(path, two);
                var rows = JumplistParser.Parse(path);
                Assert.Equal(new[] { "C:\\Tools\\caf\u00e9.exe", "C:\\Windows\\System32\\cmd.exe" }, rows.Select(r => r.Identity));
            }
        }

        [Fact]
        public void An_empty_DestList_is_reported_as_empty_not_as_a_read_failure()
        {
            using (var t = new TempDir())
            {
                // Rename the fixture's "Empty" stream to DestList and drop the real one: a jumplist with no entries.
                var b = File.ReadAllBytes(Path.Combine(Fixture(Case), "08_Filesystem", "jumplists", "1a2b3c.automaticDestinations-ms"));
                const int dir = 512 + 512, entry = 128;
                Array.Clear(b, dir + entry, entry);
                var name = System.Text.Encoding.Unicode.GetBytes("DestList\0");
                Array.Clear(b, dir + 3 * entry, 64);
                Array.Copy(name, 0, b, dir + 3 * entry, name.Length);
                BitConverter.GetBytes((ushort)name.Length).CopyTo(b, dir + 3 * entry + 0x40);
                var path = t.File("x.automaticDestinations-ms");
                File.WriteAllBytes(path, b);
                var row = JumplistParser.Parse(path).Single(r => r.Format == "DestList");
                Assert.False(row.Supported);
                Assert.StartsWith("DestList stream is empty.", row.Note);
            }
        }

        [Fact]
        public void Hidden_files_and_analysis_output_are_not_parsed()
        {
            using (var t = new TempDir())
            {
                var root = CopyCase(t, Case);
                var pf = Path.Combine(root, "08_Filesystem", "prefetch", "NOTEPAD.EXE-11111111.pf");
                File.SetAttributes(pf, FileAttributes.Hidden);
                var run = ParseRunner.Run(root, Quiet);
                Assert.DoesNotContain(run.Rows, r => r.SourcePath.EndsWith("NOTEPAD.EXE-11111111.pf", StringComparison.Ordinal));
                Assert.DoesNotContain(run.Rows, r => r.SourcePath.StartsWith("analysis", StringComparison.OrdinalIgnoreCase));
            }
        }

        [Fact]
        public void A_junction_inside_the_package_is_not_followed()
        {
            using (var t = new TempDir())
            {
                var root = CopyCase(t, Case);
                var outside = Path.Combine(t.Path, "outside");
                Directory.CreateDirectory(outside);
                File.Copy(Path.Combine(root, "08_Filesystem", "prefetch", "NOTEPAD.EXE-11111111.pf"), Path.Combine(outside, "OUTSIDE.EXE-1.pf"));
                var link = Path.Combine(root, "08_Filesystem", "link");
                var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{outside}\"") { UseShellExecute = false, CreateNoWindow = true });
                p!.WaitForExit(30000);
                if (!Directory.Exists(link)) return;
                var run = ParseRunner.Run(root, Quiet);
                Assert.DoesNotContain(run.Rows, r => r.SourcePath.Contains("OUTSIDE"));
            }
        }

        [Fact]
        public void A_locked_file_becomes_a_row_not_an_aborted_run()
        {
            using (var t = new TempDir())
            {
                var root = CopyCase(t, Case);
                var lnk = Path.Combine(root, "08_Filesystem", "lnk", "cafe.lnk");
                using (new FileStream(lnk, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var run = ParseRunner.Run(root, Quiet);
                    var row = run.Rows.Single(r => r.SourcePath == @"08_Filesystem\lnk\cafe.lnk");
                    Assert.Equal("Unsupported-ReadError", row.Format);
                    Assert.False(row.Supported);
                    Assert.True(run.Rows.Count > 10);
                }
            }
        }

        [Fact]
        public void Zip_package_writes_csv_beside_the_zip()
        {
            using (var t = new TempDir())
            {
                var zip = t.File(Case + ".zip");
                ZipFile.CreateFromDirectory(Fixture(Case), zip, CompressionLevel.Fastest, includeBaseDirectory: true);
                var run = ParseRunner.Run(zip, Quiet);
                Assert.Equal(t.File(Case + "_parse.csv"), run.CsvPath);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden("parse-records.csv")), File.ReadAllBytes(run.CsvPath!));
                Assert.True(File.Exists(t.File(Case + "_Parse.html")));
            }
        }

        [Fact]
        public void Exported_evtx_yields_selected_ids_newest_first()
        {
            using (var t = new TempDir())
            {
                var evtx = t.File("app.evtx");
                var p = Process.Start(new ProcessStartInfo("wevtutil.exe", $"epl Application \"{evtx}\" /ow:true") { UseShellExecute = false, CreateNoWindow = true });
                p!.WaitForExit(60000);
                if (!File.Exists(evtx)) return;
                var rows = EvtxParser.Parse(evtx, 50);
                Assert.All(rows, r => Assert.Equal("EVTX", r.Format));
                var events = rows.Where(r => r.Field("EventId").Length > 0).ToList();
                Assert.All(events, r => Assert.Contains(int.Parse(r.Field("EventId")), EvtxParser.SelectedIds));
                var ids = events.Select(r => long.Parse(r.Field("RecordId"))).ToList();
                Assert.Equal(ids.OrderByDescending(x => x), ids);
            }
        }

        /// <summary>A regf with one ROOT key whose subkey list is built by <paramref name="list"/> (cell offset of ROOT, add-cell).</summary>
        static byte[] HostileHive(Func<int, Func<byte[], int>, int> list)
        {
            var b = new byte[0x40000];
            System.Text.Encoding.ASCII.GetBytes("regf").CopyTo(b, 0);
            System.Text.Encoding.ASCII.GetBytes("hbin").CopyTo(b, 0x1000);
            int next = 0x20;
            int Add(byte[] payload)
            {
                int len = 4 + payload.Length, total = len + (8 - len % 8) % 8, off = next;
                BitConverter.GetBytes(-total).CopyTo(b, 0x1000 + off);
                payload.CopyTo(b, 0x1000 + off + 4);
                next += total;
                return off;
            }
            var nk = new byte[0x4C + 4];
            nk[0] = 0x6E; nk[1] = 0x6B; nk[2] = 0x20;
            BitConverter.GetBytes(20000).CopyTo(nk, 0x14);
            BitConverter.GetBytes(-1).CopyTo(nk, 0x28);
            BitConverter.GetBytes((ushort)4).CopyTo(nk, 0x48);
            System.Text.Encoding.ASCII.GetBytes("ROOT").CopyTo(nk, 0x4C);
            int root = Add(nk);
            int listOff = list(root, Add);
            BitConverter.GetBytes(listOff).CopyTo(b, 0x1000 + root + 4 + 0x1C);
            BitConverter.GetBytes(root).CopyTo(b, 0x24);
            return b;
        }

        [Theory]
        [InlineData("ri-fanout")]
        [InlineData("self-listing")]
        public void Cyclic_hive_lists_finish_quickly(string kind)
        {
            var hive = HostileHive((root, add) =>
            {
                if (kind == "self-listing")
                {
                    // An lf list naming ROOT itself 5000 times.
                    var lf = new byte[4 + 5000 * 8];
                    lf[0] = (byte)'l'; lf[1] = (byte)'f';
                    BitConverter.GetBytes((ushort)5000).CopyTo(lf, 2);
                    for (int i = 0; i < 5000; i++) BitConverter.GetBytes(root).CopyTo(lf, 4 + i * 8);
                    return add(lf);
                }
                // An ri list whose 2000 entries all point back at itself.
                var ri = new byte[4 + 2000 * 4];
                ri[0] = (byte)'r'; ri[1] = (byte)'i';
                BitConverter.GetBytes((ushort)2000).CopyTo(ri, 2);
                int self = add(ri);
                return self;
            });
            if (kind == "ri-fanout")
            {
                // Patch the ri entries to its own offset now that it is known.
                int self = BitConverter.ToInt32(hive, 0x1000 + BitConverter.ToInt32(hive, 0x24) + 4 + 0x1C);
                for (int i = 0; i < 2000; i++) BitConverter.GetBytes(self).CopyTo(hive, 0x1000 + self + 4 + 4 + i * 4);
            }
            using (var t = new TempDir())
            {
                var path = t.File("Amcache.hve");
                File.WriteAllBytes(path, hive);
                var sw = Stopwatch.StartNew();
                var rows = AmcacheParser.Parse(path);
                sw.Stop();
                Assert.Equal("AmcacheHive", rows.Single().Format);
                Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), "Hive walk took " + sw.Elapsed);
            }
        }

        [Fact]
        public void Garbage_behind_valid_headers_never_throws()
        {
            var rng = new Random(1234);
            using (var t = new TempDir())
            {
                var path = t.File("x.bin");
                byte[][] heads =
                {
                    new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, System.Text.Encoding.ASCII.GetBytes("regf"),
                    new byte[] { 0x4C, 0, 0, 0 }, System.Text.Encoding.ASCII.GetBytes("SCCA"),
                };
                for (int i = 0; i < 300; i++)
                {
                    var b = new byte[rng.Next(8, 20000)];
                    rng.NextBytes(b);
                    var h = heads[i % heads.Length];
                    Array.Copy(h, b, Math.Min(h.Length, b.Length));
                    if (i % 8 == 1 && b.Length > 0x1030) { b[0x24] = 0x20; b[0x25] = b[0x26] = b[0x27] = 0; }
                    File.WriteAllBytes(path, b);
                    PrefetchParser.Parse(path);
                    LnkParser.Parse(path);
                    JumplistParser.Parse(path);
                    AmcacheParser.Parse(path);
                }
            }
        }
    }
}
