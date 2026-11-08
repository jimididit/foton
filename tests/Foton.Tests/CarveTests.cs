using System;
using System.IO;
using System.Linq;
using Foton.Carve;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    public class CarveTests
    {
        /// <summary>An MZ header at 'at' whose e_lfanew points 0x80 bytes on, where "PE\0\0" is written when pe is true.</summary>
        static void Mz(byte[] blob, int at, bool pe)
        {
            blob[at] = 0x4D;
            blob[at + 1] = 0x5A;
            BitConverter.GetBytes(0x80).CopyTo(blob, at + 0x3C);
            if (pe) { blob[at + 0x80] = 0x50; blob[at + 0x81] = 0x45; }
        }

        [Fact]
        public void Labels_PE_only_when_e_lfanew_points_at_the_PE_signature()
        {
            using (var t = new TempDir())
            {
                var blob = new byte[4096];
                Mz(blob, 100, pe: true);
                Mz(blob, 1000, pe: false);
                File.WriteAllBytes(t.File("blob.bin"), blob);
                var run = Carver.Scan(t.File("blob.bin"));
                Assert.Equal(4096, run.BytesScanned);
                Assert.Equal(new long[] { 100, 1000 }, run.Hits.Select(h => h.Offset));
                Assert.Equal(new[] { "PE", "MZ" }, run.Hits.Select(h => h.Kind));
                var window = new byte[64];
                Array.Copy(blob, 100, window, 0, 64);
                Assert.Equal(Hashing.Sha256Hex(window), run.Hits[0].WindowSha256);
                Assert.Equal(Carver.HitNote, run.Hits[0].Note);
            }
        }

        [Fact]
        public void Caps_bytes_and_hits_and_survives_a_hostile_e_lfanew()
        {
            using (var t = new TempDir())
            {
                var blob = new byte[300];
                Mz(blob, 0, pe: false);
                BitConverter.GetBytes(int.MaxValue).CopyTo(blob, 0x3C);
                Mz(blob, 100, pe: false);
                BitConverter.GetBytes(-50).CopyTo(blob, 100 + 0x3C);
                blob[298] = 0x4D; blob[299] = 0x5A;
                File.WriteAllBytes(t.File("blob.bin"), blob);

                var all = Carver.Scan(t.File("blob.bin"));
                Assert.Equal(new long[] { 0, 100, 298 }, all.Hits.Select(h => h.Offset));
                Assert.All(all.Hits, h => Assert.Equal("MZ", h.Kind));
                // A hit at the end hashes only the bytes that remain.
                Assert.Equal(Hashing.Sha256Hex(new byte[] { 0x4D, 0x5A }), all.Hits[2].WindowSha256);

                Assert.Single(Carver.Scan(t.File("blob.bin"), maxHits: 1).Hits);
                Assert.Equal(new long[] { 0 }, Carver.Scan(t.File("blob.bin"), maxBytes: 99).Hits.Select(h => h.Offset));
                Assert.Throws<FileNotFoundException>(() => Carver.Scan(t.File("missing.bin")));
            }
        }
    }
}
