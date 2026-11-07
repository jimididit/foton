using System;
using System.Collections.Generic;
using System.Text;

namespace Foton.Parse
{
    /// <summary>
    /// Named streams from an OLE compound file (CFB), as used by .automaticDestinations-ms
    /// (Get-FotonOleCompoundStreams). Caps stream count and size; returns what was read when a chain is bad.
    /// </summary>
    public static class OleCompound
    {
        public sealed class Stream
        {
            public string Name { get; internal set; } = "";
            public byte[] Data { get; internal set; } = new byte[0];
        }

        sealed class DirEntry { public byte Type; public string Name = ""; public int Start; public uint Size; }

        const uint EndOfChain = 0xFFFFFFFE, FreeSect = 0xFFFFFFFF, FatSect = 0xFFFFFFFD, DifSect = 0xFFFFFFFC;

        public static List<Stream> Streams(byte[]? b, int maxStreams = 64, int maxStreamBytes = 2097152)
        {
            var output = new List<Stream>();
            if (b == null || b.Length < 512) return output;
            if (b[0] != 0xD0 || b[1] != 0xCF || b[2] != 0x11 || b[3] != 0xE0) return output;

            int shift = BitConverter.ToUInt16(b, 0x1E);
            if (shift < 9 || shift > 12) return output;
            int sectorSize = 1 << shift;
            int miniShift = BitConverter.ToUInt16(b, 0x20);
            int miniSize = miniShift >= 4 && miniShift <= 8 ? 1 << miniShift : 64;
            int dirStart = BitConverter.ToInt32(b, 0x30);
            uint miniCutoff = BitConverter.ToUInt32(b, 0x38);
            int miniFatStart = BitConverter.ToInt32(b, 0x3C);
            int difatStart = BitConverter.ToInt32(b, 0x44);
            int difatCount = BitConverter.ToInt32(b, 0x48);

            var fatSectors = new List<int>();
            for (int i = 0; i < 109; i++)
            {
                int id = BitConverter.ToInt32(b, 0x4C + 4 * i);
                if (id >= 0) fatSectors.Add(id);
            }
            int dif = difatStart, guard = 0, perDif = sectorSize / 4 - 1;
            while (dif >= 0 && guard < difatCount && guard < 32)
            {
                var sec = Sector(b, sectorSize, dif);
                if (sec == null) break;
                for (int j = 0; j < perDif; j++)
                {
                    int id = BitConverter.ToInt32(sec, 4 * j);
                    if (id >= 0) fatSectors.Add(id);
                }
                dif = BitConverter.ToInt32(sec, sectorSize - 4);
                guard++;
            }
            var fat = new List<uint>();
            foreach (var fs in fatSectors)
            {
                var sec = Sector(b, sectorSize, fs);
                if (sec == null) continue;
                for (int k = 0; k < sectorSize / 4; k++) fat.Add(BitConverter.ToUInt32(sec, 4 * k));
            }
            if (fat.Count < 1) return output;

            var dir = FatChain(b, sectorSize, fat, dirStart, 1024 * 1024);
            if (dir == null || dir.Length < 128) return output;
            var entries = new List<DirEntry>();
            for (int off = 0; off + 128 <= dir.Length; off += 128)
            {
                int nameLen = BitConverter.ToUInt16(dir, off + 0x40);
                var name = "";
                if (nameLen >= 2)
                {
                    int nb = Math.Min(nameLen - 2, 64);
                    if (nb > 0) name = Encoding.Unicode.GetString(dir, off, nb).Trim('\0');
                }
                entries.Add(new DirEntry { Type = dir[off + 0x42], Name = name, Start = BitConverter.ToInt32(dir, off + 0x74), Size = BitConverter.ToUInt32(dir, off + 0x78) });
            }

            byte[]? miniData = null;
            List<uint>? miniFat = null;
            foreach (var root in entries)
            {
                if (root.Type != 5) continue;
                if (root.Size > 0 && root.Start >= 0 && root.Size <= int.MaxValue)
                {
                    miniData = FatChain(b, sectorSize, fat, root.Start, (int)root.Size);
                    if (miniFatStart >= 0)
                    {
                        var mf = FatChain(b, sectorSize, fat, miniFatStart, 256 * 1024);
                        if (mf != null)
                        {
                            miniFat = new List<uint>();
                            for (int m = 0; m + 4 <= mf.Length; m += 4) miniFat.Add(BitConverter.ToUInt32(mf, m));
                        }
                    }
                }
                break;
            }

            int taken = 0;
            foreach (var e in entries)
            {
                if (e.Type != 2 || e.Name.Length == 0) continue;
                if (taken >= maxStreams) break;
                if (e.Size == 0)
                {
                    // A present but empty stream (a jumplist with no DestList entries) is a fact, not a read failure.
                    output.Add(new Stream { Name = e.Name });
                    taken++;
                    continue;
                }
                int want = (int)Math.Min(e.Size, (uint)maxStreamBytes);
                byte[]? data = e.Size < miniCutoff && miniData != null && miniFat != null
                    ? MiniChain(miniData, miniFat, miniSize, e.Start, want)
                    : FatChain(b, sectorSize, fat, e.Start, want);
                if (data == null) continue;
                output.Add(new Stream { Name = e.Name, Data = data });
                taken++;
            }
            return output;
        }

        static byte[]? Sector(byte[] b, int sectorSize, long index)
        {
            if (index < 0) return null;
            long off = 512 + index * sectorSize;
            if (off + sectorSize > b.Length) return null;
            var buf = new byte[sectorSize];
            Array.Copy(b, off, buf, 0, sectorSize);
            return buf;
        }

        static bool Special(uint s) => s == EndOfChain || s == FreeSect || s == FatSect || s == DifSect;

        static byte[]? FatChain(byte[] b, int sectorSize, List<uint> fat, int start, int maxBytes)
        {
            if (start < 0) return null;
            var chunks = new List<byte>();
            uint s = (uint)start;
            for (int guard = 0; guard < 4096 && chunks.Count < maxBytes; guard++)
            {
                if (Special(s) || s > int.MaxValue) break;
                var sec = Sector(b, sectorSize, s);
                if (sec == null) break;
                int take = Math.Min(sec.Length, maxBytes - chunks.Count);
                for (int i = 0; i < take; i++) chunks.Add(sec[i]);
                if (s >= fat.Count) break;
                s = fat[(int)s];
            }
            return chunks.Count == 0 ? null : chunks.ToArray();
        }

        static byte[]? MiniChain(byte[] miniData, List<uint> miniFat, int miniSize, int start, int size)
        {
            // 1.38.x cast a negative start (an empty stream's ENDOFCHAIN) to uint32 and threw, dropping every
            // stream after it; an empty or broken mini chain now ends only that stream.
            if (start < 0) return null;
            var chunks = new List<byte>();
            uint s = (uint)start;
            for (int guard = 0; guard < 4096 && chunks.Count < size; guard++)
            {
                if (Special(s) || s > int.MaxValue) break;
                long off = (long)s * miniSize;
                if (off + miniSize > miniData.Length) break;
                int take = Math.Min(miniSize, size - chunks.Count);
                for (int i = 0; i < take; i++) chunks.Add(miniData[off + i]);
                if (s >= miniFat.Count) break;
                s = miniFat[(int)s];
            }
            return chunks.Count == 0 ? null : chunks.ToArray();
        }
    }
}
