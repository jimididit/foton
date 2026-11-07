using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Foton.Core;

namespace Foton.Parse
{
    /// <summary>
    /// Offline registry hive (regf) walk over bytes (Get-FotonRegfHiveWalk). Cell offsets are relative to the first
    /// hbin at 0x1000. Fails closed: a bad cell yields null, never a guessed name or time.
    /// </summary>
    public static class Regf
    {
        public sealed class Key
        {
            public int CellOffset { get; internal set; }
            public string Name { get; internal set; } = "";
            public string KeyLastWriteUtc { get; internal set; } = "";
            public int SubkeyCount { get; internal set; }
            public int SubkeyListOffset { get; internal set; }
            public int ValueCount { get; internal set; }
            public int ValueListOffset { get; internal set; }
        }

        /// <summary>"Compressed" key and value names are 8-bit Latin-1 (1.38.x decoded ASCII, turning accents into '?').</summary>
        static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        static byte[]? Cell(byte[] b, long cellOffset)
        {
            if (cellOffset < 0) return null;
            long pos = 0x1000 + cellOffset;
            if (pos + 4 > b.Length) return null;
            long raw = BitConverter.ToInt32(b, (int)pos);
            if (raw == 0) return null;
            long len = Math.Abs(raw);
            if (len < 8 || pos + len > b.Length) return null;
            var payload = new byte[len - 4];
            Array.Copy(b, pos + 4, payload, 0, payload.Length);
            return payload;
        }

        public static Key? Nk(byte[] b, int cellOffset)
        {
            var p = Cell(b, cellOffset);
            if (p == null || p.Length < 0x4C || p[0] != 0x6E || p[1] != 0x6B) return null;
            int flags = BitConverter.ToUInt16(p, 2);
            int nameLen = BitConverter.ToUInt16(p, 0x48);
            if (0x4C + nameLen > p.Length) return null;
            var name = nameLen == 0 ? ""
                : ((flags & 0x0020) != 0 ? Latin1.GetString(p, 0x4C, nameLen) : Encoding.Unicode.GetString(p, 0x4C, nameLen)).Trim('\0');
            return new Key
            {
                CellOffset = cellOffset, Name = name, KeyLastWriteUtc = Bin.FileTimeUtc(p, 4),
                SubkeyCount = BitConverter.ToInt32(p, 0x14), SubkeyListOffset = BitConverter.ToInt32(p, 0x1C),
                ValueCount = BitConverter.ToInt32(p, 0x24), ValueListOffset = BitConverter.ToInt32(p, 0x28),
            };
        }

        static void SubkeyOffsets(byte[] b, int listOffset, int expected, List<int> output, int depth, HashSet<int> visited)
        {
            // Nested ri lists recurse; 1.38.x had no bound, so a cyclic list never returned. Each list is read
            // once and reading stops at the key's subkey count, so a fan-out of self-references stays linear.
            if (listOffset < 0 || depth > 8 || output.Count >= expected || !visited.Add(listOffset)) return;
            var p = Cell(b, listOffset);
            if (p == null || p.Length < 4) return;
            var sig = Encoding.ASCII.GetString(p, 0, 2);
            int count = BitConverter.ToUInt16(p, 2);
            if (string.Equals(sig, "ri", StringComparison.OrdinalIgnoreCase))
            {
                for (int i = 0; i < count && 4 + i * 4 + 4 <= p.Length && output.Count < expected; i++)
                    SubkeyOffsets(b, BitConverter.ToInt32(p, 4 + i * 4), expected, output, depth + 1, visited);
                return;
            }
            int entrySize;
            if (string.Equals(sig, "lf", StringComparison.OrdinalIgnoreCase) || string.Equals(sig, "lh", StringComparison.OrdinalIgnoreCase)) entrySize = 8;
            else if (string.Equals(sig, "li", StringComparison.OrdinalIgnoreCase)) entrySize = 4;
            else return;
            for (int i = 0; i < count && output.Count < expected; i++)
            {
                int at = 4 + i * entrySize;
                if (at + 4 > p.Length) break;
                output.Add(BitConverter.ToInt32(p, at));
            }
        }

        public static List<Key> Subkeys(byte[] b, Key? nk)
        {
            var list = new List<Key>();
            if (nk == null || nk.SubkeyCount <= 0) return list;
            int n = Math.Min(nk.SubkeyCount, 20000);
            var offs = new List<int>();
            if (nk.SubkeyCount > 0) SubkeyOffsets(b, nk.SubkeyListOffset, n, offs, 0, new HashSet<int>());
            for (int i = 0; i < offs.Count && i < n; i++)
            {
                var child = Nk(b, offs[i]);
                if (child != null) list.Add(child);
            }
            return list;
        }

        static KeyValuePair<string, string>? Vk(byte[] b, int vkOffset)
        {
            var p = Cell(b, vkOffset);
            if (p == null || p.Length < 0x14 || p[0] != 0x76 || p[1] != 0x6B) return null;
            int nameLen = BitConverter.ToUInt16(p, 2);
            uint sizeField = BitConverter.ToUInt32(p, 4);
            int dataOff = BitConverter.ToInt32(p, 8);
            int type = BitConverter.ToInt32(p, 0x0C);
            int vflags = BitConverter.ToUInt16(p, 0x10);
            if (0x14 + nameLen > p.Length) return null;
            var name = nameLen == 0 ? "(default)"
                : ((vflags & 0x0001) != 0 ? Latin1.GetString(p, 0x14, nameLen) : Encoding.Unicode.GetString(p, 0x14, nameLen)).Trim('\0');
            int dlen = (int)(sizeField & 0x7FFFFFFF);
            byte[] data;
            if ((sizeField & 0x80000000) != 0)
            {
                data = BitConverter.GetBytes(dataOff);
                if (dlen < data.Length) Array.Resize(ref data, dlen);
            }
            else if (dlen == 0) data = new byte[0];
            else
            {
                var dp = Cell(b, dataOff);
                if (dp == null) return null;
                data = new byte[Math.Min(dlen, dp.Length)];
                Array.Copy(dp, data, data.Length);
            }
            var text = "";
            if (type == 1 || type == 2)
            {
                if (data.Length >= 2) text = Encoding.Unicode.GetString(data).Trim('\0');
                else if (data.Length > 0) text = Encoding.ASCII.GetString(data).Trim('\0');
            }
            else if (type == 4 && data.Length >= 4) text = BitConverter.ToUInt32(data, 0).ToString(CultureInfo.InvariantCulture);
            return new KeyValuePair<string, string>(name, text);
        }

        /// <summary>String and DWORD values by name (case-insensitive; a later duplicate wins). Empty values are omitted.</summary>
        public static Dictionary<string, string> Values(byte[] b, Key? nk)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (nk == null || nk.ValueCount <= 0) return map;
            int n = Math.Min(nk.ValueCount, 500);
            var lp = Cell(b, nk.ValueListOffset);
            if (lp == null) return map;
            for (int i = 0; i < n && i * 4 + 4 <= lp.Length; i++)
            {
                var vk = Vk(b, BitConverter.ToInt32(lp, i * 4));
                if (vk != null && vk.Value.Key.Length > 0 && vk.Value.Value.Length > 0) map[vk.Value.Key] = vk.Value.Value;
            }
            return map;
        }

        public static Key? Root(byte[] b)
        {
            if (b.Length < 0x1020 || !string.Equals(Encoding.ASCII.GetString(b, 0, 4), "regf", StringComparison.OrdinalIgnoreCase)) return null;
            return Nk(b, BitConverter.ToInt32(b, 0x24));
        }

        /// <summary>Breadth-first search for a key name (case-insensitive) up to maxDepth below start.</summary>
        public static Key? Find(byte[] b, Key? start, string name, int maxDepth = 4)
        {
            if (start == null || name.Length == 0) return null;
            // Each key cell is queued once, so a key that lists itself (or a cycle) cannot grow the queue, and the
            // total number of child keys read is budgeted so a hostile hive cannot force millions of reads.
            var queued = new HashSet<int> { start.CellOffset };
            var queue = new Queue<KeyValuePair<Key, int>>();
            queue.Enqueue(new KeyValuePair<Key, int>(start, 0));
            long budget = 500000;
            for (int seen = 0; queue.Count > 0 && seen < 8000 && budget > 0; seen++)
            {
                var item = queue.Dequeue();
                if (item.Key.Name.Length > 0 && string.Equals(item.Key.Name.ToLowerInvariant(), name.ToLowerInvariant(), StringComparison.Ordinal)) return item.Key;
                if (item.Value >= maxDepth) continue;
                var children = Subkeys(b, item.Key);
                budget -= Math.Max(1, children.Count);
                foreach (var ch in children)
                    if (queued.Add(ch.CellOffset)) queue.Enqueue(new KeyValuePair<Key, int>(ch, item.Value + 1));
            }
            return null;
        }
    }

    /// <summary>
    /// Amcache.hve copied off the host (ConvertFrom-FotonAmcache). Win10+ InventoryApplicationFile named values only.
    /// KeyLastWriteUtc is the key last-write, not proof of execution; LinkDate stays the stored string.
    /// Legacy Root\File numeric value IDs are recorded as unsupported, not mapped.
    /// </summary>
    public static class AmcacheParser
    {
        static readonly string[] FieldNames = { "FileId", "Name", "Publisher", "Version", "Size", "LinkDateRaw", "KeyLastWriteUtc", "LowerCaseLongPath", "Path" };

        public static List<ParseRecord> Parse(string path, int maxEntries = 8000)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) throw new FileNotFoundException("Amcache hive not found: " + path, path);
            var bytes = File.ReadAllBytes(full);
            var sha = Hashing.Sha256Hex(bytes);
            ParseRecord Row(string format, bool supported, string identity, string note, Dictionary<string, string>? fields = null)
            {
                var r = ParseRecord.For(full, bytes.Length, sha);
                r.Format = format;
                r.Supported = supported;
                r.Identity = identity;
                r.Note = note;
                foreach (var f in FieldNames) r.Fields[f] = fields != null && fields.TryGetValue(f, out var v) ? v : "";
                return r;
            }
            List<ParseRecord> One(ParseRecord r) => new List<ParseRecord> { r };

            if (bytes.Length < 0x1000)
                return One(Row("Unsupported-TooSmall", false, "", "Shorter than a registry hive header. Paths and times were not guessed."));
            if (!string.Equals(Encoding.ASCII.GetString(bytes, 0, 4), "regf", StringComparison.OrdinalIgnoreCase))
                return One(Row("Unsupported-NotHive", false, "", "Header is not regf. Wrong Amcache fields would be worse than this record."));
            var root = Regf.Root(bytes);
            if (root == null)
                return One(Row("Unsupported-HiveWalk", false, "", "regf header present but the root nk was not read. Use a hive tool; times were not guessed."));

            var inv = Regf.Find(bytes, root, "InventoryApplicationFile", 4);
            if (inv == null)
            {
                if (Regf.Find(bytes, root, "File", 3) != null)
                    return One(Row("Amcache-LegacyFile", false, "", "Amcache Root\\File (Win7/8-style) numeric value IDs are not mapped here. Use an Amcache/hive tool. FILETIME fields were not guessed."));
                return One(Row("AmcacheHive", false, "", "regf hive has no InventoryApplicationFile key. Absence of parsed rows is not evidence the host never executed software. Use a hive tool if this is a non-Amcache hive."));
            }

            const string noteOk = "InventoryApplicationFile named values. KeyLastWriteUtc is the registry key last-write, not proof of execution. LinkDateRaw is the stored string (often PE compile time), not converted to UTC.";
            var children = Regf.Subkeys(bytes, inv);
            if (children.Count == 0)
                return One(Row("AmcacheHive", true, "", "InventoryApplicationFile is present but has no file subkeys. That is an empty key, not proof of a clean host.",
                    new Dictionary<string, string> { ["KeyLastWriteUtc"] = inv.KeyLastWriteUtc }));

            var output = new List<ParseRecord>();
            foreach (var ch in children)
            {
                if (output.Count >= maxEntries) break;
                var vals = Regf.Values(bytes, ch);
                string V(string n) => vals.TryGetValue(n, out var v) ? v : "";
                var p = V("LowerCaseLongPath");
                var id = p.Length > 0 ? p : V("Name").Length > 0 ? V("Name") : V("FileId").Length > 0 ? V("FileId") : ch.Name;
                output.Add(Row("AmcacheFile", true, id, noteOk, new Dictionary<string, string>
                {
                    ["FileId"] = V("FileId"), ["Name"] = V("Name"), ["Publisher"] = V("Publisher"), ["Version"] = V("Version"),
                    ["Size"] = V("Size"), ["LinkDateRaw"] = V("LinkDate"), ["KeyLastWriteUtc"] = ch.KeyLastWriteUtc,
                    ["LowerCaseLongPath"] = p, ["Path"] = p,
                }));
            }
            return output;
        }
    }
}
