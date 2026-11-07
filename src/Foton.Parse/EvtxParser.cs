using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Parse
{
    /// <summary>
    /// Exported .evtx copied into a package (ConvertFrom-FotonEvtx). One row per selected Event ID, newest first,
    /// capped; other IDs are skipped, not dumped. Messages are rendered with this workstation's provider metadata,
    /// as Get-WinEvent did, so a provider not installed here yields an empty message, not a guessed one.
    /// </summary>
    public static class EvtxParser
    {
        /// <summary>Event IDs Collect queries (Get-FotonSelectedEvtxIds).</summary>
        public static readonly IReadOnlyCollection<int> SelectedIds = new SortedSet<int>
        {
            1, 3, 4, 6, 7, 8, 10, 11, 12, 13, 15, 21, 22, 23, 24, 25, 39, 40, 41,
            59, 60, 104, 106, 129, 140, 141, 200, 201, 219, 400, 403, 600, 800,
            1000, 1001, 1002, 1006, 1007, 1008, 1009, 1015, 1074,
            1116, 1117, 1118, 1119, 1148, 1149, 2003, 2004, 2005, 2006, 2033,
            4103, 4104, 4624, 4625, 4634, 4647, 4648, 4656, 4663, 4672,
            4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4719,
            4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729,
            4732, 4733, 4738, 4739, 4740, 4756, 4757, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4781,
            4907, 4912, 5001, 5004, 5007, 5010, 5012, 5140, 5142, 5143, 5144, 5145,
            53504, 5857, 5858, 5859, 5860, 5861, 6005, 6006, 6008, 6013,
            7031, 7034, 7036, 7040, 7045,
        };

        static readonly Regex Space = new Regex(@"\s+");

        public static List<ParseRecord> Parse(string path, int maxEvents = 500)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) throw new FileNotFoundException("EVTX file not found: " + path, path);
            long len = new FileInfo(full).Length;
            var sha = Bin.Sha256(full);
            ParseRecord Row(string format, bool supported, string note)
            {
                var r = ParseRecord.For(full, len, sha);
                r.Format = format;
                r.Supported = supported;
                r.Note = note;
                foreach (var f in new[] { "EventId", "RecordId", "TimeCreatedUtc", "Provider" }) r.Fields[f] = "";
                return r;
            }
            List<ParseRecord> One(ParseRecord r) => new List<ParseRecord> { r };

            if (len < 8) return One(Row("Unsupported-TooSmall", false, "Shorter than an ElfFile header. Do not invent Event IDs."));
            var hdr = new byte[8];
            using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                fs.Read(hdr, 0, 8);
            if (!string.Equals(Encoding.ASCII.GetString(hdr, 0, 7), "ElfFile", StringComparison.OrdinalIgnoreCase))
                return One(Row("Unsupported-NotEvtx", false, "Header is not ElfFile. Wrong Event IDs would be worse than this record."));

            // 1.38.x passed every ID to Get-WinEvent -FilterHashtable; past a couple of dozen IDs that query
            // silently matches nothing. Reading newest-first and filtering here has no such limit.
            var output = new List<ParseRecord>();
            try
            {
                using (var reader = new EventLogReader(new EventLogQuery(full, PathType.FilePath) { ReverseDirection = true }))
                {
                    while (output.Count < maxEvents)
                        using (var e = reader.ReadEvent())
                        {
                            if (e == null) break;
                            if (SelectedIds.Contains(e.Id)) output.Add(Event(full, len, sha, e));
                        }
                }
            }
            catch (Exception ex) when (ex is EventLogException || ex is UnauthorizedAccessException || ex is IOException || ex is PlatformNotSupportedException)
            {
                if (output.Count == 0)
                    return One(Row("Unsupported-EvtxRead", false, "ElfFile header present but Windows could not read the log: " + TextFile.OneLine(ex.Message) + ". Event IDs were not guessed."));
                // Keep what was read; say where reading stopped instead of implying the rest of the log was empty.
                output.Add(Row("Unsupported-EvtxRead", false, $"Reading stopped after {output.Count} selected event(s): " + TextFile.OneLine(ex.Message) + ". Older events in this file were not read."));
                return output;
            }
            if (output.Count == 0)
                return One(Row("EVTX", true, "ElfFile opened. No selected-ID events within the cap. Other Event IDs in this file were not dumped. Absence here is a filter, not an empty log."));
            if (output.Count >= maxEvents)
                output.Add(Row("EVTX", false, $"Stopped at the cap of {maxEvents} selected events (newest first); any older selected events in this file were not read."));
            return output;
        }

        static ParseRecord Event(string full, long len, string sha, EventRecord e)
        {
            var msg = "";
            try { msg = e.FormatDescription() ?? ""; } catch (EventLogException) { } catch (InvalidOperationException) { }
            if (msg.Length > 500) msg = msg.Substring(0, 500) + "...[truncated]";
            msg = Space.Replace(msg, " ");
            var eid = e.Id.ToString(CultureInfo.InvariantCulture);
            var rid = e.RecordId?.ToString(CultureInfo.InvariantCulture) ?? "";
            var r = ParseRecord.For(full, len, sha);
            r.Format = "EVTX";
            r.Supported = true;
            r.Identity = eid + "|" + rid;
            r.Note = msg;
            r.Fields["EventId"] = eid;
            r.Fields["RecordId"] = rid;
            r.Fields["TimeCreatedUtc"] = e.TimeCreated?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "";
            r.Fields["Provider"] = e.ProviderName ?? "";
            return r;
        }
    }
}
