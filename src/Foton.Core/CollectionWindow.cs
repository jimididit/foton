using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Foton.Core
{
    /// <summary>
    /// When the collector ran, from 00_Collection\collection.log (every line starts
    /// "yyyy-MM-dd HH:mm:ss UTC"). Analyze uses it to separate events Foton itself caused from events
    /// about the host. Null when no window can be established; callers must read that as "cannot
    /// attribute", never as "nothing to attribute". No end is guessed from a start alone.
    /// </summary>
    public sealed class CollectionWindow
    {
        public DateTime StartUtc { get; }
        public DateTime EndUtc { get; }

        CollectionWindow(DateTime start, DateTime end) { StartUtc = start; EndUtc = end; }

        static readonly Regex Stamp = new Regex(@"^(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC");

        public static CollectionWindow? FromCase(string? caseRoot)
        {
            if (caseRoot == null) return null;
            var log = Path.Combine(caseRoot, CaseTree.CollectionFolder, "collection.log");
            if (!File.Exists(log)) return null;
            DateTime? min = null, max = null;
            try
            {
                foreach (var line in TextFile.ReadLines(log))
                {
                    var m = Stamp.Match(line);
                    if (!m.Success || !FotonTime.TryParse(m.Groups["ts"].Value, out var t)) continue;
                    if (min == null || t < min) min = t;
                    if (max == null || t > max) max = t;
                }
            }
            // Unreadable (locked, access denied, ...) means "cannot attribute", never an exception for the caller.
            catch (Exception) { return null; }
            return min.HasValue && max.HasValue ? new CollectionWindow(min.Value, max.Value) : null;
        }

        /// <summary>
        /// Log stamps have one-second resolution, so the last logged second is covered in full: an event at
        /// 12:03:00.7 is inside a window whose last stamp is 12:03:00 (1.38.x dropped it).
        /// </summary>
        public bool Contains(DateTime utc) => utc >= StartUtc && utc < EndUtc.AddSeconds(1);
    }
}
