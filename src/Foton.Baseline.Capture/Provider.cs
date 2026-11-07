using System;
using System.Collections.Generic;
using System.Linq;
using Foton.Core;
using Foton.Win;

namespace Foton.Baseline.Capture
{
    /// <summary>Per-capture facts and caches shared by providers.</summary>
    public sealed class CaptureContext
    {
        public CaptureContext(bool elevated) { Elevated = elevated; }

        public bool Elevated { get; }

        List<UserHive>? _hives;
        List<UserProfile>? _profiles;

        /// <summary>Loaded user hives (no hive is mounted by a baseline capture).</summary>
        public List<UserHive> Hives => _hives ?? (_hives = HostInfo.HiveRoots(Elevated));

        public List<UserProfile> Profiles => _profiles ?? (_profiles = HostInfo.Profiles(Elevated));

        readonly List<string> _gaps = new List<string>();

        /// <summary>
        /// Runs a best-effort read. A failure yields no rows from that read (1.38.x caught and moved on), but the
        /// reason is kept so coverage shows a partial read instead of a clean zero: absence is not evidence.
        /// </summary>
        public IEnumerable<Dictionary<string, object?>> Safe(Func<IEnumerable<Dictionary<string, object?>>> read)
        {
            try { return read().ToList(); }
            catch (Exception ex)
            {
                var msg = TextFile.OneLine(ex.GetType().Name + ": " + ex.Message).Trim();
                if (!_gaps.Contains(msg)) _gaps.Add(msg);
                return Enumerable.Empty<Dictionary<string, object?>>();
            }
        }

        /// <summary>Read failures recorded since the last call (one provider's worth).</summary>
        internal List<string> TakeGaps()
        {
            var g = new List<string>(_gaps);
            _gaps.Clear();
            return g;
        }
    }

    /// <summary>
    /// One record type: its identity key, the only fields that produce Modified, the benign causes analysts
    /// should rule out, and the live read. Records are ordered field maps so the JSON (and the payload hash)
    /// is the same bytes 1.38.x produced for the same machine state.
    /// </summary>
    public sealed class Provider
    {
        public string RecordType { get; set; } = "";
        public string[] IdentityFields { get; set; } = new string[0];
        public string[] ComparedFields { get; set; } = new string[0];
        public string FalsePositives { get; set; } = "";
        /// <summary>Sort-Object keys applied to the collected rows.</summary>
        public string[] SortKeys { get; set; } = new string[0];
        public Func<CaptureContext, IEnumerable<Dictionary<string, object?>>> Collect { get; set; } = _ => Enumerable.Empty<Dictionary<string, object?>>();

        public ProviderMeta Meta => new ProviderMeta
        {
            RecordType = RecordType, IdentityFields = IdentityFields, ComparedFields = ComparedFields, FalsePositives = FalsePositives,
        };

        /// <summary>
        /// Collects and sorts by the 1.38.x Sort-Object keys (current culture, case-insensitive). Windows PowerShell
        /// 5.1 sorted unstably, so rows that tie on every key (an MSI and its bundle registering the same DisplayName
        /// and Publisher) landed in arbitrary order, and Compare keeps the last duplicate. v2 breaks ties on every
        /// remaining field so identical machine state always gives identical bytes.
        /// </summary>
        public List<Dictionary<string, object?>> Run(CaptureContext ctx)
        {
            var rows = Collect(ctx).ToList();
            if (SortKeys.Length == 0 || rows.Count < 2) return rows;
            return rows.OrderBy(r => r, Comparer<Dictionary<string, object?>>.Create(CompareRows)).ToList();
        }

        int CompareRows(Dictionary<string, object?> a, Dictionary<string, object?> b)
        {
            foreach (var key in SortKeys)
            {
                int c = PsOrder.Compare(Key(a, key), Key(b, key));
                if (c != 0) return c;
            }
            foreach (var key in a.Keys.Union(b.Keys).OrderBy(k => k, StringComparer.Ordinal))
            {
                int c = string.CompareOrdinal(Key(a, key), Key(b, key));
                if (c != 0) return c;
            }
            return 0;
        }

        static string Key(Dictionary<string, object?> r, string key) => r.TryGetValue(key, out var v) ? BaselineDocument.PsString(v) : "";

        static readonly StringComparer PsOrder = StringComparer.CurrentCultureIgnoreCase;
    }

    /// <summary>Row-building helpers with the 1.38.x [string] and "(not set)" conventions.</summary>
    static class R
    {
        /// <summary>A record from alternating field names and values, in that order.</summary>
        public static Dictionary<string, object?> Row(params object?[] nameValue)
        {
            var d = new Dictionary<string, object?>();
            for (int i = 0; i + 1 < nameValue.Length; i += 2) d[(string)nameValue[i]!] = nameValue[i + 1];
            return d;
        }

        /// <summary>PowerShell [string] of a registry or WMI value.</summary>
        public static string S(object? v) => BaselineDocument.PsString(v);

        /// <summary>"(not set)" for null or empty, else the [string] value.</summary>
        public static string NotSet(object? v) => v == null || S(v).Length == 0 ? "(not set)" : S(v);
    }
}
