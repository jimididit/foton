using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace Foton.Core
{
    /// <summary>baseline.json header. Timestamps live here, outside the hashed payload.</summary>
    public sealed class BaselineHeader
    {
        public string BaselineSchemaVersion { get; set; } = "";
        public string ToolVersion { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string CapturedUtc { get; set; } = "";
        public bool Elevated { get; set; }
        public string PayloadSha256 { get; set; } = "";
        public string Note { get; set; } = "";
    }

    /// <summary>A provider's contract as recorded in the baseline: identity key, compared fields, benign causes.</summary>
    public sealed class ProviderMeta
    {
        public string RecordType { get; set; } = "";
        public string[] IdentityFields { get; set; } = new string[0];
        public string[] ComparedFields { get; set; } = new string[0];
        public string FalsePositives { get; set; } = "";
    }

    /// <summary>
    /// A baseline snapshot (1.38.x PowerShell or v2). Records keep their parsed JSON values and order, so
    /// the payload hash can be recomputed exactly: same machine state, same bytes, same hash.
    /// </summary>
    public sealed class BaselineDocument
    {
        public BaselineHeader Header { get; set; } = new BaselineHeader();
        public List<ProviderMeta> Providers { get; set; } = new List<ProviderMeta>();
        /// <summary>
        /// RecordType to records in capture order. Type and field names are case-insensitive, as 1.38.x
        /// property lookup was. Read-only so it cannot be swapped for a case-sensitive map.
        /// </summary>
        public Dictionary<string, List<Dictionary<string, object?>>> Records { get; } =
            new Dictionary<string, List<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The "Records" value exactly as parsed from a file (null for a document built in code).</summary>
        object? _parsedRecords;

        public const string HeaderNote =
            "Header timestamps are not part of the compared payload hash. Diff proves change between observations, not attribution. A baseline taken after an incident is a picture of that state.";

        /// <summary>
        /// SHA-256 of the records serialized compactly by JavaScriptSerializer: the same bytes Windows
        /// PowerShell 5.1 "ConvertTo-Json -Compress" produced, so 1.14.0 hashes stay comparable.
        /// </summary>
        /// <remarks>Always hashes <see cref="Records"/> (what capture writes into the header).</remarks>
        public string ComputePayloadSha256()
        {
            var d = new Dictionary<string, object?>();
            foreach (var kv in Records) d[kv.Key] = kv.Value;
            return HashPayload(d);
        }

        static string HashPayload(object payload)
        {
            var json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 }.Serialize(payload);
            return Hashing.Sha256Hex(Encoding.UTF8.GetBytes(json));
        }

        /// <summary>
        /// Whether the header's PayloadSha256 matches the records. For a loaded baseline the check runs on
        /// the Records value exactly as it was in the file, so it verifies the file's own bytes whatever
        /// shape a type was stored in; false means edited after capture, or a placeholder hash.
        /// </summary>
        public bool PayloadMatches() =>
            string.Equals(_parsedRecords != null ? HashPayload(_parsedRecords) : ComputePayloadSha256(), Header.PayloadSha256, StringComparison.OrdinalIgnoreCase);

        /// <summary>A folder package holds baseline.json; a .json path is used as is.</summary>
        public static string ResolveJsonPath(string path)
        {
            if (Directory.Exists(path))
            {
                var json = Path.Combine(path, "baseline.json");
                if (!File.Exists(json)) throw new FileNotFoundException("No baseline.json in package folder: " + path, json);
                return Path.GetFullPath(json);
            }
            if (!File.Exists(path)) throw new FileNotFoundException("Baseline not found: " + path, path);
            return Path.GetFullPath(path);
        }

        public static BaselineDocument Load(string path)
        {
            var file = ResolveJsonPath(path);
            var root = Json.Parse(File.ReadAllText(file, Encoding.UTF8)) as Dictionary<string, object>
                ?? throw new InvalidDataException("Not a baseline document: " + file);
            var doc = new BaselineDocument();
            if (root.TryGetValue("Header", out var h) && h is Dictionary<string, object> hd)
            {
                doc.Header.BaselineSchemaVersion = Str(hd, "BaselineSchemaVersion");
                doc.Header.ToolVersion = Str(hd, "ToolVersion");
                doc.Header.Hostname = Str(hd, "Hostname");
                doc.Header.CapturedUtc = Str(hd, "CapturedUtc");
                doc.Header.Elevated = hd.TryGetValue("Elevated", out var e) && e is bool b && b;
                doc.Header.PayloadSha256 = Str(hd, "PayloadSha256");
                doc.Header.Note = Str(hd, "Note");
            }
            foreach (var p in Items(root.TryGetValue("Providers", out var ps) ? ps : null).OfType<Dictionary<string, object>>())
                doc.Providers.Add(new ProviderMeta
                {
                    RecordType = Str(p, "RecordType"),
                    IdentityFields = Items(p.TryGetValue("IdentityFields", out var i) ? i : null).Select(x => PsString(x)).ToArray(),
                    ComparedFields = Items(p.TryGetValue("ComparedFields", out var c) ? c : null).Select(x => PsString(x)).ToArray(),
                    FalsePositives = Str(p, "FalsePositives"),
                });
            if (root.TryGetValue("Records", out var r)) doc._parsedRecords = r;
            if (r is Dictionary<string, object> rd)
                foreach (var kv in rd)
                    doc.Records[kv.Key] = Items(kv.Value).OfType<Dictionary<string, object>>()
                        .Select(x =>
                        {
                            var rec = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                            foreach (var f in x) rec[f.Key] = f.Value;
                            return rec;
                        }).ToList();
            return doc;
        }

        /// <summary>A JSON value that may be a list or a single item (PowerShell unrolled one-element arrays).</summary>
        static IEnumerable<object?> Items(object? v) =>
            v == null ? Enumerable.Empty<object?>()
            : v is IDictionary ? new[] { v }
            : v is IEnumerable e && !(v is string) ? e.Cast<object?>()
            : new[] { v };

        static string Str(Dictionary<string, object> d, string key) => d.TryGetValue(key, out var v) ? PsString(v) : "";

        /// <summary>
        /// A value as PowerShell's [string] cast renders it, which is what 1.38.x compared and keyed on:
        /// null is "", booleans True/False, numbers invariant, arrays space-joined.
        /// </summary>
        public static string PsString(object? v)
        {
            switch (v)
            {
                case null: return "";
                case string s: return s;
                case bool b: return b ? "True" : "False";
                case DateTime t: return FotonTime.Format(t);
                case IFormattable f: return f.ToString(null, CultureInfo.InvariantCulture);
                case IDictionary d: return Json.Compact(d);
                case IEnumerable e: return string.Join(" ", e.Cast<object?>().Select(PsString));
                default: return v.ToString() ?? "";
            }
        }

        /// <summary>
        /// baseline.json for a document built at capture time (header hash = ComputePayloadSha256()).
        /// Not a re-save path for loaded files: records are written in normalized list form.
        /// </summary>
        public string ToJson() => Json.Indented(new Dictionary<string, object?>
        {
            ["Header"] = Header,
            ["Providers"] = Providers,
            ["Records"] = Records,
        });
    }

    /// <summary>Which baseline schemas may be diffed against each other.</summary>
    public static class BaselineSchema
    {
        /// <summary>
        /// 1.15.0 changed record values and coverage, not identity keys or compared fields, so a 1.14.0 day0
        /// stays usable: unreported Defender properties become "(not reported)", BitsJob NotifyCmdLine
        /// "(not set)", WinHttpSettings hex, a standard-user capture now reads loaded user hives that
        /// 1.14.0 skipped, and active WDAC policies (CiPolicies\Active) and explorer.exe (Windows directory)
        /// are captured. Those show once as Modified or Added.
        /// </summary>
        static readonly string[][] Compatible = { new[] { "1.14.0", "1.15.0" } };

        public static bool CanCompare(string a, string b) =>
            a == b || Compatible.Any(p => p.Contains(a) && p.Contains(b));

        /// <summary>Explanation to show when two different but compatible schemas are compared; null when equal.</summary>
        public static string? CrossVersionNote(string a, string b) =>
            a == b ? null
            : $"Reference schema {a} and difference schema {b} differ. 1.15.0 records Defender properties the platform no longer reports as \"(not reported)\" (1.14.0 wrote an empty value) and an unset BitsJob NotifyCmdLine as \"(not set)\" (1.14.0 wrote a single space), and writes the WinHttpSettings proxy blob as hex (1.14.0 wrote decimals). A 1.14.0 standard-user capture also skipped every loaded user hive, so per-user UserAutorun, StartupApproved and ProxyConfig rows can show as Added, and 1.15.0 adds active WDAC policies (WdacActiveCip, from CiPolicies\\Active) and the SystemBinary row for explorer.exe, which 1.14.0 looked for in System32. That is a format and coverage change, not a host change.";
    }
}
