using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using static Foton.Analyze.Ps;

namespace Foton.Analyze
{
    public sealed class Ioc
    {
        public string Kind { get; set; } = "text";
        public string Value { get; set; } = "";
    }

    public sealed class IocHit
    {
        public string IocKind { get; set; } = "";
        public string IocValue { get; set; } = "";
        public string Artifact { get; set; } = "";
        public string Property { get; set; } = "";
        public string Sample { get; set; } = "";
    }

    /// <summary>
    /// Matches a simple indicator list against an already-collected package (Invoke-FotonIocMatch). Offline: no
    /// lookups. sha256: exact on SHA256/Hash columns; path: substring on Path/Command/File columns; text: substring
    /// anywhere. A hit is a Tier 2 lead (lists match admin tools as readily as attacker tools), never a conclusion.
    /// </summary>
    public static class IocMatcher
    {
        /// <summary>Text (one per line, "#" comments, sha256:/path:/text: prefixes), .csv (Kind,Value), or .json ([{Kind,Value}]).</summary>
        public static List<Ioc> Load(string path)
        {
            var iocs = new List<Ioc>();
            Ioc Make(string? kind, string? value)
            {
                var k = (kind ?? "").ToLowerInvariant();
                if (k.Length == 0) k = "text";
                var v = value ?? "";
                return new Ioc { Kind = k, Value = k == "sha256" ? v.ToUpperInvariant() : v };
            }
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext == ".csv")
                iocs.AddRange(Csv.Read(path).Select(r => Make(Field(r, "Kind"), Field(r, "Value"))));
            else if (ext == ".json")
                iocs.AddRange(Items(PackageData.FromJson(Json.Parse(File.ReadAllText(path, Encoding.UTF8)))).Select(r => Make(Str(Get(r, "Kind")), Str(Get(r, "Value")))));
            else
                foreach (var line in TextFile.ReadLines(path))
                {
                    if (Regex.IsMatch(line, @"^\s*$") || Regex.IsMatch(line, @"^\s*#")) continue;
                    var t = line.Trim();
                    if (Like(t, "sha256:*")) iocs.Add(new Ioc { Kind = "sha256", Value = t.Substring(7).Trim().ToUpperInvariant() });
                    else if (Like(t, "path:*")) iocs.Add(new Ioc { Kind = "path", Value = t.Substring(5).Trim() });
                    else if (Like(t, "text:*")) iocs.Add(new Ioc { Kind = "text", Value = t.Substring(5).Trim() });
                    else iocs.Add(new Ioc { Kind = "text", Value = t });
                }
            // An empty value ("path:") is a substring of everything; 1.38.x matched every field with it.
            return iocs.Where(i => i.Value.Trim().Length > 0).ToList();
        }

        static string? Field(Dictionary<string, string?> row, string name)
        {
            foreach (var kv in row) if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            return null;
        }

        static readonly Regex HashColumn = new Regex("SHA256|Hash", RegexOptions.IgnoreCase);
        static readonly Regex PathColumn = new Regex("Path|Command|File|FullName", RegexOptions.IgnoreCase);

        /// <summary>
        /// Every artifact row and column against every indicator. Artifacts are visited in name order (1.38.x used
        /// hashtable order). Text-file artifacts are matched line by line as column "Line": 1.38.x saw only a string's
        /// Length property, so hosts and WMI subscription text never matched.
        /// </summary>
        public static List<IocHit> Match(PackageData data, IEnumerable<string> artifactNames, IReadOnlyList<Ioc> iocs)
        {
            var hits = new List<IocHit>();
            foreach (var key in artifactNames.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
                foreach (var row in Items(data[key]))
                {
                    if (row == null) continue;
                    var props = row is PsRow r ? r.Names.Select(n => new KeyValuePair<string, object?>(n, r[n])).ToList()
                        : new List<KeyValuePair<string, object?>> { new KeyValuePair<string, object?>("Line", row) };
                    foreach (var ioc in iocs)
                        foreach (var prop in props)
                        {
                            var pv = Str(prop.Value);
                            if (string.IsNullOrWhiteSpace(pv)) continue;
                            bool matched =
                                (ioc.Kind == "sha256" && HashColumn.IsMatch(prop.Key) && pv.ToUpperInvariant() == ioc.Value.ToUpperInvariant())
                                || (ioc.Kind == "path" && PathColumn.IsMatch(prop.Key) && pv.ToLowerInvariant().Contains(ioc.Value.ToLowerInvariant()))
                                || (ioc.Kind == "text" && pv.ToLowerInvariant().Contains(ioc.Value.ToLowerInvariant()));
                            if (matched) hits.Add(new IocHit { IocKind = ioc.Kind, IocValue = ioc.Value, Artifact = key, Property = prop.Key, Sample = pv });
                        }
                }
            return hits;
        }

        /// <summary>One Tier 2 finding per hit, citing the artifact and column.</summary>
        public static void AddFindings(AnalysisContext c, IEnumerable<IocHit> hits)
        {
            foreach (var h in hits)
                c.Add("Medium", "Ioc", 2, F("IOC match ({0})", h.IocKind),
                    F("Indicator matched {0}.{1}: {2}", h.Artifact, h.Property, h.Sample),
                    "IOC lists match strings and hashes, including legitimate software and reused lab indicators. A match is a lead to verify against the cited artifact, not a conclusion.",
                    h.Artifact,
                    "Confirm the artifact context (signer, path, time) before treating this as related to an incident.");
        }
    }
}
