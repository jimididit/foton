using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;

namespace Foton.Baseline.Compare
{
    /// <summary>One field-level change (a baseline_diff.csv row).</summary>
    public sealed class BaselineChange
    {
        public string RecordType { get; set; } = "";
        public string Identity { get; set; } = "";
        public string ChangeType { get; set; } = "";
        public string Field { get; set; } = "";
        public string OldValue { get; set; } = "";
        public string NewValue { get; set; } = "";
    }

    public sealed class CompareResult
    {
        /// <summary>Temporal (same host, two times) or Fleet (host vs golden / role image).</summary>
        public string Mode { get; internal set; } = "";
        public List<BaselineChange> Changes { get; } = new List<BaselineChange>();
        public List<Finding> Findings { get; } = new List<Finding>();
        public BaselineHeader ReferenceHeader { get; internal set; } = new BaselineHeader();
        public BaselineHeader DifferenceHeader { get; internal set; } = new BaselineHeader();
        /// <summary>Set when two different but compatible schemas were compared.</summary>
        public string? SchemaNote { get; internal set; }
        /// <summary>False when a baseline's records no longer match its own PayloadSha256 (edited after capture).</summary>
        public bool ReferencePayloadIntact { get; internal set; }
        public bool DifferencePayloadIntact { get; internal set; }
        public string? DiffCsvPath { get; internal set; }
    }

    /// <summary>
    /// Field-level diff of two baselines (Compare-FotonBaseline): Added / Removed by identity key, Modified on
    /// compared fields only. Changes are Tier 1 facts; findings state change between two observations, never
    /// when, who, or that the host is compromised.
    /// </summary>
    public static class BaselineComparer
    {
        // Sort-Object order for type and identity lists (culture-aware, case-insensitive).
        static readonly StringComparer Order = StringComparer.InvariantCultureIgnoreCase;

        public static CompareResult Compare(BaselineDocument reference, BaselineDocument difference, string differenceFileName)
        {
            var rv = reference.Header.BaselineSchemaVersion;
            var dv = difference.Header.BaselineSchemaVersion;
            if (!BaselineSchema.CanCompare(rv, dv))
                throw new InvalidDataException($"Baseline schema mismatch: reference {rv} vs difference {dv}. Refuse to diff.");

            var result = new CompareResult
            {
                Mode = string.Equals(reference.Header.Hostname, difference.Header.Hostname, StringComparison.OrdinalIgnoreCase) ? "Temporal" : "Fleet",
                ReferenceHeader = reference.Header,
                DifferenceHeader = difference.Header,
                SchemaNote = BaselineSchema.CrossVersionNote(rv, dv),
                ReferencePayloadIntact = reference.PayloadMatches(),
                DifferencePayloadIntact = difference.PayloadMatches(),
            };

            // Identity and compared fields come from the reference baseline's provider contracts; a type only
            // the difference baseline knows uses its contract (1.38.x fell back to "Name", which collapses
            // every record onto one empty identity when the type has no Name field).
            var meta = new Dictionary<string, ProviderMeta>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in difference.Providers) meta[p.RecordType] = p;
            foreach (var p in reference.Providers) meta[p.RecordType] = p;

            var types = reference.Records.Keys.ToList();
            foreach (var t in difference.Records.Keys)
                if (!types.Contains(t, StringComparer.OrdinalIgnoreCase)) types.Add(t);

            foreach (var type in types.OrderBy(t => t, Order))
            {
                var m = meta.TryGetValue(type, out var found) ? found : new ProviderMeta { IdentityFields = new[] { "Name" } };
                var notComparable = BaselineSchema.FieldsNotComparable(rv, dv, type);
                var refMap = Keyed(reference, type, m.IdentityFields);
                var difMap = Keyed(difference, type, m.IdentityFields);

                foreach (var key in difMap.Keys.OrderBy(k => difMap[k].Identity, Order))
                {
                    var b = difMap[key];
                    if (!refMap.TryGetValue(key, out var a))
                    {
                        result.Changes.Add(new BaselineChange { RecordType = type, Identity = b.Identity, ChangeType = "Added" });
                        continue;
                    }
                    foreach (var f in m.ComparedFields.Where(f => !notComparable.Contains(f)))
                    {
                        var ov = Field(a.Record, f);
                        var nv = Field(b.Record, f);
                        if (!string.Equals(ov, nv, StringComparison.Ordinal))
                            result.Changes.Add(new BaselineChange { RecordType = type, Identity = b.Identity, ChangeType = "Modified", Field = f, OldValue = ov, NewValue = nv });
                    }
                }
                foreach (var key in refMap.Keys.OrderBy(k => refMap[k].Identity, Order))
                    if (!difMap.ContainsKey(key))
                        result.Changes.Add(new BaselineChange { RecordType = type, Identity = refMap[key].Identity, ChangeType = "Removed" });
            }

            foreach (var c in result.Changes)
                result.Findings.Add(FindingFor(c, result.Mode, reference, difference, differenceFileName));
            return result;
        }

        sealed class KeyedRecord { public string Identity = ""; public Dictionary<string, object?> Record = null!; }

        /// <summary>
        /// Records by identity. Identities compare case-insensitively and a repeated identity keeps the last
        /// record, as a PowerShell hashtable did. The map key length-prefixes each field, so values that
        /// contain "|" cannot collide ("a|b"+"c" vs "a"+"b|c", which 1.38.x merged); the displayed and
        /// written identity is still the 1.38.x "|"-joined form that severity rules and Analyze match on.
        /// </summary>
        static Dictionary<string, KeyedRecord> Keyed(BaselineDocument doc, string type, string[] identityFields)
        {
            var map = new Dictionary<string, KeyedRecord>(StringComparer.OrdinalIgnoreCase);
            if (!doc.Records.TryGetValue(type, out var rows)) return map;
            foreach (var r in rows)
            {
                var parts = identityFields.Select(f => Field(r, f)).ToArray();
                var key = string.Concat(parts.Select(p => p.Length + ":" + p + ";"));
                // Hashtable semantics: the first spelling of a key stays, the last record wins.
                if (map.TryGetValue(key, out var existing)) existing.Record = r;
                else map[key] = new KeyedRecord { Identity = string.Join("|", parts), Record = r };
            }
            return map;
        }

        static string Field(Dictionary<string, object?> record, string field)
        {
            foreach (var kv in record)
                if (string.Equals(kv.Key, field, StringComparison.OrdinalIgnoreCase)) return BaselineDocument.PsString(kv.Value);
            return "";
        }

        static Finding FindingFor(BaselineChange c, string mode, BaselineDocument reference, BaselineDocument difference, string differenceFileName)
        {
            var obs = c.ChangeType == "Modified"
                ? $"Identity '{c.Identity}' field {c.Field}: '{c.OldValue}' -> '{c.NewValue}'."
                : $"Identity '{c.Identity}'.";
            var why = $"{mode} mode ({reference.Header.CapturedUtc} vs {difference.Header.CapturedUtc}). A baseline diff records change between two snapshots. It does not establish when the change occurred, who made it, or that the host is compromised.";
            var fp = FalsePositives(c.RecordType, reference, difference);
            why += fp.Length > 0 ? $" Common benign sources for {c.RecordType}: {fp}" : " Software version bumps and GPO are common benign sources.";
            var next = mode == "Temporal"
                ? "Confirm against change control for this host. Prefer a provisioning-time day0 stored off-host."
                : "Confirm against the role golden image and expected local variance (hostname, SID, joined domain).";
            return new Finding
            {
                Severity = ChangeSeverity.Of(c),
                Category = "Baseline",
                Title = c.ChangeType + " " + c.RecordType,
                Observation = obs,
                Tier = 1,
                WhyItMatters = why,
                Artifact = differenceFileName,
                NextStep = next,
            };
        }

        /// <summary>The provider's documented benign causes, from the baselines themselves (no live provider code needed).</summary>
        static string FalsePositives(string type, BaselineDocument reference, BaselineDocument difference)
        {
            foreach (var doc in new[] { reference, difference })
                foreach (var p in doc.Providers)
                    if (string.Equals(p.RecordType, type, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(p.FalsePositives))
                        return p.FalsePositives;
            return "";
        }

        /// <summary>
        /// Loads both baselines (JSON or package folder), diffs them, and writes baseline_diff.csv beside the
        /// difference baseline for Analyze. Zero changes write a header-only file, so a stale diff from an
        /// earlier comparison is never left behind (1.38.x kept the old file).
        /// </summary>
        public static CompareResult Run(string referencePath, string differencePath, StatusLog log, bool writeCsv = true)
        {
            var refFile = BaselineDocument.ResolveJsonPath(referencePath);
            var difFile = BaselineDocument.ResolveJsonPath(differencePath);
            var result = Compare(BaselineDocument.Load(refFile), BaselineDocument.Load(difFile), Path.GetFileName(difFile));
            if (writeCsv)
            {
                var csv = Path.Combine(Path.GetDirectoryName(difFile)!, "baseline_diff.csv");
                if (result.Changes.Count > 0) Csv.Write(csv, result.Changes);
                else TextFile.Write(csv, "\"RecordType\",\"Identity\",\"ChangeType\",\"Field\",\"OldValue\",\"NewValue\"");
                result.DiffCsvPath = csv;
            }
            if (result.SchemaNote != null) log.Write(result.SchemaNote, StatusLevel.Warn);
            if (!result.ReferencePayloadIntact) log.Write($"Reference baseline records do not match its PayloadSha256: edited after capture, or a placeholder hash ({Path.GetFileName(refFile)}).", StatusLevel.Warn);
            if (!result.DifferencePayloadIntact) log.Write($"Difference baseline records do not match its PayloadSha256: edited after capture, or a placeholder hash ({Path.GetFileName(difFile)}).", StatusLevel.Warn);
            log.Write($"Baseline diff ({result.Mode}): {result.Changes.Count} change(s), {result.Findings.Count} finding(s)", StatusLevel.Good);
            return result;
        }
    }
}
