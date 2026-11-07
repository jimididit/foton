using System;
using System.Collections.Generic;
using System.Management;
using System.Text.RegularExpressions;

namespace Foton.Win
{
    /// <summary>WMI reads with 1.38.x semantics for absent data.</summary>
    public static class Wmi
    {
        /// <summary>Marker for a property the class no longer defines (Defender drops properties between platform builds).</summary>
        public static readonly object NotReported = new object();

        public static List<ManagementBaseObject> Query(string ns, string wql)
        {
            var list = new List<ManagementBaseObject>();
            using (var s = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql)))
            using (var results = s.Get())
                foreach (ManagementBaseObject mo in results) list.Add(mo);
            return list;
        }

        /// <summary>The property value, null when it is null, or <see cref="NotReported"/> when the class lacks it.</summary>
        public static object? Prop(ManagementBaseObject mo, string name)
        {
            try { return mo[name]; }
            catch (ManagementException) { return NotReported; }
        }

        /// <summary>The property as PowerShell [string] rendered it ("" for null or absent).</summary>
        public static string Str(ManagementBaseObject mo, string name)
        {
            var v = Prop(mo, name);
            return v == NotReported ? "" : Foton.Core.BaselineDocument.PsString(v);
        }

        static readonly Regex KeyPair = new Regex("(?<k>[^=,]+)=(?:\"(?<q>(?:[^\"\\\\]|\\\\.)*)\"|(?<n>[^,]*))");

        /// <summary>
        /// A WMI reference (\\HOST\ROOT\ns:Class.Key="v") rendered the way a CimInstance printed in 1.38.x:
        /// Class (Key = "v"). Binding rows were keyed on that text, so it is kept for parity.
        /// </summary>
        public static string CimRefString(string? reference)
        {
            if (string.IsNullOrEmpty(reference)) return "";
            var path = reference!;
            int colon = path.IndexOf(':');
            var rel = colon >= 0 ? path.Substring(colon + 1) : path;
            int dot = rel.IndexOf('.');
            if (dot < 0) return rel;
            var cls = rel.Substring(0, dot);
            var parts = new List<string>();
            foreach (Match m in KeyPair.Matches(rel.Substring(dot + 1)))
                parts.Add(m.Groups["q"].Success
                    ? m.Groups["k"].Value + " = \"" + m.Groups["q"].Value.Replace("\\\"", "\"").Replace("\\\\", "\\") + "\""
                    : m.Groups["k"].Value + " = " + m.Groups["n"].Value);
            return cls + " (" + string.Join(", ", parts) + ")";
        }
    }
}
