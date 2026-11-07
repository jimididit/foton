using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace Foton.Core
{
    /// <summary>
    /// JSON artifacts. Serialization goes through JavaScriptSerializer (the engine Windows PowerShell 5.1
    /// ConvertTo-Json used) after converting objects to ordered maps, so property order is declaration
    /// order, times are UTC strings, and output is the same on every run.
    /// </summary>
    public static class Json
    {
        static JavaScriptSerializer NewSerializer() => new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };

        /// <summary>Compact form (no whitespace), as ConvertTo-Json -Compress.</summary>
        public static string Compact(object? value) => NewSerializer().Serialize(ToNode(value, 0));

        /// <summary>Indented two spaces for artifacts people open by hand.</summary>
        public static string Indented(object? value) => Indent(Compact(value));

        /// <summary>Parsed graph: Dictionary&lt;string, object&gt; (order kept), object[], string, bool, number, or null.</summary>
        public static object? Parse(string json) => NewSerializer().DeserializeObject(json);

        const int MaxDepth = 64;

        /// <summary>Objects become ordered dictionaries (declaration order); lists, primitives, and times normalized.</summary>
        public static object? ToNode(object? v, int depth)
        {
            if (v == null) return null;
            if (depth > MaxDepth) return Csv.FormatValue(v);
            switch (v)
            {
                case string _:
                case bool _:
                    return v;
                case DateTime t: return FotonTime.Format(t);
                case DateTimeOffset o: return FotonTime.Format(o.UtcDateTime);
                case Enum e: return e.ToString();
                case Guid g: return g.ToString();
            }
            var type = v.GetType();
            if (type.IsPrimitive || v is decimal) return v;
            if (v is IDictionary dict)
            {
                var d = new Dictionary<string, object?>();
                foreach (DictionaryEntry kv in dict)
                    d[Convert.ToString(kv.Key, CultureInfo.InvariantCulture) ?? ""] = ToNode(kv.Value, depth + 1);
                return d;
            }
            if (v is IEnumerable list) return list.Cast<object?>().Select(x => ToNode(x, depth + 1)).ToList();
            var obj = new Dictionary<string, object?>();
            foreach (var p in Csv.Properties(type))
                obj[p.Name] = ToNode(p.GetValue(v), depth + 1);
            return obj;
        }

        /// <summary>Re-indents compact JSON; string contents are left untouched.</summary>
        static string Indent(string compact)
        {
            var sb = new StringBuilder(compact.Length * 2);
            int level = 0;
            bool inString = false;
            for (int i = 0; i < compact.Length; i++)
            {
                char c = compact[i];
                if (inString)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < compact.Length) { sb.Append(compact[++i]); continue; }
                    if (c == '"') inString = false;
                    continue;
                }
                switch (c)
                {
                    case '"': inString = true; sb.Append(c); break;
                    case '{':
                    case '[':
                        // Keep empty containers on one line: {} and [].
                        char close = c == '{' ? '}' : ']';
                        if (i + 1 < compact.Length && compact[i + 1] == close) { sb.Append(c).Append(close); i++; break; }
                        sb.Append(c).Append("\r\n").Append(' ', ++level * 2);
                        break;
                    case '}':
                    case ']':
                        sb.Append("\r\n").Append(' ', --level * 2).Append(c);
                        break;
                    case ',': sb.Append(c).Append("\r\n").Append(' ', level * 2); break;
                    case ':': sb.Append(": "); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
