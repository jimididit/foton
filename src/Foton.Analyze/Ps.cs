using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Analyze
{
    /// <summary>
    /// One loaded artifact object (a CSV row or a JSON object). Property names are case-insensitive and a missing
    /// property reads as null, as PowerShell member access on a PSCustomObject did.
    /// </summary>
    public sealed class PsRow
    {
        readonly Dictionary<string, object?> _values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        public object? this[string name] => _values.TryGetValue(name, out var v) ? v : null;
        public bool Has(string name) => _values.ContainsKey(name);
        internal void Set(string name, object? value) => _values[name] = value;
        public IEnumerable<string> Names => _values.Keys;
    }

    /// <summary>
    /// The Windows PowerShell 5.1 operator semantics 1.38.x analysis relied on, over loaded package values
    /// (string, bool, int/long/decimal, null, PsRow, object?[]). Rules call these instead of C# operators so a
    /// "False" string, a JSON 0, or a missing column behave exactly as they did in the PowerShell rules.
    /// </summary>
    public static class Ps
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        /// <summary>[string] cast and "$(...)" expansion: null "", True/False, numbers invariant, arrays space-joined.</summary>
        public static string Str(object? v)
        {
            switch (v)
            {
                case null: return "";
                case string s: return s;
                case bool b: return b ? "True" : "False";
                case PsRow r: return "@{" + string.Join("; ", r.Names.Select(n => n + "=" + Str(r[n]))) + "}";
                case IFormattable f: return f.ToString(null, Inv);
                case IEnumerable e: return string.Join(" ", e.Cast<object?>().Select(Str));
                default: return v.ToString() ?? "";
            }
        }

        /// <summary>A "-f" argument: like Str, except an array renders as its type name ("System.Object[]").</summary>
        public static string Fmt(object? v) => v is object?[] ? "System.Object[]" : Str(v);

        /// <summary>"-f" with PowerShell argument rendering (a lone array argument is spread into the arguments).</summary>
        public static string F(string format, params object?[] args)
        {
            if (args.Length == 1 && args[0] is object?[] spread) args = spread;
            return string.Format(Inv, format, args.Select(a => (object)Fmt(a)).ToArray());
        }

        /// <summary>"items | ForEach-Object { f }": nulls kept, an array result flattened one level.</summary>
        public static IEnumerable<object?> Each<T>(IEnumerable<T> items, Func<T, object?> f)
        {
            foreach (var x in items)
            {
                var v = f(x);
                if (v is object?[] a) foreach (var e in a) yield return e;
                else yield return v;
            }
        }

        /// <summary>LanguagePrimitives.IsTrue: empty string, 0, null, empty array, or a one-element array of a false value are false.</summary>
        public static bool IsTrue(object? v)
        {
            switch (v)
            {
                case null: return false;
                case bool b: return b;
                case string s: return s.Length > 0;
                case object?[] a: return a.Length == 0 ? false : a.Length == 1 ? (a[0] is object?[] || IsTrue(a[0])) : true;
                case PsRow _: return true;
                default: return Num(v, out var d) ? d != 0 : true;
            }
        }

        /// <summary>-eq (case-insensitive). The right operand is converted to the left operand's type.</summary>
        public static bool Eq(object? left, object? right)
        {
            if (left == null) return right == null;
            if (right == null) return false;
            switch (left)
            {
                case string ls:
                    return string.Equals(ls, right is string rs ? rs : Str(right), StringComparison.InvariantCultureIgnoreCase);
                case bool lb:
                    return lb == IsTrue(right);
            }
            if (Num(left, out var l))
            {
                if (right is bool rb) return l == (rb ? 1 : 0);
                if (Num(right, out var r)) return l == r;
                return right is string s && ParseNum(s, out r) && l == r;
            }
            return Equals(left, right);
        }

        public static bool Ne(object? left, object? right) => !Eq(left, right);

        /// <summary>-gt / -lt ordering: numeric when the left side is a number, otherwise string order (case-insensitive).</summary>
        public static int Cmp(object? left, object? right)
        {
            if (Num(left, out var l))
            {
                if (Num(right, out var r) || (right is string s && ParseNum(s, out r))) return l.CompareTo(r);
                if (right is bool rb) return l.CompareTo(rb ? 1m : 0m);
            }
            return string.Compare(Str(left), Str(right), StringComparison.InvariantCultureIgnoreCase);
        }

        public static bool Gt(object? left, object? right) => left != null && Cmp(left, right) > 0;

        /// <summary>-in / -contains: any element equals the value, element on the left.</summary>
        public static bool In(object? value, params object?[] set) => set.Any(e => Eq(e, value));

        /// <summary>-match (case-insensitive) on the [string] form.</summary>
        public static bool Match(object? v, string pattern) => Regex.IsMatch(Str(v), pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>-like (case-insensitive wildcard: * ? [set]).</summary>
        public static bool Like(object? v, string pattern) => Regex.IsMatch(Str(v), WildcardToRegex(pattern), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline);

        static string WildcardToRegex(string w)
        {
            var sb = new StringBuilder("^");
            for (int i = 0; i < w.Length; i++)
            {
                char c = w[i];
                if (c == '*') sb.Append(".*");
                else if (c == '?') sb.Append('.');
                else if (c == '[')
                {
                    int end = w.IndexOf(']', i + 1);
                    if (end < 0) { sb.Append(Regex.Escape("[")); continue; }
                    sb.Append('[').Append(w.Substring(i + 1, end - i - 1).Replace("\\", "\\\\")).Append(']');
                    i = end;
                }
                else if (c == '`' && i + 1 < w.Length) sb.Append(Regex.Escape(w[++i].ToString()));
                else sb.Append(Regex.Escape(c.ToString()));
            }
            return sb.Append('$').ToString();
        }

        /// <summary>@(...): a null is an empty list, an array its elements, anything else one element.</summary>
        public static IReadOnlyList<object?> Items(object? v)
        {
            if (v == null) return new object?[0];
            if (v is object?[] a) return a;
            return new[] { v };
        }

        public static IReadOnlyList<PsRow> Rows(object? v) => Items(v).OfType<PsRow>().ToList();

        /// <summary>Member access: a property of one object, or member enumeration over an array (non-null values).</summary>
        public static object? Get(object? obj, string name)
        {
            switch (obj)
            {
                case PsRow r: return r[name];
                case object?[] a:
                    var vals = a.Select(x => Get(x, name)).Where(x => x != null).ToArray();
                    return vals.Length == 0 ? null : vals.Length == 1 ? vals[0] : vals;
                default: return null;
            }
        }

        /// <summary>ConvertTo-FotonSample: a few values joined with " ; " plus how many more the artifact holds.</summary>
        public static string Sample(IEnumerable<object?> items, int max = 5)
        {
            var arr = items.ToArray();
            if (!IsTrue(arr)) return "";
            var text = string.Join(" ; ", arr.Take(max).Select(Str));
            if (arr.Length > max) text += F(" ... (+{0} more, see artifact)", arr.Length - max);
            return text;
        }

        public static string Sample(IEnumerable<string> items, int max = 5) => Sample(items.Cast<object?>(), max);

        internal static bool Num(object? v, out decimal d)
        {
            switch (v)
            {
                case int i: d = i; return true;
                case long l: d = l; return true;
                case decimal m: d = m; return true;
                case double x when !double.IsNaN(x) && !double.IsInfinity(x) && Math.Abs(x) < 7.9e27: d = (decimal)x; return true;
                case uint u: d = u; return true;
                case short s: d = s; return true;
                case byte by: d = by; return true;
                default: d = 0; return false;
            }
        }

        static bool ParseNum(string s, out decimal d) =>
            decimal.TryParse(s.Trim(), NumberStyles.Float | NumberStyles.AllowThousands, Inv, out d);
    }
}
