using System;
using System.Globalization;

namespace Foton.Core
{
    /// <summary>UTC everywhere, invariant culture: the two formats every Foton artifact uses.</summary>
    public static class FotonTime
    {
        /// <summary>yyyy-MM-dd HH:mm:ss (artifact columns, logs, custody, coverage).</summary>
        public static string Format(DateTime utc) =>
            ToUtc(utc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        /// <summary>yyyyMMdd-HHmmss (case and baseline folder names).</summary>
        public static string Stamp(DateTime utc) =>
            ToUtc(utc).ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);

        public static bool TryParse(string? text, out DateTime utc)
        {
            var ok = DateTime.TryParseExact(text, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out utc);
            return ok;
        }

        static DateTime ToUtc(DateTime t) =>
            t.Kind == DateTimeKind.Utc ? t : t.Kind == DateTimeKind.Local ? t.ToUniversalTime() : DateTime.SpecifyKind(t, DateTimeKind.Utc);
    }
}
