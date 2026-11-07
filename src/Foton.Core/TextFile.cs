using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Foton.Core
{
    /// <summary>
    /// Text artifacts with the bytes Windows PowerShell 5.1 "Out-File -Encoding UTF8" produced:
    /// UTF-8 with BOM, CRLF line endings, a trailing CRLF; appends add no second BOM.
    /// </summary>
    public static class TextFile
    {
        public static readonly Encoding Utf8Bom = new UTF8Encoding(true);
        public static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        public static void WriteLines(string path, IEnumerable<string> lines)
        {
            using (var w = new StreamWriter(path, false, Utf8Bom))
                foreach (var l in lines) { w.Write(l); w.Write("\r\n"); }
        }

        public static void Write(string path, string text) => WriteLines(path, new[] { text });

        public static void AppendLine(string path, string line)
        {
            // A new file gets the BOM (as Out-File -Append would); an existing one does not.
            var enc = File.Exists(path) ? Utf8NoBom : Utf8Bom;
            using (var w = new StreamWriter(path, true, enc)) { w.Write(line); w.Write("\r\n"); }
        }

        /// <summary>
        /// A value safe to embed in a line-oriented record: CR, LF, and other control characters become
        /// spaces. Host-supplied text (OS caption, paths, error messages) must not forge lines in custody
        /// records, or a fake "yyyy-MM-dd HH:mm:ss UTC" line in collection.log that widens the collection window.
        /// </summary>
        public static string OneLine(string? value)
        {
            if (string.IsNullOrEmpty(value)) return value ?? "";
            var chars = value!.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
                if (char.IsControl(chars[i]) && chars[i] != '\t') chars[i] = ' ';
            return new string(chars);
        }

        /// <summary>Reads text written by either line (BOM or not, CRLF or LF).</summary>
        public static string[] ReadLines(string path) => File.ReadAllLines(path, Encoding.UTF8);
    }
}
