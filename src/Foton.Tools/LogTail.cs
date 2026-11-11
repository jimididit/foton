using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Foton.Tools
{
    /// <summary>
    /// Follows a log another process is writing (the collector's collection.log / baseline.log), one complete line at a
    /// time. Reads share the file, so the collector is never blocked. The collectors write whole lines, so a UTF-8
    /// character is never split across two reads.
    /// </summary>
    public sealed class LogTail
    {
        readonly string _path;
        long _offset;
        readonly StringBuilder _partial = new StringBuilder();

        public LogTail(string path) { _path = path; }

        public IReadOnlyList<string> ReadNewLines()
        {
            var lines = new List<string>();
            if (!File.Exists(_path)) return lines;
            try
            {
                using (var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (fs.Length < _offset) { _offset = 0; _partial.Clear(); }   // replaced: start again
                    fs.Seek(_offset, SeekOrigin.Begin);
                    var buffer = new byte[fs.Length - _offset];
                    int read = 0, n;
                    while (read < buffer.Length && (n = fs.Read(buffer, read, buffer.Length - read)) > 0) read += n;
                    _offset += read;
                    _partial.Append(Encoding.UTF8.GetString(buffer, 0, read));
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return lines; }
            var text = _partial.ToString();
            int start = 0, nl;
            while ((nl = text.IndexOf('\n', start)) >= 0)
            {
                lines.Add(text.Substring(start, nl - start).TrimEnd('\r'));
                start = nl + 1;
            }
            _partial.Clear().Append(text.Substring(start));
            return lines;
        }
    }
}
