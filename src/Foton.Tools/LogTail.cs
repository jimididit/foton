using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Foton.Tools
{
    /// <summary>
    /// Follows a log another process is writing (the collector's collection.log / baseline.log), one complete line at a
    /// time. Reads share the file, so the collector is never blocked. Bytes are decoded only up to the last line feed,
    /// which never occurs inside a multi-byte UTF-8 character, so a read that lands mid-write cannot split one.
    /// </summary>
    public sealed class LogTail
    {
        readonly string _path;
        long _offset;
        DateTime _created;
        byte[] _pending = new byte[0];

        public LogTail(string path) { _path = path; }

        public IReadOnlyList<string> ReadNewLines()
        {
            var lines = new List<string>();
            byte[] data;
            try
            {
                var info = new FileInfo(_path);
                if (!info.Exists) return lines;
                // A log replaced by a new file (a different creation time, or a shorter one) is read from the start.
                if (info.CreationTimeUtc != _created || info.Length < _offset)
                {
                    _created = info.CreationTimeUtc;
                    _offset = 0;
                    _pending = new byte[0];
                }
                using (var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    fs.Seek(_offset, SeekOrigin.Begin);
                    var buffer = new byte[Math.Max(0, fs.Length - _offset)];
                    int read = 0, n;
                    while (read < buffer.Length && (n = fs.Read(buffer, read, buffer.Length - read)) > 0) read += n;
                    _offset += read;
                    data = new byte[_pending.Length + read];
                    Buffer.BlockCopy(_pending, 0, data, 0, _pending.Length);
                    Buffer.BlockCopy(buffer, 0, data, _pending.Length, read);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return lines; }

            var end = Array.LastIndexOf(data, (byte)'\n');
            if (end < 0) { _pending = data; return lines; }
            var parts = Encoding.UTF8.GetString(data, 0, end + 1).Split('\n');
            for (int i = 0; i < parts.Length - 1; i++) lines.Add(parts[i].TrimEnd('\r'));   // the last part follows the final '\n'
            _pending = new byte[data.Length - end - 1];
            Buffer.BlockCopy(data, end + 1, _pending, 0, _pending.Length);
            return lines;
        }
    }
}
