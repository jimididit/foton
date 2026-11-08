using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Foton.Win
{
    /// <summary>One NTFS stream of a file, named as Get-Item -Stream * reported it (":$DATA" for the unnamed stream).</summary>
    public sealed class FileStreamInfo
    {
        public string Stream { get; set; } = "";
        public long Length { get; set; }
    }

    /// <summary>NTFS alternate data streams through FindFirstStreamW (Get-Item -Stream *). Read-only.</summary>
    public static class FileStreams
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct FindStreamData
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string StreamName;
        }

        internal static int StructSize() => Marshal.SizeOf(typeof(FindStreamData));

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstStreamW(string fileName, int infoLevel, out FindStreamData data, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FindNextStreamW(IntPtr find, out FindStreamData data);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FindClose(IntPtr find);

        static readonly IntPtr Invalid = new IntPtr(-1);

        /// <summary>The file's streams; empty when it cannot be opened (a path from host data is opened only when local).</summary>
        public static List<FileStreamInfo> List(string path)
        {
            var list = new List<FileStreamInfo>();
            if (!Foton.Core.Hashing.IsLocalPath(path)) return list;
            var h = FindFirstStreamW(path, 0, out var data, 0);
            if (h == Invalid) return list;
            try
            {
                do list.Add(new FileStreamInfo { Stream = Name(data.StreamName), Length = data.StreamSize });
                while (FindNextStreamW(h, out data));
            }
            finally { FindClose(h); }
            return list;
        }

        /// <summary>"::$DATA" is ":$DATA"; ":Zone.Identifier:$DATA" is "Zone.Identifier".</summary>
        internal static string Name(string raw)
        {
            if (raw == "::$DATA") return ":$DATA";
            var n = raw.StartsWith(":", StringComparison.Ordinal) ? raw.Substring(1) : raw;
            return n.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase) ? n.Substring(0, n.Length - ":$DATA".Length) : n;
        }

        /// <summary>A named stream opened for reading (\\?\ form: the path normalizer rejects "file:stream").</summary>
        public static FileStream Open(string path, string stream) =>
            new FileStream(@"\\?\" + path + ":" + stream, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    }
}
