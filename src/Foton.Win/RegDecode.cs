using System;
using System.Text;

namespace Foton.Win
{
    /// <summary>Decoders for registry values whose meaning is packed into binary data. Shared by Collect and Baseline.</summary>
    public static class RegDecode
    {
        /// <summary>DLL path from a Winsock PackedCatalogItem: ANSI MAX_PATH on current Windows, UTF-16 on older layouts.</summary>
        public static string WinsockPackedPath(object? v)
        {
            if (!(v is byte[] b) || b.Length < 4) return "(not set)";
            int lim = Math.Min(260, b.Length);
            bool ascii = true;
            for (int i = 0; i < lim; i++)
            {
                if (b[i] == 0) break;
                if (b[i] < 32 || b[i] > 126) { ascii = false; break; }
            }
            string s;
            if (ascii) s = Encoding.ASCII.GetString(b, 0, lim);
            else
            {
                int n = Math.Min(520, b.Length);
                if (n % 2 == 1) n--;
                s = Encoding.Unicode.GetString(b, 0, n);
            }
            int z = s.IndexOf('\0');
            if (z >= 0) s = s.Substring(0, z);
            s = s.Trim();
            return s.Length == 0 ? "(not set)" : s;
        }

        /// <summary>Settings / Task Manager "Startup apps" state from the StartupApproved REG_BINARY (byte 0): 2/6 enabled, 3/7 disabled.</summary>
        public static string StartupApprovedState(object? v)
        {
            if (!(v is byte[] b) || b.Length < 1) return "Unknown";
            switch (b[0])
            {
                case 2: case 6: return "Enabled";
                case 3: case 7: return "Disabled";
                default: return "Other:" + b[0];
            }
        }
    }
}
