using System;
using System.IO;
using System.Reflection;

namespace Foton.Tools
{
    public enum CollectorKind { Collect, Baseline }

    /// <summary>
    /// The endpoint collectors that foton.exe and foton-console.exe carry as data (cli\EmbedCollectors.targets): the
    /// same foton-collect.exe and foton-baseline.exe bytes the release publishes, built first and packed as manifest
    /// resources. They are only ever written to disk (a bundle) and never loaded or run by the program carrying them.
    /// </summary>
    public static class EmbeddedCollectors
    {
        const string Prefix = "Foton.Collectors.";
        const long MaxBytes = 64L * 1024 * 1024;

        public static string FileName(CollectorKind kind) => kind == CollectorKind.Collect ? "foton-collect.exe" : "foton-baseline.exe";

        public static string ResourceName(CollectorKind kind) => Prefix + FileName(kind);

        /// <summary>The collector's bytes from <paramref name="host"/> (the running executable by default); InvalidDataException when it carries none.</summary>
        public static byte[] Read(CollectorKind kind, Assembly? host = null)
        {
            host = host ?? Assembly.GetEntryAssembly();
            using (var stream = host?.GetManifestResourceStream(ResourceName(kind)))
            {
                if (stream == null) throw new InvalidDataException($"This program does not carry {FileName(kind)}; use the released foton.exe or foton-console.exe.");
                if (stream.Length > MaxBytes) throw new InvalidDataException($"The embedded {FileName(kind)} is larger than {MaxBytes} bytes.");
                var bytes = new byte[stream.Length];
                int read = 0, n;
                while (read < bytes.Length && (n = stream.Read(bytes, read, bytes.Length - read)) > 0) read += n;
                if (read != bytes.Length) throw new InvalidDataException($"The embedded {FileName(kind)} could not be read in full.");
                return bytes;
            }
        }
    }
}
