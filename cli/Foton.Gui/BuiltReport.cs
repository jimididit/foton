using System;
using System.IO;
using Foton.Core;

namespace Foton.Gui
{
    /// <summary>
    /// An HTML report this console built, and its SHA-256 then. A browser runs whatever an HTML file holds, and a package's
    /// own report was written on the endpoint, which may be compromised; so only a report built here, unchanged since, is
    /// opened.
    /// </summary>
    sealed class BuiltReport
    {
        string? _sha256;

        public string? Path { get; private set; }

        /// <summary>Records a report just built; one that cannot be hashed (locked, removed) is not recorded, so it is not opened.</summary>
        public void Remember(string? path)
        {
            Path = null;
            _sha256 = null;
            if (path == null) return;
            try
            {
                if (!File.Exists(path)) return;
                _sha256 = Hashing.Sha256Hex(path);
                Path = path;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { _sha256 = null; }
        }

        public bool Unchanged()
        {
            try { return Path != null && File.Exists(Path) && string.Equals(Hashing.Sha256Hex(Path), _sha256, StringComparison.OrdinalIgnoreCase); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return false; }
        }
    }
}
