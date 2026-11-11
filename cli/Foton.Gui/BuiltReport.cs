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

        public void Remember(string? path)
        {
            Path = path != null && File.Exists(path) ? path : null;
            _sha256 = Path != null ? Hashing.Sha256Hex(Path) : null;
        }

        public bool Unchanged()
        {
            try { return Path != null && File.Exists(Path) && string.Equals(Hashing.Sha256Hex(Path), _sha256, StringComparison.OrdinalIgnoreCase); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return false; }
        }
    }
}
