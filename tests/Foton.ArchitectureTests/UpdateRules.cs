using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// The updater's trust anchor: the owner's release public keys live in one file, so adding, swapping, or removing a
    /// key is always a visible diff of src\Foton.Tools\Update\ReleaseKeys.cs and nothing else.
    /// </summary>
    public class UpdateRules
    {
        // Base64 of a CNG ECCPUBLICBLOB header for P-256 ("ECS1", key length 32): the start of every pinned key.
        // Computed, so this file does not hold the text it looks for.
        static readonly string EccP256BlobPrefix = Convert.ToBase64String(new byte[] { 0x45, 0x43, 0x53, 0x31, 0x20, 0, 0, 0 }).Substring(0, 10);
        static readonly string KeysFile = Path.Combine("src", "Foton.Tools", "Update", "ReleaseKeys.cs");
        static readonly string[] Folders = { "src", "cli", "tests", "packaging", ".github" };

        [Fact]
        public void Release_public_keys_are_pinned_only_in_ReleaseKeys_cs()
        {
            var holders = new List<string>();
            foreach (var folder in Folders.Select(f => Path.Combine(Repo.Root, f)).Where(Directory.Exists))
                foreach (var f in Directory.GetFiles(folder, "*", SearchOption.AllDirectories))
                {
                    if (f.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar)
                        || f.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar)
                        || !new[] { ".cs", ".ps1", ".yml", ".json", ".txt", ".md" }.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
                        continue;
                    if (File.ReadAllText(f).Contains(EccP256BlobPrefix)) holders.Add(f.Substring(Repo.Root.Length + 1));
                }
            Assert.Equal(new[] { KeysFile }, holders);
        }
    }
}
