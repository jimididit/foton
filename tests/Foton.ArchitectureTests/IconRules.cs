using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Every shipped executable carries its own icon (assets\brand\icons\&lt;AssemblyName&gt;.ico) after ILRepack, and no
    /// two share one. Windows stores each icon frame's image data verbatim as a resource, so finding every frame's bytes
    /// in the exe proves which icon it is.
    /// </summary>
    public class IconRules
    {
        static string IconPath(string assemblyName) => Path.Combine(Repo.Root, "assets", "brand", "icons", assemblyName + ".ico");

        static List<ProjectInfo> Exes() => Repo.Projects.Values.Where(p => p.IsExe).OrderBy(p => p.AssemblyName, StringComparer.Ordinal).ToList();

        sealed class Frame
        {
            public int Size;
            public bool Png;
            public byte[] Data = new byte[0];
        }

        /// <summary>The frames of an .ico file (directory entries: width at +0, size at +8, offset at +12).</summary>
        static List<Frame> Frames(string path)
        {
            var name = Path.GetFileName(path);
            Assert.True(File.Exists(path), name + " is missing from assets\\brand\\icons.");
            var ico = File.ReadAllBytes(path);
            Assert.True(ico.Length > 6 && BitConverter.ToUInt16(ico, 2) == 1, name + " is not an icon file.");
            int count = BitConverter.ToUInt16(ico, 4);
            Assert.True(count > 0 && 6 + 16 * count <= ico.Length, name + "'s directory does not fit the file.");
            var frames = new List<Frame>();
            for (int i = 0; i < count; i++)
            {
                var entry = 6 + 16 * i;
                int size = BitConverter.ToInt32(ico, entry + 8), offset = BitConverter.ToInt32(ico, entry + 12);
                // A frame that is empty or runs past the file would make the byte search below meaningless.
                Assert.True(size > 0 && offset >= 6 + 16 * count && (long)offset + size <= ico.Length, $"{name} frame {i} lies outside the file.");
                var data = ico.Skip(offset).Take(size).ToArray();
                frames.Add(new Frame { Size = ico[entry] == 0 ? 256 : ico[entry], Png = data.Length > 4 && data[0] == 0x89 && data[1] == (byte)'P', Data = data });
            }
            return frames;
        }

        static bool Contains(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                if (haystack[i] != needle[0]) continue;
                int j = 1;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }

        [Fact]
        public void Each_icon_has_every_size_Windows_asks_for_in_a_format_the_loader_reads()
        {
            foreach (var p in Exes())
            {
                var frames = Frames(IconPath(p.AssemblyName));
                foreach (var size in new[] { 16, 20, 24, 32, 40, 48, 64, 256 })
                    Assert.True(frames.Any(f => f.Size == size), p.AssemblyName + ".ico has no " + size + " px frame.");
                // The .NET Framework icon loader (the console's window icon) reads PNG reliably only in the 256 px frame.
                Assert.True(frames.Where(f => f.Size <= 64).All(f => !f.Png), p.AssemblyName + ".ico stores a frame up to 64 px as PNG; use a 32-bit bitmap.");
            }
        }

        [Fact]
        public void No_two_executables_share_an_icon()
        {
            var exes = Exes();
            Assert.Equal(4, exes.Count);
            using (var sha = SHA256.Create())
            {
                var digests = exes.Select(p => Convert.ToBase64String(sha.ComputeHash(File.ReadAllBytes(IconPath(p.AssemblyName))))).ToList();
                Assert.Equal(exes.Count, digests.Distinct().Count());
            }
        }

        [Fact]
        public void Every_executable_carries_its_own_icon_and_no_other()
        {
            var exes = Exes();
            var large = exes.ToDictionary(p => p.AssemblyName, p => Frames(IconPath(p.AssemblyName)).Single(f => f.Size == 256).Data);
            // foton.exe and the console carry the two collectors (EmbedCollectors.targets) for bundles, icons included.
            var collectors = new[] { "foton-collect", "foton-baseline" };
            foreach (var p in exes)
            {
                Assert.True(File.Exists(p.OutputAssembly), p.OutputAssembly + " missing; build the solution (" + Repo.Configuration + ") first.");
                var exe = File.ReadAllBytes(p.OutputAssembly);
                foreach (var f in Frames(IconPath(p.AssemblyName)))
                    Assert.True(Contains(exe, f.Data), p.AssemblyName + ".exe lacks the " + f.Size + " px frame of its icon.");
                var embeds = File.ReadAllText(p.Path).Contains("EmbedCollectors.targets");
                foreach (var other in large.Where(kv => kv.Key != p.AssemblyName && !(embeds && collectors.Contains(kv.Key))))
                    Assert.False(Contains(exe, other.Value), p.AssemblyName + ".exe carries " + other.Key + ".ico.");
            }
        }
    }
}
