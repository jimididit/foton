using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Every shipped executable carries the Foton icon (assets\brand\foton.ico) after ILRepack. Windows stores each icon
    /// frame's image data verbatim as a resource, so finding every frame's bytes in the exe proves it is this icon.
    /// </summary>
    public class IconRules
    {
        static string IconPath => Path.Combine(Repo.Root, "assets", "brand", "foton.ico");

        /// <summary>The image data of each frame in an .ico file (directory entries: size at +8, offset at +12).</summary>
        static List<byte[]> Frames(byte[] ico)
        {
            Assert.True(ico.Length > 6 && BitConverter.ToUInt16(ico, 2) == 1, "foton.ico is not an icon file.");
            int count = BitConverter.ToUInt16(ico, 4);
            var frames = new List<byte[]>();
            for (int i = 0; i < count; i++)
            {
                var entry = 6 + 16 * i;
                int size = BitConverter.ToInt32(ico, entry + 8), offset = BitConverter.ToInt32(ico, entry + 12);
                frames.Add(ico.Skip(offset).Take(size).ToArray());
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
        public void The_icon_has_every_size_Windows_asks_for()
        {
            var ico = File.ReadAllBytes(IconPath);
            var sizes = Enumerable.Range(0, BitConverter.ToUInt16(ico, 4)).Select(i => ico[6 + 16 * i] == 0 ? 256 : ico[6 + 16 * i]).ToList();
            foreach (var size in new[] { 16, 20, 24, 32, 40, 48, 64, 256 }) Assert.Contains(size, sizes);
        }

        [Fact]
        public void Every_executable_carries_the_Foton_icon()
        {
            var frames = Frames(File.ReadAllBytes(IconPath));
            var exes = Repo.Projects.Values.Where(p => p.IsExe).ToList();
            Assert.Equal(4, exes.Count);
            foreach (var p in exes)
            {
                Assert.True(File.Exists(p.OutputAssembly), p.OutputAssembly + " missing; build the solution (" + Repo.Configuration + ") first.");
                var exe = File.ReadAllBytes(p.OutputAssembly);
                for (int i = 0; i < frames.Count; i++)
                    Assert.True(Contains(exe, frames[i]), p.AssemblyName + ".exe lacks icon frame " + i + " of foton.ico.");
            }
        }
    }
}
