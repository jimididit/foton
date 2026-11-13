using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using Foton.Win.Ui;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Every console palette meets WCAG contrast for each pairing the console draws.</summary>
    public class PaletteTests
    {
        static IEnumerable<(string Pair, Color Fore, Color Back, double Need)> Pairs(Palette p)
        {
            foreach (var (name, back) in new[] { ("Back", p.Back), ("Surface", p.Surface), ("List", p.List), ("Field", p.Field), ("Raised", p.Raised), ("Hover", p.Hover), ("Pressed", p.Pressed), ("Header", p.Header), ("Info", p.Info) })
                yield return ("Text on " + name, p.Text, back, 4.5);
            foreach (var (name, back) in new[] { ("Back", p.Back), ("Surface", p.Surface), ("List", p.List), ("Info", p.Info) })
                yield return ("Muted on " + name, p.Muted, back, 4.5);
            foreach (var (name, fore) in new[] { ("Good", p.Good), ("Bad", p.Bad), ("Warn", p.Warn) })
            {
                yield return (name + " on Surface", fore, p.Surface, 4.5);
                yield return (name + " on List", fore, p.List, 4.5);
            }
            yield return ("SelectionText on Selection", p.SelectionText, p.Selection, 4.5);
            yield return ("AccentText on Accent", p.AccentText, p.Accent, 4.5);
            yield return ("Border on Field", p.Border, p.Field, 3.0);
            yield return ("Border on Surface", p.Border, p.Surface, 3.0);
            yield return ("Accent on Back", p.Accent, p.Back, 3.0);
            yield return ("Accent on Surface", p.Accent, p.Surface, 3.0);
        }

        [Fact]
        public void Every_palette_meets_contrast()
        {
            var failures = Palette.All
                .SelectMany(p => Pairs(p).Select(x => (p.Name, x.Pair, Ratio: Contrast.Ratio(x.Fore, x.Back), x.Need)))
                .Where(x => x.Ratio < x.Need)
                .Select(x => $"{x.Name}: {x.Pair} {x.Ratio:0.00} < {x.Need}")
                .ToList();
            Assert.True(failures.Count == 0, string.Join("; ", failures));
        }

        [Fact]
        public void Contrast_matches_WCAG_reference_values()
        {
            Assert.Equal(21.0, Contrast.Ratio(Color.Black, Color.White), 2);
            Assert.Equal(1.0, Contrast.Ratio(Color.Gray, Color.Gray), 2);
            Assert.Equal(4.54, Contrast.Ratio(ColorTranslator.FromHtml("#767676"), Color.White), 2);
        }

        [Fact]
        public void Palettes_are_found_by_name_and_Light_is_not_one()
        {
            Assert.Same(Palette.SolarizedDark, Palette.Find("solarizeddark"));
            Assert.Null(Palette.Find("Light"));
            Assert.Equal(4, Palette.All.Select(p => p.Name).Distinct().Count());
        }
    }
}
