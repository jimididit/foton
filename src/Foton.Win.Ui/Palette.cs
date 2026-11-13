using System;
using System.Collections.Generic;
using System.Drawing;

namespace Foton.Win.Ui
{
    /// <summary>
    /// One theme's colors, by role. Text, Muted, Good, Bad, and Warn are text colors; the others are surfaces,
    /// lines, and states. Every pairing the console draws is held to WCAG contrast by a test (4.5:1 for text,
    /// 3:1 for borders and the accent), so a new palette is added here and checked there.
    /// </summary>
    public sealed class Palette
    {
        public string Name { get; private set; } = "";
        /// <summary>Whether Windows should draw its own parts (title bar, scroll bars) dark.</summary>
        public bool IsDark { get; private set; }
        /// <summary>Window chrome: menu bar, tab strip, status bar.</summary>
        public Color Back { get; private set; }
        /// <summary>Tab pages and panels.</summary>
        public Color Surface { get; private set; }
        /// <summary>Large reading areas: grids, trees, the log, multi-line text.</summary>
        public Color List { get; private set; }
        /// <summary>Single-line inputs: text boxes, drop-downs, number boxes.</summary>
        public Color Field { get; private set; }
        /// <summary>Buttons, with their hover and pressed states.</summary>
        public Color Raised { get; private set; }
        public Color Hover { get; private set; }
        public Color Pressed { get; private set; }
        /// <summary>Grid column headers.</summary>
        public Color Header { get; private set; }
        public Color Text { get; private set; }
        /// <summary>Secondary text (hints, inactive tabs).</summary>
        public Color Muted { get; private set; }
        /// <summary>Control boundaries.</summary>
        public Color Border { get; private set; }
        /// <summary>Grid lines (decorative).</summary>
        public Color GridLines { get; private set; }
        /// <summary>Selected rows and items: a muted tint, never a saturated fill, with the normal text color on it.</summary>
        public Color Selection { get; private set; }
        public Color SelectionText { get; private set; }
        /// <summary>Selected tab underline, primary action, keyboard focus.</summary>
        public Color Accent { get; private set; }
        /// <summary>Text on an Accent fill (the primary action).</summary>
        public Color AccentText { get; private set; }
        /// <summary>Guidance strips (Start here).</summary>
        public Color Info { get; private set; }
        public Color Good { get; private set; }
        public Color Bad { get; private set; }
        public Color Warn { get; private set; }

        static Color H(string hex) => ColorTranslator.FromHtml(hex);

        /// <summary>Neutral dark, after the Windows 11 dark surfaces.</summary>
        public static readonly Palette Dark = new Palette
        {
            Name = "Dark", IsDark = true,
            Back = H("#1B1B1B"), Surface = H("#232323"), List = H("#1E1E1E"), Field = H("#2D2D2D"),
            Raised = H("#333333"), Hover = H("#3D3D3D"), Pressed = H("#262626"), Header = H("#2A2A2A"),
            Text = H("#E6E6E6"), Muted = H("#A8A8A8"), Border = H("#7A7A7A"), GridLines = H("#3A3A3A"),
            Selection = H("#264F78"), SelectionText = H("#E6E6E6"), Accent = H("#4CC2FF"), AccentText = H("#000000"), Info = H("#1C3344"),
            Good = H("#6CCB5F"), Bad = H("#FF99A4"), Warn = H("#FCE100"),
        };

        /// <summary>Windows Terminal's default (Campbell) scheme.</summary>
        public static readonly Palette Campbell = new Palette
        {
            Name = "Campbell", IsDark = true,
            Back = H("#0C0C0C"), Surface = H("#121212"), List = H("#0C0C0C"), Field = H("#1E1E1E"),
            Raised = H("#262626"), Hover = H("#303030"), Pressed = H("#181818"), Header = H("#1A1A1A"),
            Text = H("#CCCCCC"), Muted = H("#949494"), Border = H("#767676"), GridLines = H("#2A2A2A"),
            Selection = H("#1F3A5F"), SelectionText = H("#CCCCCC"), Accent = H("#3B78FF"), AccentText = H("#000000"), Info = H("#0D2440"),
            Good = H("#16C60C"), Bad = H("#F26D78"), Warn = H("#F9F1A5"),
        };

        /// <summary>Solarized dark; reds, greens, and borders lightened where the originals fall below 4.5:1 or 3:1.</summary>
        public static readonly Palette SolarizedDark = new Palette
        {
            Name = "SolarizedDark", IsDark = true,
            Back = H("#00212B"), Surface = H("#002B36"), List = H("#002B36"), Field = H("#073642"),
            Raised = H("#05313D"), Hover = H("#083B48"), Pressed = H("#02252F"), Header = H("#073642"),
            Text = H("#93A1A1"), Muted = H("#839496"), Border = H("#7B9096"), GridLines = H("#0A4252"),
            Selection = H("#0B4F63"), SelectionText = H("#EEE8D5"), Accent = H("#268BD2"), AccentText = H("#000000"), Info = H("#012F3B"),
            Good = H("#9AB000"), Bad = H("#F0625F"), Warn = H("#C9A100"),
        };

        /// <summary>Solarized light; text darkened to base02 and accents deepened to keep 4.5:1 on the cream surfaces.</summary>
        public static readonly Palette SolarizedLight = new Palette
        {
            Name = "SolarizedLight", IsDark = false,
            Back = H("#EEE8D5"), Surface = H("#FDF6E3"), List = H("#FDF6E3"), Field = H("#FFFDF7"),
            Raised = H("#EEE8D5"), Hover = H("#E4DDC8"), Pressed = H("#D9D2BC"), Header = H("#EEE8D5"),
            Text = H("#073642"), Muted = H("#4E6269"), Border = H("#7E9196"), GridLines = H("#E0D9C3"),
            Selection = H("#D3E4EE"), SelectionText = H("#073642"), Accent = H("#1F7AB8"), AccentText = H("#FFFFFF"), Info = H("#F5E7C0"),
            Good = H("#5A6B00"), Bad = H("#B5241F"), Warn = H("#7A5C00"),
        };

        /// <summary>Every palette, by name. Light is not here: it is Windows' own drawing, not a palette.</summary>
        public static IReadOnlyList<Palette> All { get; } = new[] { Dark, Campbell, SolarizedDark, SolarizedLight };

        public static Palette? Find(string name)
        {
            foreach (var p in All)
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) return p;
            return null;
        }
    }

    /// <summary>WCAG 2.x relative luminance and contrast ratio.</summary>
    public static class Contrast
    {
        public static double Ratio(Color a, Color b)
        {
            double la = Luminance(a), lb = Luminance(b);
            return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
        }

        static double Luminance(Color c) => 0.2126 * Linear(c.R) + 0.7152 * Linear(c.G) + 0.0722 * Linear(c.B);

        static double Linear(byte v)
        {
            var s = v / 255.0;
            return s <= 0.04045 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }
    }
}
