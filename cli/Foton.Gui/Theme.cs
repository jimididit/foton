using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using Foton.Tools;
using Foton.Win.Ui;

namespace Foton.Gui
{
    /// <summary>
    /// The console's themes and text size. Light is Windows' own drawing; every other theme is a Palette (Foton.Win.Ui),
    /// whose roles map onto the controls here: chrome, surfaces, reading areas, inputs, buttons, grids, menus. Windows
    /// draws the title bar and the scroll bars, tree glyphs, and drop-down buttons, so those are asked for dark through
    /// WindowChrome. Each control's original colors are remembered the first time it is themed, so Light restores exactly
    /// what the control had; a control that took its colors from its parent keeps following the parent. To theme a new
    /// kind of control, add it to Style.
    /// </summary>
    static class Theme
    {
        /// <summary>The palette in use; null is Light (Windows' own colors), also used with Windows High Contrast.</summary>
        public static Palette? Palette { get; private set; }
        public static float TextSize { get; private set; } = 9f;

        /// <summary>Selected rows in Light: Explorer's pale blue (16:1 with black text).</summary>
        static readonly Color LightSelection = Color.FromArgb(0xCC, 0xE4, 0xF7);

        /// <summary>Secondary text in the current theme (grey timeline rows, hints set after the control was themed).</summary>
        public static Color MutedText => Palette?.Muted ?? SystemColors.GrayText;

        sealed class Original
        {
            public Color Back, Fore;
            public bool BackSet, ForeSet;
            public FlatStyle? Flat;
            public DataGridViewCellStyle? Cells, Headers;
            public Color GridBack, GridLines;
            public bool HeaderVisualStyles;
            public TabDrawMode? TabDraw;
            public Color? TreeLines;
            public ToolStripRenderer? Renderer;
            public bool? VisualStyleBack;
        }

        static readonly ConditionalWeakTable<Control, Original> Originals = new ConditionalWeakTable<Control, Original>();
        static readonly Dictionary<Palette, ToolStripRenderer> Renderers = new Dictionary<Palette, ToolStripRenderer>();

        /// <summary>Sets the palette (null for Light) and size, then themes <paramref name="root"/> and everything under it.</summary>
        public static void Apply(Control root, Palette? palette, float textSize)
        {
            Palette = palette;
            TextSize = textSize;
            Walk(root);
        }

        /// <summary>Themes a window built after the theme was set (dialogs), and keeps theming controls added to it later.</summary>
        public static void Adopt(Form form)
        {
            Tidy.Apply(form);
            SetFont(form);
            Walk(form);
            Watch(form);
        }

        /// <summary>Controls already watched: a control removed and added again (rebuilt panels) gets the handler once.</summary>
        static readonly ConditionalWeakTable<Control, object> Watched = new ConditionalWeakTable<Control, object>();

        /// <summary>Themes controls as they are added anywhere under <paramref name="root"/> (checklist labels, rebuilt panels).</summary>
        public static void Watch(Control root)
        {
            if (Watched.TryGetValue(root, out _)) return;
            Watched.Add(root, new object());
            root.ControlAdded += (s, e) => { Walk(e.Control); Watch(e.Control); };
            foreach (Control c in root.Controls) Watch(c);
        }

        /// <summary>
        /// Gives a control a new text color after it was themed, as Light would show it (GrayText, DarkGreen, DarkRed):
        /// the theme maps it to its own muted, good, or bad color, and Light shows it as given.
        /// </summary>
        public static void SetFore(Control c, Color lightColor)
        {
            var o = Remember(c);
            o.Fore = lightColor;
            o.ForeSet = true;
            Style(c);
        }

        /// <summary>Fonts this class created for a form; only those are disposed when replaced (a caller's font is never disposed here).</summary>
        static readonly ConditionalWeakTable<Form, Font> OwnFonts = new ConditionalWeakTable<Form, Font>();

        /// <summary>A new font only when the size changes.</summary>
        static void SetFont(Form form)
        {
            if (Math.Abs(form.Font.Size - TextSize) < 0.01f) return;
            var font = new Font("Segoe UI", TextSize);
            form.Font = font;
            if (OwnFonts.TryGetValue(form, out var previous)) { OwnFonts.Remove(form); previous.Dispose(); }
            OwnFonts.Add(form, font);
        }

        /// <summary>A monospaced font for logs and raw text: Cascadia Mono, else Consolas, else Windows' fixed font.</summary>
        public static Font MonoFont(float size)
        {
            foreach (var family in new[] { "Cascadia Mono", "Consolas" })
            {
                var f = new Font(family, size);
                if (string.Equals(f.Name, family, StringComparison.OrdinalIgnoreCase)) return f;   // GDI+ substitutes a missing family
                f.Dispose();
            }
            return new Font(FontFamily.GenericMonospace, size);
        }

        /// <summary>Records a whole tree before styling any of it, so a child's inherited colors are seen as the parent's.</summary>
        static void Walk(Control c)
        {
            RememberTree(c);
            StyleTree(c);
        }

        static void RememberTree(Control c)
        {
            Remember(c);
            foreach (Control child in c.Controls) RememberTree(child);
        }

        static void StyleTree(Control c)
        {
            Style(c);
            foreach (Control child in c.Controls) StyleTree(child);
        }

        static Original Remember(Control c)
        {
            if (Originals.TryGetValue(c, out var o)) return o;
            // Whether the color was set on this control (WinForms' own test), not inferred from what it reads now: a color
            // that was never set is the parent's (ambient) or the control's default, whatever theme is showing when the
            // control is first seen, and is reset rather than restored.
            bool Set(string property) => TypeDescriptor.GetProperties(c)[property]?.ShouldSerializeValue(c) ?? false;
            o = new Original { Back = c.BackColor, Fore = c.ForeColor, BackSet = Set("BackColor"), ForeSet = Set("ForeColor") };
            if (c is ButtonBase b) { o.Flat = b.FlatStyle; o.VisualStyleBack = b.UseVisualStyleBackColor; }
            if (c is ComboBox cb) o.Flat = cb.FlatStyle;
            if (c is DataGridView g)
            {
                o.Cells = new DataGridViewCellStyle(g.DefaultCellStyle);
                o.Headers = new DataGridViewCellStyle(g.ColumnHeadersDefaultCellStyle);
                o.GridBack = g.BackgroundColor;
                o.GridLines = g.GridColor;
                o.HeaderVisualStyles = g.EnableHeadersVisualStyles;
            }
            if (c is TabControl t) o.TabDraw = t.DrawMode;
            if (c is TreeView tv) o.TreeLines = tv.LineColor;
            if (c is ToolStrip ts) o.Renderer = ts.Renderer;
            Originals.Add(c, o);
            return o;
        }

        /// <summary>A text color set for Light, in the palette's terms.</summary>
        static Color Fore(Palette p, Color light) =>
            light == SystemColors.GrayText ? p.Muted
            : light == Color.DarkGreen || light == Color.Green ? p.Good
            : light == Color.DarkRed || light == Color.Red ? p.Bad
            : light == Color.DarkOrange || light == Color.Orange ? p.Warn
            : p.Text;

        /// <summary>Reading areas (multi-line text, lists, trees) versus single-line inputs.</summary>
        static bool IsReadingArea(Control c) => (c is TextBoxBase t && t.Multiline) || c is ListBox || c is TreeView || c is ListView;

        static bool IsField(Control c) => c is TextBoxBase || c is ListControl || c is TreeView || c is UpDownBase || c is ListView;

        static void Style(Control c)
        {
            var o = Remember(c);
            if (c is Form f) SetFont(f);
            var p = Palette;

            var pushButton = c is ButtonBase && !(c is CheckBox) && !(c is RadioButton);
            if (p == null)
            {
                if (o.BackSet) c.BackColor = o.Back; else c.ResetBackColor();
                if (o.ForeSet) c.ForeColor = o.Fore; else c.ResetForeColor();
            }
            else
            {
                // Surfaces that paint themselves get palette colors; everything else (panels, labels, check boxes) follows
                // its parent, as it does in Light.
                if (c is Form) c.BackColor = p.Back;
                else if (c is TabPage) c.BackColor = p.Surface;
                else if (IsField(c)) c.BackColor = IsReadingArea(c) ? p.List : p.Field;
                else if (pushButton) c.BackColor = p.Raised;
                else if (o.BackSet) c.BackColor = o.Back == SystemColors.Info ? p.Info : o.Back == SystemColors.Window ? p.List : p.Surface;
                if (o.ForeSet) c.ForeColor = Fore(p, o.Fore);
                else if (IsField(c) || c is Form || pushButton) c.ForeColor = p.Text;
            }

            switch (c)
            {
                case CheckBox _:
                case RadioButton _:
                    var box = (ButtonBase)c;
                    // Flat check boxes draw their box and mark in the control's own colors, so they follow the palette.
                    box.FlatStyle = p != null ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    if (p != null)
                    {
                        box.FlatAppearance.BorderColor = p.Border;
                        box.FlatAppearance.CheckedBackColor = p.Field;
                        box.FlatAppearance.MouseOverBackColor = p.Hover;
                        box.FlatAppearance.MouseDownBackColor = p.Pressed;
                    }
                    break;
                case ButtonBase b:
                    b.FlatStyle = p != null ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    if (p != null)
                    {
                        // Hover and pressed feedback, which flat buttons do not draw by themselves.
                        b.FlatAppearance.BorderColor = p.Border;
                        b.FlatAppearance.MouseOverBackColor = p.Hover;
                        b.FlatAppearance.MouseDownBackColor = p.Pressed;
                    }
                    else b.UseVisualStyleBackColor = o.VisualStyleBack ?? true;   // as the button had it
                    if (Primary.TryGetValue(b, out _)) StylePrimary(b, p);
                    break;
                case ComboBox cb:
                    // A flat combo box paints its button in Windows' light colors; in a dark palette Windows draws the
                    // whole box with its dark theme instead (Chrome), so it keeps the standard style there.
                    cb.FlatStyle = p != null && !p.IsDark ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    break;
                case DataGridView g:
                    StyleGrid(g, o, p);
                    break;
                case ThemedTabs themed:
                    themed.Palette = p;
                    break;
                case TabControl t:
                    StyleTabs(t, o);
                    break;
                case TabPage page:
                    page.UseVisualStyleBackColor = p == null;
                    break;
                case TreeView tv:
                    tv.LineColor = p != null ? p.Muted : o.TreeLines ?? SystemColors.ControlText;
                    break;
                case ToolStrip strip:
                    if (p != null) strip.Renderer = Renderer(p);
                    else if (o.Renderer != null) strip.Renderer = o.Renderer;   // the strip's own renderer, as it was
                    break;
            }
            Chrome(c);
        }

        /// <summary>Buttons marked as the main action of their view.</summary>
        static readonly ConditionalWeakTable<ButtonBase, object> Primary = new ConditionalWeakTable<ButtonBase, object>();
        /// <summary>Bold fonts by size, shared by primary buttons (a few sizes at most; kept for the process).</summary>
        static readonly Dictionary<float, Font> BoldFonts = new Dictionary<float, Font>();

        /// <summary>The one main action of a view (Do this next): bold, and in a palette the accent fill.</summary>
        public static void MarkPrimary(ButtonBase b)
        {
            if (!Primary.TryGetValue(b, out _)) Primary.Add(b, new object());
            Remember(b);
            Style(b);
        }

        static void StylePrimary(ButtonBase b, Palette? p)
        {
            if (!BoldFonts.TryGetValue(TextSize, out var bold)) BoldFonts[TextSize] = bold = new Font("Segoe UI", TextSize, FontStyle.Bold);
            b.Font = bold;
            if (p == null) return;
            b.BackColor = p.Accent;
            b.ForeColor = p.AccentText;
            b.FlatAppearance.BorderColor = p.Accent;
            // Hover moves away from the text color, so the text keeps (and gains) contrast.
            var hover = p.AccentText.GetBrightness() < 0.5f ? ControlPaint.Light(p.Accent, 0.4f) : ControlPaint.Dark(p.Accent, 0.1f);
            b.FlatAppearance.MouseOverBackColor = hover;
            b.FlatAppearance.MouseDownBackColor = hover;
        }

        static void StyleGrid(DataGridView g, Original o, Palette? p)
        {
            if (p == null)
            {
                g.BackgroundColor = o.GridBack;
                g.GridColor = o.GridLines;
                g.EnableHeadersVisualStyles = o.HeaderVisualStyles;
                g.DefaultCellStyle = new DataGridViewCellStyle(o.Cells!);
                // Windows 11's pale list selection rather than the saturated highlight; High Contrast keeps Windows' own.
                if (!SystemInformation.HighContrast)
                {
                    g.DefaultCellStyle.SelectionBackColor = LightSelection;
                    g.DefaultCellStyle.SelectionForeColor = SystemColors.ControlText;
                }
                g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle(o.Headers!);
                return;
            }
            g.BackgroundColor = p.List;
            g.GridColor = p.GridLines;
            g.EnableHeadersVisualStyles = false;
            g.DefaultCellStyle = new DataGridViewCellStyle(o.Cells!) { BackColor = p.List, ForeColor = p.Text, SelectionBackColor = p.Selection, SelectionForeColor = p.SelectionText };
            g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle(o.Headers!) { BackColor = p.Header, ForeColor = p.Text, SelectionBackColor = p.Header, SelectionForeColor = p.Text };
        }

        /// <summary>Tab controls given the header painter (weak: a closed dialog's tabs are not kept alive).</summary>
        static readonly ConditionalWeakTable<TabControl, object> OwnerDrawn = new ConditionalWeakTable<TabControl, object>();

        /// <summary>
        /// A plain TabControl (not ThemedTabs) gets owner-drawn headers in a palette; the strip beside the last tab keeps
        /// Windows' color. The console's own tab controls are ThemedTabs, which paint all of it.
        /// </summary>
        static void StyleTabs(TabControl t, Original o)
        {
            if (!OwnerDrawn.TryGetValue(t, out _))
            {
                OwnerDrawn.Add(t, new object());
                t.DrawItem += (s, e) =>
                {
                    var p = Palette;
                    if (p == null) return;
                    var selected = e.Index == t.SelectedIndex;
                    using (var back = new SolidBrush(selected ? p.Surface : p.Back)) e.Graphics.FillRectangle(back, e.Bounds);
                    TextRenderer.DrawText(e.Graphics, t.TabPages[e.Index].Text, t.Font, e.Bounds, selected ? p.Text : p.Muted,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
                };
            }
            t.DrawMode = Palette != null ? TabDrawMode.OwnerDrawFixed : o.TabDraw ?? TabDrawMode.Normal;
            t.Invalidate();
        }

        /// <summary>Controls whose Windows-drawn parts follow the theme once their window exists.</summary>
        static readonly ConditionalWeakTable<Control, object> ChromeHooked = new ConditionalWeakTable<Control, object>();

        /// <summary>
        /// The parts Windows draws for a control: the title bar of a form, scroll bars of anything that scrolls, tree
        /// glyphs, and a drop-down's button. A control without a window yet gets them when its window is created.
        /// </summary>
        static void Chrome(Control c)
        {
            var kind = c is Form ? 1
                : c is ComboBox ? 2
                : c is TextBoxBase || c is ListBox || c is TreeView || c is ListView || c is ScrollBar || c is DataGridView
                  || (c is ScrollableControl sc && sc.AutoScroll) ? 3
                : 0;
            if (kind == 0) return;
            if (!ChromeHooked.TryGetValue(c, out _))
            {
                ChromeHooked.Add(c, new object());
                c.HandleCreated += (s, e) => Chrome(c);
            }
            if (!c.IsHandleCreated) return;
            var p = Palette;
            var dark = p != null && p.IsDark;
            switch (kind)
            {
                case 1: WindowChrome.TitleBar(c.Handle, p); break;
                case 2: WindowChrome.Control(c.Handle, dark ? WindowChrome.Parts.DarkComboBox : WindowChrome.Parts.Default); break;
                default:
                    // Trees and lists take Explorer's soft selection and chevrons in light themes too (not with High Contrast).
                    var explorerLight = !dark && !SystemInformation.HighContrast && (c is TreeView || c is ListView);
                    WindowChrome.Control(c.Handle, dark ? WindowChrome.Parts.DarkExplorer : explorerLight ? WindowChrome.Parts.Explorer : WindowChrome.Parts.Default);
                    break;
            }
            if (kind != 1) c.Invalidate();
        }

        static ToolStripRenderer Renderer(Palette p)
        {
            if (!Renderers.TryGetValue(p, out var r))
                Renderers[p] = r = new ToolStripProfessionalRenderer(new StripColors(p)) { RoundedEdges = false };
            return r;
        }

        sealed class StripColors : ProfessionalColorTable
        {
            readonly Palette _p;
            public StripColors(Palette p) { _p = p; UseSystemColors = false; }
            public override Color MenuStripGradientBegin => _p.Back;
            public override Color MenuStripGradientEnd => _p.Back;
            public override Color StatusStripGradientBegin => _p.Back;
            public override Color StatusStripGradientEnd => _p.Back;
            public override Color ToolStripDropDownBackground => _p.Field;
            public override Color ImageMarginGradientBegin => _p.Field;
            public override Color ImageMarginGradientMiddle => _p.Field;
            public override Color ImageMarginGradientEnd => _p.Field;
            public override Color MenuItemSelected => _p.Hover;
            public override Color MenuItemSelectedGradientBegin => _p.Hover;
            public override Color MenuItemSelectedGradientEnd => _p.Hover;
            public override Color MenuItemPressedGradientBegin => _p.Field;
            public override Color MenuItemPressedGradientEnd => _p.Field;
            public override Color MenuItemBorder => _p.Border;
            public override Color MenuBorder => _p.Border;
            public override Color SeparatorDark => _p.Border;
            public override Color SeparatorLight => _p.Border;
            public override Color CheckBackground => _p.Selection;
            public override Color CheckSelectedBackground => _p.Selection;
            public override Color CheckPressedBackground => _p.Selection;
        }

        /// <summary>Menu text colors follow the theme (the renderer draws item text; dynamic items such as recent cases included).</summary>
        public static void StyleMenuItems(ToolStripItemCollection items)
        {
            foreach (ToolStripItem item in items)
            {
                item.ForeColor = Palette?.Text ?? SystemColors.ControlText;
                if (item is ToolStripDropDownItem d) StyleMenuItems(d.DropDownItems);
            }
        }

        /// <summary>How a theme setting is named in the menu and Settings.</summary>
        public static string DisplayName(string theme) =>
            theme == ConsoleSettings.ThemeWindows ? "Follow Windows"
            : theme == ConsoleSettings.ThemeSolarizedDark ? "Solarized Dark"
            : theme == ConsoleSettings.ThemeSolarizedLight ? "Solarized Light"
            : theme;

        /// <summary>
        /// The palette a theme setting shows now: none with Windows High Contrast on (Windows' colors win) or for Light,
        /// Dark or none for Follow Windows, else the named palette.
        /// </summary>
        public static Palette? PaletteFor(string theme)
        {
            if (SystemInformation.HighContrast) return null;
            if (theme == ConsoleSettings.ThemeWindows) return WindowsPrefersDark() ? Foton.Win.Ui.Palette.Dark : null;
            return Foton.Win.Ui.Palette.Find(theme);
        }

        /// <summary>Whether Windows is set to dark mode for apps (HKCU, the workstation's own preference; light when unknown).</summary>
        public static bool WindowsPrefersDark()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                    return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException || ex is UnauthorizedAccessException || ex is System.IO.IOException) { return false; }
        }
    }
}
