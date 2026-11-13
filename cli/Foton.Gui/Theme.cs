using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>
    /// The console's Light and Dark themes and text size, in managed code only: the console may not use native calls
    /// (they live in Foton.Win, which the console never references), so the title bar, scrollbars, and check boxes keep
    /// Windows' light drawing, as do message boxes and the file and folder dialogs. Each control's original colors are
    /// remembered the first time it is themed, so Light restores exactly what the control had. A control that took its
    /// colors from its parent keeps following the parent. To theme a new kind of control, add it to Style.
    /// </summary>
    static class Theme
    {
        public static bool Dark { get; private set; }
        public static float TextSize { get; private set; } = 9f;

        static readonly Color Back = Color.FromArgb(32, 32, 32);
        static readonly Color Field = Color.FromArgb(24, 24, 24);
        static readonly Color ButtonBack = Color.FromArgb(55, 55, 55);
        static readonly Color ButtonHover = Color.FromArgb(72, 72, 72);
        static readonly Color ButtonPressed = Color.FromArgb(40, 40, 40);
        static readonly Color Text = Color.FromArgb(232, 232, 232);
        static readonly Color Gray = Color.FromArgb(160, 160, 160);
        static readonly Color Border = Color.FromArgb(80, 80, 80);
        static readonly Color Header = Color.FromArgb(48, 48, 50);
        static readonly Color Grid = Color.FromArgb(64, 64, 64);
        static readonly Color Selection = Color.FromArgb(0, 92, 170);
        static readonly Color InfoBack = Color.FromArgb(56, 50, 28);
        static readonly Color Good = Color.FromArgb(128, 208, 128);
        static readonly Color Bad = Color.FromArgb(240, 128, 128);

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
        static readonly ToolStripProfessionalRenderer DarkRenderer = new ToolStripProfessionalRenderer(new DarkStripColors()) { RoundedEdges = false };

        /// <summary>Sets the theme and size, then themes <paramref name="root"/> and everything under it.</summary>
        public static void Apply(Control root, bool dark, float textSize)
        {
            Dark = dark;
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

        static Color DarkFore(Color original) =>
            original == SystemColors.GrayText ? Gray
            : original == Color.DarkGreen ? Good
            : original == Color.DarkRed ? Bad
            : Text;

        static void Style(Control c)
        {
            var o = Remember(c);
            if (c is Form f) SetFont(f);

            var field = c is TextBoxBase || c is ListControl || c is TreeView || c is UpDownBase;
            var pushButton = c is ButtonBase && !(c is CheckBox) && !(c is RadioButton);
            if (!Dark)
            {
                if (o.BackSet) c.BackColor = o.Back; else c.ResetBackColor();
                if (o.ForeSet) c.ForeColor = o.Fore; else c.ResetForeColor();
            }
            else
            {
                // Surfaces that paint themselves get dark colors; everything else (panels, labels, check boxes) follows
                // its parent, as it did in Light.
                if (o.BackSet || field || pushButton || c is Form || c is TabPage)
                    c.BackColor = o.BackSet && o.Back == SystemColors.Info ? InfoBack : field ? Field : pushButton ? ButtonBack : Back;
                if (o.ForeSet || field || c is Form) c.ForeColor = o.ForeSet ? DarkFore(o.Fore) : Text;
            }

            switch (c)
            {
                case CheckBox _:
                case RadioButton _:
                    break;
                case ButtonBase b:
                    b.FlatStyle = Dark ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    if (Dark)
                    {
                        // Hover and pressed feedback, which flat buttons do not draw by themselves.
                        b.FlatAppearance.BorderColor = Border;
                        b.FlatAppearance.MouseOverBackColor = ButtonHover;
                        b.FlatAppearance.MouseDownBackColor = ButtonPressed;
                    }
                    if (!Dark) b.UseVisualStyleBackColor = o.VisualStyleBack ?? true;   // as the button had it
                    break;
                case ComboBox cb:
                    cb.FlatStyle = Dark ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    break;
                case DataGridView g:
                    StyleGrid(g, o);
                    break;
                case TabControl t:
                    StyleTabs(t, o);
                    break;
                case TabPage page:
                    page.UseVisualStyleBackColor = !Dark;
                    break;
                case TreeView tv:
                    tv.LineColor = Dark ? Gray : o.TreeLines ?? SystemColors.ControlText;
                    break;
                case ToolStrip strip:
                    if (Dark) strip.Renderer = DarkRenderer;
                    else if (o.Renderer != null) strip.Renderer = o.Renderer;   // the strip's own renderer, as it was
                    break;
            }
        }

        static void StyleGrid(DataGridView g, Original o)
        {
            if (!Dark)
            {
                g.BackgroundColor = o.GridBack;
                g.GridColor = o.GridLines;
                g.EnableHeadersVisualStyles = o.HeaderVisualStyles;
                g.DefaultCellStyle = new DataGridViewCellStyle(o.Cells!);
                g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle(o.Headers!);
                return;
            }
            g.BackgroundColor = Back;
            g.GridColor = Grid;
            g.EnableHeadersVisualStyles = false;
            var cells = new DataGridViewCellStyle(o.Cells!) { BackColor = Field, ForeColor = Text, SelectionBackColor = Selection, SelectionForeColor = Color.White };
            g.DefaultCellStyle = cells;
            g.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle(o.Headers!) { BackColor = Header, ForeColor = Text, SelectionBackColor = Header, SelectionForeColor = Text };
        }

        /// <summary>Tab controls given the header painter (weak: a closed dialog's tabs are not kept alive).</summary>
        static readonly ConditionalWeakTable<TabControl, object> OwnerDrawn = new ConditionalWeakTable<TabControl, object>();

        /// <summary>Dark tab headers are drawn here; the strip beside the last tab keeps Windows' color.</summary>
        static void StyleTabs(TabControl t, Original o)
        {
            if (!OwnerDrawn.TryGetValue(t, out _))
            {
                OwnerDrawn.Add(t, new object());
                t.DrawItem += (s, e) =>
                {
                    var page = t.TabPages[e.Index];
                    var selected = e.Index == t.SelectedIndex;
                    using (var back = new SolidBrush(selected ? Header : Back)) e.Graphics.FillRectangle(back, e.Bounds);
                    TextRenderer.DrawText(e.Graphics, page.Text, t.Font, e.Bounds, selected ? Color.White : Gray,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
                    // Keyboard focus stays visible on hand-drawn tabs, as Windows shows it on its own.
                    if (selected && t.Focused)
                    {
                        var r = e.Bounds;
                        r.Inflate(-3, -3);
                        ControlPaint.DrawFocusRectangle(e.Graphics, r, Color.White, Header);
                    }
                };
            }
            t.DrawMode = Dark ? TabDrawMode.OwnerDrawFixed : o.TabDraw ?? TabDrawMode.Normal;
            t.Invalidate();
        }

        sealed class DarkStripColors : ProfessionalColorTable
        {
            public override Color MenuStripGradientBegin => Back;
            public override Color MenuStripGradientEnd => Back;
            public override Color StatusStripGradientBegin => Back;
            public override Color StatusStripGradientEnd => Back;
            public override Color ToolStripDropDownBackground => Header;
            public override Color ImageMarginGradientBegin => Header;
            public override Color ImageMarginGradientMiddle => Header;
            public override Color ImageMarginGradientEnd => Header;
            public override Color MenuItemSelected => Selection;
            public override Color MenuItemSelectedGradientBegin => Selection;
            public override Color MenuItemSelectedGradientEnd => Selection;
            public override Color MenuItemPressedGradientBegin => Header;
            public override Color MenuItemPressedGradientEnd => Header;
            public override Color MenuItemBorder => Selection;
            public override Color MenuBorder => Border;
            public override Color SeparatorDark => Border;
            public override Color SeparatorLight => Border;
            public override Color CheckBackground => Selection;
            public override Color CheckSelectedBackground => Selection;
        }

        /// <summary>Menu text colors follow the theme (the renderer draws item text; dynamic items such as recent cases included).</summary>
        public static void StyleMenuItems(ToolStripItemCollection items)
        {
            foreach (ToolStripItem item in items)
            {
                item.ForeColor = Dark ? Text : SystemColors.ControlText;
                if (item is ToolStripDropDownItem d) StyleMenuItems(d.DropDownItems);
            }
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
