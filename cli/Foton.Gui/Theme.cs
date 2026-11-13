using System;
using System.Collections.Generic;
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
            public bool InheritsBack, InheritsFore;
            public FlatStyle? Flat;
            public DataGridViewCellStyle? Cells, Headers;
            public Color GridBack, GridLines;
            public bool HeaderVisualStyles;
            public TabDrawMode? TabDraw;
            public Color? TreeLines;
            public ToolStripRenderer? Renderer;
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
            SetFont(form);
            Walk(form);
            Watch(form);
        }

        /// <summary>Themes controls as they are added anywhere under <paramref name="root"/> (checklist labels, rebuilt panels).</summary>
        public static void Watch(Control root)
        {
            root.ControlAdded += (s, e) => { Walk(e.Control); Watch(e.Control); };
            foreach (Control c in root.Controls) Watch(c);
        }

        /// <summary>A new font only when the size changes; the replaced one is disposed (children use the form's, never their own copy).</summary>
        static void SetFont(Form form)
        {
            if (Math.Abs(form.Font.Size - TextSize) < 0.01f) return;
            var old = form.Font;
            form.Font = new Font("Segoe UI", TextSize);
            if (!ReferenceEquals(old, Control.DefaultFont)) old.Dispose();
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
            var parent = c.Parent;
            o = new Original
            {
                Back = c.BackColor, Fore = c.ForeColor,
                // Colors equal to the parent's current ones came from it (WinForms ambient colors): leave them to follow it.
                // Input controls and buttons have their own defaults even when they match.
                // A tab page paints its own background (its parent's color is not drawn), so it always gets one.
                InheritsBack = parent != null && c.BackColor == parent.BackColor && !(c is TextBoxBase) && !(c is ListControl) && !(c is TreeView) && !(c is ButtonBase) && !(c is UpDownBase) && !(c is TabPage),
                InheritsFore = parent != null && c.ForeColor == parent.ForeColor,
            };
            if (c is ButtonBase b) o.Flat = b.FlatStyle;
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

            if (!o.InheritsBack)
            {
                c.BackColor = !Dark ? o.Back
                    : o.Back == SystemColors.Info ? InfoBack
                    : c is TextBoxBase || c is ListControl || c is TreeView || c is UpDownBase ? Field
                    : c is ButtonBase && !(c is CheckBox) && !(c is RadioButton) ? ButtonBack
                    : Back;
            }
            if (!o.InheritsFore) c.ForeColor = Dark ? DarkFore(o.Fore) : o.Fore;

            switch (c)
            {
                case CheckBox _:
                case RadioButton _:
                    break;
                case ButtonBase b:
                    b.FlatStyle = Dark ? FlatStyle.Flat : o.Flat ?? FlatStyle.Standard;
                    if (Dark) b.FlatAppearance.BorderColor = Border;
                    if (!Dark && b is Button button) button.UseVisualStyleBackColor = true;
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

        static readonly HashSet<TabControl> OwnerDrawn = new HashSet<TabControl>();

        /// <summary>Dark tab headers are drawn here; the strip beside the last tab keeps Windows' color.</summary>
        static void StyleTabs(TabControl t, Original o)
        {
            if (OwnerDrawn.Add(t))
                t.DrawItem += (s, e) =>
                {
                    var page = t.TabPages[e.Index];
                    var selected = e.Index == t.SelectedIndex;
                    using (var back = new SolidBrush(selected ? Header : Back)) e.Graphics.FillRectangle(back, e.Bounds);
                    TextRenderer.DrawText(e.Graphics, page.Text, t.Font, e.Bounds, selected ? Color.White : Gray,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
                };
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
