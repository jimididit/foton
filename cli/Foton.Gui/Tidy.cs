using System.Drawing;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>
    /// One spacing and border style for every window, applied after it is built: tab pages get an even inner margin,
    /// button bars start flush with the panes below them, and every scrolling pane (grids, lists, trees, text) has the
    /// same thin border, so panes side by side line up. Run before the theme, which then colors the result.
    /// </summary>
    static class Tidy
    {
        const int PageMargin = 6;

        public static void Apply(Control root)
        {
            switch (root)
            {
                case TabPage page:
                    page.Padding = new Padding(PageMargin);
                    break;
                // Bars docked to an edge: no inset of their own, first item flush with the panes. The tinted Start here
                // strip keeps its padding (its color is the frame).
                case FlowLayoutPanel bar when (bar.Dock == DockStyle.Top || bar.Dock == DockStyle.Bottom) && bar.BackColor != SystemColors.Info:
                    bar.Padding = new Padding(0, 2, 0, 2);
                    if (bar.Controls.Count > 0)
                    {
                        var first = bar.Controls[0];
                        first.Margin = new Padding(0, first.Margin.Top, first.Margin.Right, first.Margin.Bottom);
                    }
                    break;
                case DataGridView grid:
                    grid.BorderStyle = BorderStyle.FixedSingle;
                    grid.BackgroundColor = SystemColors.Window;   // not the default dark-gray workspace behind an empty grid
                    break;
                case TextBoxBase box:
                    if (box.BorderStyle == BorderStyle.Fixed3D) box.BorderStyle = BorderStyle.FixedSingle;
                    // Read-only reading panes (details, log, JSON) match the lists beside them, not a disabled field's gray.
                    if (box.Multiline && box.ReadOnly) box.BackColor = SystemColors.Window;
                    break;
                case TreeView tree when tree.BorderStyle == BorderStyle.Fixed3D:
                    tree.BorderStyle = BorderStyle.FixedSingle;
                    break;
                case ListBox list when list.BorderStyle == BorderStyle.Fixed3D:
                    list.BorderStyle = BorderStyle.FixedSingle;
                    break;
            }
            foreach (Control child in root.Controls) Apply(child);
        }
    }
}
