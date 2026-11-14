using System.Drawing;
using System.Linq;
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
            TabOrder(root);
            foreach (Control child in root.Controls) Apply(child);
        }

        /// <summary>
        /// For grids whose columns fit their content: the last visible column takes whatever width is left, so a wide or
        /// maximized window has no empty band to the right of the columns. It never gets narrower than its own content
        /// (up to <paramref name="maxContent"/> pixels), so a narrow window scrolls sideways instead of cutting values off.
        /// Call after each bind: the columns are new every time the data source is set.
        /// </summary>
        public static void FillLastColumn(DataGridView grid, int maxContent = 400)
        {
            var last = grid.Columns.Cast<DataGridViewColumn>().Where(c => c.Visible).OrderBy(c => c.DisplayIndex).LastOrDefault();
            if (last == null) return;
            last.AutoSizeMode = DataGridViewAutoSizeColumnMode.NotSet;
            // All cells, not displayed ones: a grid on a tab not yet shown has no displayed rows to measure.
            var content = last.GetPreferredWidth(DataGridViewAutoSizeColumnMode.AllCells, true);
            last.MinimumWidth = System.Math.Max(40, System.Math.Min(content, maxContent));
            last.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        }

        /// <summary>
        /// The Tab key follows the screen, top to bottom and left to right. WinForms orders it by when controls were
        /// added, and docked bars are added after the pane they sit above (the last docked control is the outermost),
        /// so without this Tab would go from the grid up through the bars above it.
        /// </summary>
        static void TabOrder(Control container)
        {
            // Flow panels already order by position; split containers and tab controls hold fixed panes and pages.
            if (container is FlowLayoutPanel || container is TableLayoutPanel || container is SplitContainer || container is TabControl) return;
            var kids = container.Controls.Cast<Control>().Select((c, i) => new { c, i }).ToList();
            if (kids.Count < 2) return;
            int Side(DockStyle d) => d == DockStyle.Top ? 0 : d == DockStyle.Left ? 1 : d == DockStyle.Right ? 3 : d == DockStyle.Bottom ? 4 : 2;
            // Within a side the outermost control (added last for Top and Left) comes first; Fill and undocked
            // controls by their position.
            var ordered = kids
                .OrderBy(k => Side(k.c.Dock))
                .ThenBy(k => k.c.Dock == DockStyle.Top || k.c.Dock == DockStyle.Left ? -k.i : k.c.Dock == DockStyle.None ? k.c.Top : k.i)
                .ThenBy(k => k.c.Left)
                .ToList();
            for (int n = 0; n < ordered.Count; n++) ordered[n].c.TabIndex = n;
        }
    }
}
