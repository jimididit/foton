using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>
    /// Small reading aids for grids: what to do when a grid is empty, and severity shown by color as well as by its word
    /// (never color alone). Colors come from the theme, so they keep its contrast.
    /// </summary>
    static class Cues
    {
        /// <summary>
        /// Shows <paramref name="text"/> in an empty grid (null shows nothing): the next thing to do, instead of a blank
        /// area. Asked again on every paint, so it follows the window's state.
        /// </summary>
        public static void EmptyText(DataGridView grid, Func<string?> text)
        {
            grid.Paint += (s, e) =>
            {
                if (grid.Rows.Count > 0) return;
                var message = text();
                if (string.IsNullOrEmpty(message)) return;
                var top = grid.ColumnHeadersVisible ? grid.ColumnHeadersHeight : 0;
                var area = new Rectangle(16, top + 16, Math.Max(0, grid.ClientSize.Width - 32), Math.Max(0, grid.ClientSize.Height - top - 32));
                TextRenderer.DrawText(e.Graphics, message, grid.Font, area, Theme.MutedText,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix);
            };
            grid.DataSourceChanged += (s, e) => grid.Invalidate();
            grid.RowsRemoved += (s, e) => grid.Invalidate();
            grid.Resize += (s, e) => grid.Invalidate();
        }

        static readonly Dictionary<Font, Font> BoldOf = new Dictionary<Font, Font>();

        /// <summary>The Severity column of a findings grid in the theme's bad (High, bold), warning (Medium), and muted (Info) colors.</summary>
        public static void Severity(DataGridView grid)
        {
            grid.CellFormatting += (s, e) =>
            {
                if (e.RowIndex < 0 || e.ColumnIndex < 0 || grid.Columns[e.ColumnIndex].Name != "Severity" || e.CellStyle == null) return;
                var p = Theme.Palette;
                switch (Convert.ToString(e.Value, System.Globalization.CultureInfo.InvariantCulture))
                {
                    case "High":
                        e.CellStyle.ForeColor = p?.Bad ?? Color.DarkRed;
                        var font = e.CellStyle.Font ?? grid.Font;
                        if (!BoldOf.TryGetValue(font, out var bold)) BoldOf[font] = bold = new Font(font, FontStyle.Bold);
                        e.CellStyle.Font = bold;
                        break;
                    case "Medium":
                        e.CellStyle.ForeColor = p?.Warn ?? Color.FromArgb(0x8A, 0x53, 0x00);
                        break;
                    case "Info":
                        e.CellStyle.ForeColor = Theme.MutedText;
                        break;
                }
            };
        }
    }
}
