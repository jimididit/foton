using System.Drawing;
using System.Windows.Forms;
using Foton.Win.Ui;

namespace Foton.Gui
{
    /// <summary>
    /// A tab control that, with a palette, paints its whole header strip and page frame: flat tabs, the selected one on
    /// the page's surface with an accent underline, hover feedback, and the keyboard focus cue. With no palette (Light,
    /// High Contrast) Windows draws it as usual. Tab switching, keyboard, and accessibility stay the TabControl's own.
    /// </summary>
    sealed class ThemedTabs : TabControl
    {
        Palette? _palette;
        int _hot = -1;

        public Palette? Palette
        {
            get => _palette;
            set
            {
                if (ReferenceEquals(_palette, value)) return;
                _palette = value;
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, value != null);
                UpdateStyles();
                Invalidate();
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var p = _palette;
            if (p == null) { base.OnPaint(e); return; }
            var g = e.Graphics;
            using (var back = new SolidBrush(p.Back)) g.FillRectangle(back, ClientRectangle);
            var top = TabCount > 0 ? GetTabRect(0).Bottom : 0;
            var frame = new Rectangle(0, top, Width - 1, Height - top - 1);
            using (var surface = new SolidBrush(p.Surface)) g.FillRectangle(surface, frame);
            using (var border = new Pen(p.Border)) g.DrawRectangle(border, frame);

            for (int i = 0; i < TabCount; i++)
            {
                var r = GetTabRect(i);
                var selected = i == SelectedIndex;
                var fill = selected ? p.Surface : i == _hot ? p.Hover : p.Back;
                using (var b = new SolidBrush(fill)) g.FillRectangle(b, r);
                TextRenderer.DrawText(g, TabPages[i].Text, Font, r, selected || i == _hot ? p.Text : p.Muted,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
                if (selected)
                {
                    using (var accent = new SolidBrush(p.Accent)) g.FillRectangle(accent, r.X, r.Bottom - 3, r.Width, 3);
                    // Keyboard focus stays visible on painted tabs, as Windows shows it on its own.
                    if (Focused && ShowFocusCues)
                    {
                        var f = r;
                        f.Inflate(-3, -3);
                        f.Height -= 2;
                        ControlPaint.DrawFocusRectangle(g, f, p.Text, fill);
                    }
                }
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_palette == null) return;
            var hot = -1;
            for (int i = 0; i < TabCount; i++) if (GetTabRect(i).Contains(e.Location)) { hot = i; break; }
            if (hot != _hot) { _hot = hot; Invalidate(); }
        }

        protected override void OnMouseLeave(System.EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hot != -1) { _hot = -1; Invalidate(); }
        }

        protected override void OnGotFocus(System.EventArgs e) { base.OnGotFocus(e); Invalidate(); }
        protected override void OnLostFocus(System.EventArgs e) { base.OnLostFocus(e); Invalidate(); }
    }
}
