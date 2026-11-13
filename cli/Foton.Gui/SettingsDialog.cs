using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools;

namespace Foton.Gui
{
    /// <summary>
    /// Tools > Settings: the console's own preferences (never evidence, never in a package). Edits a copy; OK checks
    /// the folders and copies the values back. To add a setting, add its control to a tab here and to Apply, and the
    /// property to Foton.Tools.ConsoleSettings.
    /// </summary>
    sealed class SettingsDialog : Form
    {
        readonly ConsoleSettings _target;
        readonly TextBox _examiner = new TextBox { Width = 260, MaxLength = 200 };
        readonly ComboBox _openOnStart = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
        readonly NumericUpDown _recentCount = new NumericUpDown { Minimum = 0, Maximum = ConsoleSettings.MaxRecent, Width = 60 };
        readonly TextBox _casesOutput = new TextBox { Width = 420 };
        readonly TextBox _baselinesOutput = new TextBox { Width = 420 };
        readonly TextBox _handoffsOutput = new TextBox { Width = 420 };
        readonly TextBox _bundlesOutput = new TextBox { Width = 420 };
        readonly ListBox _caseFolders = new ListBox { Width = 420, Height = 120, HorizontalScrollbar = true };
        readonly ComboBox _theme = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };
        readonly ComboBox _textSize = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };
        bool _clearRecent;

        public SettingsDialog(ConsoleSettings settings)
        {
            _target = settings;
            Text = "Settings";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(640, 470);
            MinimumSize = new Size(560, 420);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            ShowIcon = false;
            MinimizeBox = MaximizeBox = false;

            _openOnStart.Items.AddRange(new object[] { "The Cases tab", "The last case opened" });
            _openOnStart.SelectedIndex = settings.OpenOnStart == ConsoleSettings.StartOnLastCase ? 1 : 0;
            _examiner.Text = settings.Examiner;
            _recentCount.Value = Math.Min(ConsoleSettings.MaxRecent, Math.Max(0, settings.RecentCount));
            _casesOutput.Text = settings.CasesOutput;
            _baselinesOutput.Text = settings.BaselinesOutput;
            _handoffsOutput.Text = settings.HandoffsOutput;
            _bundlesOutput.Text = settings.BundlesOutput;
            foreach (var f in settings.CaseFolders) _caseFolders.Items.Add(f);

            var tabs = new ThemedTabs { Dock = DockStyle.Fill };
            tabs.TabPages.Add(GeneralTab(settings));
            tabs.TabPages.Add(AppearanceTab(settings));
            tabs.TabPages.Add(FoldersTab());

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var ok = new Button { Text = "OK", AutoSize = true };
            ok.Click += (s, e) => { if (Apply()) { DialogResult = DialogResult.OK; Close(); } };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            AcceptButton = ok;
            CancelButton = cancel;
            Controls.Add(tabs);
            Controls.Add(buttons);
            Theme.Adopt(this);
        }

        TabPage AppearanceTab(ConsoleSettings settings)
        {
            var page = new TabPage("Appearance");
            var p = Page();
            foreach (var t in ConsoleSettings.Themes)
                _theme.Items.Add(t == ConsoleSettings.ThemeWindows ? "Follow Windows (Light or Dark, as Windows apps are set)" : Theme.DisplayName(t));
            _theme.SelectedIndex = Math.Max(0, Array.IndexOf(ConsoleSettings.Themes, settings.Theme));
            foreach (var size in ConsoleSettings.TextSizes) _textSize.Items.Add(size + " pt" + (size == 9 ? " (standard)" : ""));
            _textSize.SelectedIndex = Math.Max(0, Array.IndexOf(ConsoleSettings.TextSizes, settings.TextSize));
            p.Controls.Add(Row("Theme", _theme));
            p.Controls.Add(Hint("Light uses Windows' own colors. Dark is neutral; Campbell follows the Windows Terminal default; Solarized Dark and Light follow the Solarized scheme, adjusted so all text stays readable. With Windows High Contrast on, the console uses Windows' colors whatever is chosen. Message boxes and the open, save, and folder dialogs keep Windows' colors."));
            p.Controls.Add(Row("Text size", _textSize));
            p.Controls.Add(Hint("The size of the window's text. The View menu changes both at once, too."));
            page.Controls.Add(p);
            return page;
        }

        static FlowLayoutPanel Page() => new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(10) };

        static Control Row(string label, params Control[] inputs)
        {
            var r = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 6) };
            r.Controls.Add(new Label { Text = label, Width = 150, Padding = new Padding(0, 6, 0, 0) });
            foreach (var i in inputs) r.Controls.Add(i);
            return r;
        }

        static Label Hint(string text) => new Label { Text = text, AutoSize = true, MaximumSize = new Size(580, 0), ForeColor = SystemColors.GrayText, Margin = new Padding(0, 0, 0, 10) };

        TabPage GeneralTab(ConsoleSettings settings)
        {
            var page = new TabPage("General");
            var p = Page();
            p.Controls.Add(Row("Examiner", _examiner));
            p.Controls.Add(Hint("Filled in for examiner notes. Empty uses the examiner recorded in the case."));
            p.Controls.Add(Row("Open on start", _openOnStart));
            p.Controls.Add(Hint("A package given on the command line always opens instead."));
            var clear = new Button { Text = "Clear the list", AutoSize = true };
            clear.Click += (s, e) => { _clearRecent = true; clear.Enabled = false; clear.Text = "Cleared (on OK)"; };
            p.Controls.Add(Row("Recent cases", _recentCount, clear));
            p.Controls.Add(Hint($"How many recently opened cases File > Recent cases lists (0 keeps none). {settings.RecentCases.Count} listed now."));
            page.Controls.Add(p);
            return page;
        }

        TabPage FoldersTab()
        {
            var page = new TabPage("Folders");
            var p = Page();
            Button Browse(TextBox box, string what)
            {
                var b = new Button { Text = "Browse...", AutoSize = true };
                b.Click += (s, e) =>
                {
                    using (var d = new FolderBrowserDialog { Description = "Choose the folder for " + what, ShowNewFolderButton = true })
                        if (d.ShowDialog(this) == DialogResult.OK) box.Text = d.SelectedPath;
                };
                return b;
            }
            p.Controls.Add(Row("Cases", _casesOutput, Browse(_casesOutput, "your cases")));
            p.Controls.Add(Row("Baselines", _baselinesOutput, Browse(_baselinesOutput, "your baselines")));
            p.Controls.Add(Row("Bundles", _bundlesOutput, Browse(_bundlesOutput, "collector bundles")));
            p.Controls.Add(Row("Handoffs", _handoffsOutput, Browse(_handoffsOutput, "handoffs")));
            p.Controls.Add(Hint($"Where you keep the cases and baselines collectors bring back (the Cases tab lists them), where the Collectors tab builds bundles, and where Export handoff writes. Empty uses {CaseTree.DefaultOutput("Cases")}, {CaseTree.DefaultOutput("Baselines")}, {CaseTree.DefaultOutput("Bundles")}, and {CaseTree.DefaultOutput("Handoffs")}."));
            var add = new Button { Text = "Add...", AutoSize = true };
            add.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = "Choose a folder that holds case or baseline packages", ShowNewFolderButton = false })
                    if (d.ShowDialog(this) == DialogResult.OK && !_caseFolders.Items.Cast<string>().Contains(d.SelectedPath, StringComparer.OrdinalIgnoreCase))
                        _caseFolders.Items.Add(d.SelectedPath);
            };
            var remove = new Button { Text = "Remove", AutoSize = true };
            remove.Click += (s, e) => { if (_caseFolders.SelectedIndex >= 0) _caseFolders.Items.RemoveAt(_caseFolders.SelectedIndex); };
            var side = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true };
            side.Controls.Add(add);
            side.Controls.Add(remove);
            p.Controls.Add(Row("Other case folders", _caseFolders, side));
            p.Controls.Add(Hint("More folders for the Cases tab to list (the same list as its Add folder and Remove folder)."));
            page.Controls.Add(p);
            return page;
        }

        /// <summary>Checks the folders and copies every value to the settings; false (with a message) keeps the dialog open.</summary>
        bool Apply()
        {
            string? Folder(TextBox box, string what)
            {
                var t = box.Text.Trim();
                if (t.Length == 0) return "";
                var full = ConsoleSettings.FullPath(t);
                if (full == null) MessageBox.Show(this, $"The {what} folder must be a full path, such as D:\\Cases or \\\\server\\share\\Cases.", "Settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return full;
            }
            var cases = Folder(_casesOutput, "cases");
            if (cases == null) return false;
            var baselines = Folder(_baselinesOutput, "baselines");
            if (baselines == null) return false;
            var handoffs = Folder(_handoffsOutput, "handoffs");
            if (handoffs == null) return false;
            var bundles = Folder(_bundlesOutput, "bundles");
            if (bundles == null) return false;

            _target.Examiner = TextFile.OneLine(_examiner.Text).Trim();
            _target.OpenOnStart = _openOnStart.SelectedIndex == 1 ? ConsoleSettings.StartOnLastCase : ConsoleSettings.StartOnCases;
            _target.RecentCount = (int)_recentCount.Value;
            if (_clearRecent) _target.RecentCases.Clear();
            _target.TrimRecent();
            _target.CasesOutput = cases;
            _target.BaselinesOutput = baselines;
            _target.HandoffsOutput = handoffs;
            _target.BundlesOutput = bundles;
            _target.CaseFolders.Clear();
            _target.CaseFolders.AddRange(_caseFolders.Items.Cast<string>());
            _target.Theme = ConsoleSettings.Themes[Math.Max(0, _theme.SelectedIndex)];
            _target.TextSize = ConsoleSettings.TextSizes[Math.Max(0, _textSize.SelectedIndex)];
            return true;
        }
    }
}
