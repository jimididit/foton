using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools;

namespace Foton.Gui
{
    /// <summary>
    /// The menu bar (File, View, Tools, Help), keyboard shortcuts, recent cases, About, and applying the console's
    /// settings (Tools > Settings). To add a command, add a menu item here; a ShortcutKeys value makes it a shortcut.
    /// </summary>
    sealed partial class MainForm
    {
        readonly ToolStripMenuItem _recentMenu = new ToolStripMenuItem("&Recent cases");
        readonly ToolStripMenuItem _themeMenu = new ToolStripMenuItem("&Theme");
        readonly ToolStripMenuItem _sizeMenu = new ToolStripMenuItem("Text &size");
        MenuStrip? _menu;
        System.Drawing.Font? _logFont;
        StatusStrip? _statusStrip;

        MenuStrip MenuBar()
        {
            var menu = new MenuStrip();
            ToolStripMenuItem Item(string text, Keys keys, Action click)
            {
                var i = new ToolStripMenuItem(text) { ShortcutKeys = keys };
                i.Click += (s, e) => click();
                return i;
            }

            var file = new ToolStripMenuItem("&File");
            file.DropDownItems.Add(Item("&Open case folder...", Keys.Control | Keys.O, () => _ = OpenFromMenu(PickFolder)));
            file.DropDownItems.Add(Item("Open &ZIP...", Keys.Control | Keys.Shift | Keys.O, () => _ = OpenFromMenu(PickZip)));
            file.DropDownItems.Add(_recentMenu);
            _recentMenu.DropDownOpening += (s, e) => FillRecentMenu();
            _recentMenu.DropDownItems.Add("(none)");   // a submenu needs an item to open; filled on opening
            file.DropDownItems.Add(new ToolStripSeparator());
            var exit = Item("E&xit", Keys.None, Close);
            exit.ShortcutKeyDisplayString = "Alt+F4";   // Windows already closes the window on Alt+F4
            file.DropDownItems.Add(exit);

            var view = new ToolStripMenuItem("&View");
            view.DropDownItems.Add(Item("&Find", Keys.Control | Keys.F, FocusFind));
            view.DropDownItems.Add(Item("&Refresh", Keys.F5, () => _ = RefreshCurrentTab()));
            view.DropDownItems.Add(new ToolStripSeparator());
            foreach (var t in new[] { ConsoleSettings.ThemeLight, ConsoleSettings.ThemeDark, ConsoleSettings.ThemeWindows })
            {
                var theme = t;
                _themeMenu.DropDownItems.Add(Item(theme == ConsoleSettings.ThemeWindows ? "&Follow Windows" : "&" + theme, Keys.None, () => { _settings.Theme = theme; SaveSettings(); ApplyAppearance(); }));
            }
            foreach (var size in ConsoleSettings.TextSizes)
            {
                var s = size;
                _sizeMenu.DropDownItems.Add(Item(s + " pt" + (s == 9 ? " (standard)" : ""), Keys.None, () => { _settings.TextSize = s; SaveSettings(); ApplyAppearance(); }));
            }
            view.DropDownItems.Add(_themeMenu);
            view.DropDownItems.Add(_sizeMenu);
            view.DropDownItems.Add(new ToolStripSeparator());
            var keys = new[] { Keys.D1, Keys.D2, Keys.D3, Keys.D4, Keys.D5, Keys.D6, Keys.D7, Keys.D8, Keys.D9, Keys.D0 };
            for (int t = 0; t < _tabs.TabPages.Count && t < keys.Length; t++)
            {
                var page = _tabs.TabPages[t];
                view.DropDownItems.Add(Item(page.Text + " tab", Keys.Control | keys[t], () => _tabs.SelectedTab = page));
            }

            var tools = new ToolStripMenuItem("&Tools");
            tools.DropDownItems.Add(Item("&Settings...", Keys.Control | Keys.Oemcomma, OpenSettings));
            tools.DropDownItems.Add(new ToolStripSeparator());
            tools.DropDownItems.Add(Item("Install or register tools (Tools tab)", Keys.None, () => SelectTab("Tools")));
            tools.DropDownItems.Add(Item("Build a collection profile (Profile tab)", Keys.None, () => SelectTab("Profile")));

            var help = new ToolStripMenuItem("&Help");
            help.DropDownItems.Add(Item("&Keyboard shortcuts", Keys.None, ShowShortcuts));
            help.DropDownItems.Add(Item("&About Foton console", Keys.None, ShowAbout));

            menu.Items.AddRange(new ToolStripItem[] { file, view, tools, help });
            _menu = menu;
            return menu;
        }

        /// <summary>Applies the theme (Light, Dark, or Windows' app setting) and text size from the settings to the whole window.</summary>
        void ApplyAppearance()
        {
            var dark = _settings.Theme == ConsoleSettings.ThemeDark || (_settings.Theme == ConsoleSettings.ThemeWindows && Theme.WindowsPrefersDark());
            SuspendLayout();
            Theme.Apply(this, dark, _settings.TextSize);
            if (Math.Abs(_log.Font.Size - _settings.TextSize) > 0.01f)
            {
                // Only a font made here is disposed; the log's first font belongs to its construction.
                var font = new System.Drawing.Font(System.Drawing.FontFamily.GenericMonospace, _settings.TextSize);
                _log.Font = font;
                _logFont?.Dispose();
                _logFont = font;
            }
            if (_menu != null) Theme.StyleMenuItems(_menu.Items);
            if (_statusStrip != null) Theme.StyleMenuItems(_statusStrip.Items);
            foreach (ToolStripMenuItem i in _themeMenu.DropDownItems)
                i.Checked = i.Text.Replace("&", "").StartsWith(_settings.Theme == ConsoleSettings.ThemeWindows ? "Follow" : _settings.Theme, StringComparison.Ordinal);
            foreach (ToolStripMenuItem i in _sizeMenu.DropDownItems)
                i.Checked = i.Text.StartsWith(_settings.TextSize + " pt", StringComparison.Ordinal);
            ResumeLayout(true);
        }

        /// <summary>Follow Windows: re-applied when Windows' light/dark setting changes while the console is open.</summary>
        void OnWindowsPreferenceChanged(object sender, Microsoft.Win32.UserPreferenceChangedEventArgs e)
        {
            if (_settings.Theme != ConsoleSettings.ThemeWindows || IsDisposed || !IsHandleCreated) return;
            // The window can close between the check and the call (this event arrives on another thread).
            try { BeginInvoke(new Action(() => { if (!IsDisposed) ApplyAppearance(); })); }
            catch (Exception ex) when (ex is InvalidOperationException || ex is ObjectDisposedException) { }
        }

        void SelectTab(string text)
        {
            var page = _tabs.TabPages.Cast<TabPage>().FirstOrDefault(p => p.Text == text);
            if (page != null) _tabs.SelectedTab = page;
        }

        async Task OpenFromMenu(Func<string?> pick)
        {
            if (_busy) { _status.Text = "Wait for the current action to finish."; return; }
            var path = pick();
            if (path == null) return;
            if (_packagePage != null) _tabs.SelectedTab = _packagePage;
            await Open(path);
        }

        void FillRecentMenu()
        {
            _recentMenu.DropDownItems.Clear();
            if (_settings.RecentCases.Count == 0) { _recentMenu.DropDownItems.Add(new ToolStripMenuItem("(none)") { Enabled = false }); return; }
            foreach (var path in _settings.RecentCases)
            {
                var exists = Directory.Exists(path) || File.Exists(path);
                var item = new ToolStripMenuItem(path.Replace("&", "&&") + (exists ? "" : "  (not found)")) { Enabled = exists };
                item.Click += async (s, e) => { if (_busy) return; if (_packagePage != null) _tabs.SelectedTab = _packagePage; await Open(path); };
                _recentMenu.DropDownItems.Add(item);
            }
            Theme.StyleMenuItems(_recentMenu.DropDownItems);
        }

        /// <summary>Ctrl+F: the find or filter box of the tab on screen.</summary>
        void FocusFind()
        {
            var tab = _tabs.SelectedTab;
            if (tab == _packagePage) _findingsFind.Focus();
            else if (tab == _viewer.Page) _viewer.FocusFind();
            else if (tab == _timelinePage) _timelineFind.Focus();
            else if (tab?.Text == "Search") _searchText.Focus();
            else _status.Text = "This tab has no find box.";
        }

        /// <summary>F5: reread what the tab on screen shows.</summary>
        Task RefreshCurrentTab()
        {
            if (_busy) return Task.FromResult(0);
            var tab = _tabs.SelectedTab;
            if (tab == _casesPage) return RefreshCases();
            if (tab == _notesPage) return RefreshNotes();
            if (tab == _timelinePage) return ApplyTimelineFilter();
            if ((tab == _packagePage || tab == _viewer.Page) && _caseRoot != null) return Open(_path.Text);
            return Task.FromResult(0);
        }

        void OpenSettings()
        {
            using (var d = new SettingsDialog(_settings))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
            }
            SaveSettings();
            ApplySettings();
            ApplyAppearance();
            if (!_busy) _ = RefreshCases();
            _status.Text = "Settings saved.";
        }

        /// <summary>Puts the settings into the tabs that use them (output folders, examiner, case folder list).</summary>
        void ApplySettings()
        {
            _caseOutput.Text = _settings.CasesFolder;
            _baselineOutput.Text = _settings.BaselinesFolder;
            if (_settings.Examiner.Length > 0) _examiner.Text = _settings.Examiner;
            FillAddedFolders();
        }

        void ShowShortcuts() => MessageBox.Show(this,
            "Ctrl+O            Open a case folder\r\n" +
            "Ctrl+Shift+O      Open a ZIP\r\n" +
            "Ctrl+F            Find on this tab\r\n" +
            "F5                Refresh this tab\r\n" +
            "Ctrl+1 ... Ctrl+0 Go to a tab (in tab order)\r\n" +
            "Ctrl+,            Settings\r\n" +
            "Alt+F4            Exit",
            "Keyboard shortcuts", MessageBoxButtons.OK, MessageBoxIcon.Information);

        void ShowAbout()
        {
            var exe = Application.ExecutablePath;
            string sha;
            try { sha = Hashing.Sha256Hex(exe).ToLowerInvariant(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { sha = "(could not be read: " + TextFile.OneLine(ex.Message) + ")"; }
            MessageBox.Show(this,
                string.Join("\r\n", FotonVersion.Describe("foton-console")) + "\r\n" +
                "Updated " + FotonVersion.ReleaseDate + " (UTC)\r\n\r\n" +
                exe + "\r\nSHA-256 " + sha + "\r\n\r\n" +
                "Not code-signed: compare this hash with SHA256SUMS.txt from the release.\r\n" +
                "Offline workstation console. It reads packages and runs foton-collect / foton-baseline as their own processes; it never collects in this window.",
                "About Foton console", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
