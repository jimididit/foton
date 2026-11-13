using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Analyze;
using Foton.Core;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// The console window. Each action runs the same runner foton.exe runs, on a worker thread, with its StatusLog shown in
    /// the log pane. The console writes only where those runners write (analysis\, a ZIP's -extracted folder).
    /// To add a tab, build it in its own method and add it in the constructor.
    /// </summary>
    sealed partial class MainForm : Form
    {
        readonly TextBox _path = new TextBox { ReadOnly = true, Width = 640 };
        readonly Label _summary = new Label { AutoSize = true, Padding = new Padding(0, 6, 0, 0) };
        readonly DataGridView _findings = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };
        readonly TextBox _details = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true };
        readonly TextBox _log = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false };
        readonly ToolStripStatusLabel _status = new ToolStripStatusLabel("Ready") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        readonly ToolStripProgressBar _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false };
        readonly List<Control> _actions = new List<Control>();
        readonly TabControl _tabs = new ThemedTabs { Dock = DockStyle.Fill };
        readonly SplitContainer _outer = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, Panel2MinSize = 60 };
        readonly ViewerTab _viewer = new ViewerTab();
        /// <summary>One writer for the log pane, shared by every action (each action gets its own StatusLog over it).</summary>
        readonly LogWriter _logWriter;
        string? _caseRoot;
        bool _busy;
        readonly Dictionary<TabPage, string> _tabStatus = new Dictionary<TabPage, string>();
        bool _restoringStatus;
        /// <summary>The tab the running action was started from; null when nothing runs.</summary>
        TabPage? _statusOwner;

        public MainForm(string? openPath)
        {
            Text = "Foton console " + FotonVersion.Product;
            using (var icon = typeof(MainForm).Assembly.GetManifestResourceStream("Foton.Gui.foton.ico"))
                if (icon != null) Icon = new Icon(icon);
            Font = new Font("Segoe UI", 9f);
            Size = new Size(1280, 820);
            MinimumSize = new Size(900, 600);
            StartPosition = FormStartPosition.CenterScreen;
            _logWriter = new LogWriter(_log);

            _tabs.TabPages.Add(_casesPage = CasesTab());
            _tabs.TabPages.Add(_packagePage = PackageTab());
            _tabs.TabPages.Add(_viewer.Page);
            _tabs.TabPages.Add(_timelinePage = TimelineTab());
            _tabs.TabPages.Add(_notesPage = NotesTab());
            _tabs.TabPages.Add(SearchTab());
            _tabs.TabPages.Add(ToolsTab());
            _tabs.TabPages.Add(ProfileTab());
            _tabs.TabPages.Add(_comparePage = CompareTab());
            _tabs.TabPages.Add(_collectorsPage = CollectorsTab());
            // The log sits under every tab: an install or register is followed there as much as a parse. View > Show log
            // hides it; its height and visibility are remembered.
            var outer = _outer;
            outer.Panel1.Controls.Add(_tabs);
            outer.Panel2.Controls.Add(_log);
            outer.Panel2.Padding = new Padding(8, 2, 8, 4);   // lines the log up with the tab content above it
            Load += (s, e) => { SetSplit(outer, 1 - _settings.LogPercent / 100.0); outer.Panel2Collapsed = !_settings.ShowLog; _logMenu.Checked = _settings.ShowLog; };
            FormClosing += (s, e) => RememberLog();
            Controls.Add(outer);
            var strip = new StatusStrip();
            strip.Items.Add(_status);
            strip.Items.Add(_progress);
            Controls.Add(strip);
            _statusStrip = strip;
            var menu = MenuBar();   // after the tabs, which it lists
            Controls.Add(menu);
            MainMenuStrip = menu;
            ApplySettings();
            Tidy.Apply(this);
            Theme.Watch(this);
            ApplyAppearance();
            Microsoft.Win32.SystemEvents.UserPreferenceChanged += OnWindowsPreferenceChanged;
            FormClosed += (s, e) => Microsoft.Win32.SystemEvents.UserPreferenceChanged -= OnWindowsPreferenceChanged;

            FindingGrid(_findings, _details);
            EmptyStates();
            // Double-click a finding (or use Show artifact) to read its source artifact in the Viewer.
            _findings.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0) ShowArtifact(); };   // not on a header (that sorts)
            // A package on the command line opens in the Package tab; otherwise the window starts on Cases.
            // Settings can ask for the last case instead; a missing one falls back to Cases.
            var last = _settings.OpenOnStart == Foton.Tools.ConsoleSettings.StartOnLastCase ? _settings.RecentCases.FirstOrDefault() : null;
            if (openPath == null && last != null && (Directory.Exists(last) || File.Exists(last))) openPath = last;
            if (openPath != null) Shown += async (s, e) => { _tabs.SelectedTab = _packagePage; await Open(openPath); };
            else Shown += async (s, e) => await RefreshCases();
            // The list is cheap to re-read (no hashing), so it is current whenever the tab is shown.
            _tabs.Selected += async (s, e) => { if (e.TabPage == _casesPage && !_busy) await RefreshCases(); };
            // The status bar shows the tab on screen's last message, not another tab's (while an action runs, its own).
            // A running action's messages (its finish included) belong to the tab it was started from.
            _status.TextChanged += (s, e) => { var tab = _statusOwner ?? _tabs.SelectedTab; if (!_restoringStatus && tab != null) _tabStatus[tab] = _status.Text; };
            _tabs.Selected += (s, e) =>
            {
                if (_busy || e.TabPage == null) return;
                _restoringStatus = true;
                _status.Text = _tabStatus.TryGetValue(e.TabPage, out var text) ? text : "Ready";
                _restoringStatus = false;
            };
        }

        TabPage PackageTab()
        {
            var page = new TabPage("Package");
            var open = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(4) };
            open.Controls.Add(new Label { Text = "Package", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            open.Controls.Add(_path);
            open.Controls.Add(AddButton("Open folder...", async () => { var p = PickFolder(); if (p != null) await Open(p); }));
            open.Controls.Add(AddButton("Open ZIP...", async () => { var p = PickZip(); if (p != null) await Open(p); }));

            var actions = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            actions.Controls.Add(AddButton("Verify", VerifyOpenPackage, needsPackage: true));
            actions.Controls.Add(AddButton("Parse", () => Run("Parse", Parse), needsPackage: true));
            actions.Controls.Add(AddButton("Compose", () => Run("Compose", ComposeStep()), needsPackage: true));
            actions.Controls.Add(AddButton("Analyze", () => Run("Analyze", Analyze), needsPackage: true));
            actions.Controls.Add(AddButton("Parse, compose, analyze", () =>
            {
                var compose = ComposeStep();
                return Run("Parse, compose, analyze", (log, path) => { Parse(log, path); compose(log, path); return Analyze(log, path); });
            }, needsPackage: true));
            // Three groups, set apart: run the steps, match indicators, open what the package holds.
            var ioc = AddButton("Match IOCs...", MatchIocs, needsPackage: true);
            ioc.Margin = new Padding(18, ioc.Margin.Top, ioc.Margin.Right, ioc.Margin.Bottom);
            actions.Controls.Add(ioc);
            var show = AddButton("Show artifact", ShowArtifact, needsPackage: true);
            show.Margin = new Padding(18, show.Margin.Top, show.Margin.Right, show.Margin.Bottom);
            actions.Controls.Add(show);
            actions.Controls.Add(AddButton("Open report", OpenReport, needsPackage: true));
            actions.Controls.Add(AddButton("Show case folder", ShowFolder, needsPackage: true));
            _summary.Padding = new Padding(12, 6, 0, 0);
            actions.Controls.Add(_summary);

            var findingsSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            findingsSplit.Panel1.Controls.Add(_findings);
            findingsSplit.Panel2.Controls.Add(_details);
            findingsSplit.Panel2.Controls.Add(NoteEditor());
            // A splitter position is checked against the control's current size, so set it once the window has its real
            // size, as a share of it (any window size or display scaling).
            Load += (s, e) => SetSplit(findingsSplit, 0.68);

            page.Controls.Add(findingsSplit);
            // Above both panes, so the findings grid and the details beside it start at the same height.
            page.Controls.Add(FindingsFilterBar());
            page.Controls.Add(Checklist());
            page.Controls.Add(actions);
            page.Controls.Add(open);
            UpdateButtons();
            return page;
        }

        static void SetSplit(SplitContainer split, double share)
        {
            var extent = split.Orientation == Orientation.Vertical ? split.ClientSize.Width : split.ClientSize.Height;
            var max = extent - split.Panel2MinSize - split.SplitterWidth;
            if (max <= split.Panel1MinSize) return;
            split.SplitterDistance = Math.Max(split.Panel1MinSize, Math.Min(max, (int)(extent * share)));
        }

        Button AddButton(string text, Func<Task> click, bool needsPackage = false)
        {
            var b = new Button { Text = text, AutoSize = true, Tag = needsPackage };
            b.Click += async (s, e) => await click();
            _actions.Add(b);
            return b;
        }

        Button AddButton(string text, Action click, bool needsPackage = false) => AddButton(text, () => { click(); return Task.FromResult(0); }, needsPackage);

        void UpdateButtons()
        {
            foreach (var c in _actions)
                c.Enabled = !_busy && (!(c.Tag is bool needs && needs) || _caseRoot != null) && (_profile != null || !(c is Button b && _needsValidProfile.Contains(b)));
        }

        /// <summary>
        /// Runs one action on a worker thread with its own StatusLog; a failure is logged, never thrown at the operator.
        /// The package path is read here, on the UI thread, and handed to the work. True when the action ran to the end
        /// (false when it stopped with an error, or did not start because another action was running).
        /// </summary>
        Task<bool> Run(string label, Func<StatusLog, string, object?> work)
        {
            var path = _path.Text;
            return Run(label, log => work(log, path));
        }

        async Task<bool> Run(string label, Func<StatusLog, object?> work)
        {
            if (_busy) return false;
            var completed = false;
            _busy = true;
            _statusOwner = _tabs.SelectedTab;
            UpdateButtons();
            _status.Text = label + "...";
            _progress.Visible = true;
            var log = new StatusLog(_logWriter);
            log.WriteConsole("");
            log.WriteConsole("== " + label + " (" + FotonTime.Format(DateTime.UtcNow) + " UTC)");
            try
            {
                var result = await Task.Run(() => work(log));
                _status.Text = label + " finished";
                if (result is AnalysisRun run)
                {
                    ShowFindings(run.Findings.Select(FindingRow));
                    _status.Text += $" - {run.Findings.Count} finding(s)";
                    _report.Remember(run.ReportPath);
                }
                // Parse, compose, and analyze write new files into the package; show them in the Viewer. A failure here
                // is logged and never costs the results above.
                if (_caseRoot != null && label != "Open") RefreshViewer(_caseRoot, log);
                if (result is IocRun ioc)
                {
                    _status.Text += $" - {ioc.Hits.Count} match(es)";
                    _viewer.Select(Path.Combine("analysis", "ioc_matches.csv"));
                }
                completed = true;
            }
            catch (Exception ex)
            {
                log.Write(label + " stopped: " + ex.Message, StatusLevel.Error);
                _status.Text = label + " stopped: " + TextFile.OneLine(ex.Message) + (_outer.Panel2Collapsed ? " (Ctrl+L shows the log)" : "");
            }
            finally
            {
                _busy = false;
                _progress.Visible = false;
                UpdateButtons();
                RefreshChecklist();
                _statusOwner = null;
            }
            return completed;
        }

        async Task Open(string path)
        {
            _path.Text = path;
            _caseRoot = null;
            _report.Remember(null);
            ClearTimeline();
            LoadNotes(null);
            _notesGrid.DataSource = null;
            _notesSummary.Text = "";
            _searchHits.DataSource = null;
            _searchSummary.Text = "";
            ShowFindings(new List<Dictionary<string, string?>>());
            _details.Clear();
            _summary.Text = "";
            await Run("Open", log =>
            {
                var p = FotonPackage.Open(path);
                if (p.ZipNote != null) log.Write(p.ZipNote, StatusLevel.Info);
                log.Write($"Loaded {p.CaseRoot} ({p.Artifacts.Count} artifacts, {p.Manifest.Count} manifest rows)", StatusLevel.Good);
                var findings = ExistingFindings(p.CaseRoot);
                BeginInvoke(new Action(() =>
                {
                    _caseRoot = p.CaseRoot;
                    _summary.Text = $"{Path.GetFileName(p.CaseRoot)} - {p.Kind}, {p.Artifacts.Count} artifacts";
                    LoadNotes(p.CaseRoot);
                    ShowFindings(findings);
                    RefreshChecklist();
                    _settings.AddRecent(path);
                    SaveSettings();
                    RefreshViewer(p.CaseRoot, log);
                    UpdateButtons();
                }));
                return null;
            });
        }

        static object Verify(StatusLog log, string path)
        {
            var code = PackageCheck.Report(log, FotonPackage.Open(path));
            log.Write(code == 0 ? "Every file listed in hashes.csv matches." : "The package does not verify; see the lines above.", code == 0 ? StatusLevel.Good : StatusLevel.Warn);
            return code;
        }

        static object Parse(StatusLog log, string path) => Foton.Parse.ParseRunner.Run(path, log);

        static object Compose(StatusLog log, string path, IReadOnlyCollection<string>? onlyTools)
        {
            var run = Foton.Tools.ComposeRunner.Run(path, log, onlyTools: onlyTools);
            foreach (var r in run.Rows)
                log.WriteConsole($"   {r.Tool,-14} {(r.Version.Length > 0 ? r.Version : "-"),-12} {r.Status,-14} {(r.DestRelative.Length > 0 ? r.DestRelative : r.Note)}");
            log.Write("Inventory: " + run.InventoryPath, StatusLevel.Good);
            return run;
        }

        static object Analyze(StatusLog log, string path) => Analyzer.RunPackage(path, log, Foton.Patterns.WorkstationPatterns.SuspiciousCommands);

        /// <summary>foton ioc: match an indicator list (text, CSV, or JSON) against the package; hits go to analysis\ioc_matches.csv.</summary>
        async Task MatchIocs()
        {
            string iocFile;
            using (var d = new OpenFileDialog
            {
                Title = "Choose an IOC list",
                Filter = "IOC list (*.txt;*.csv;*.json)|*.txt;*.csv;*.json|All files (*.*)|*.*",
                CheckFileExists = true,
            })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                iocFile = d.FileName;
            }
            await Run("Match IOCs", (log, path) =>
            {
                var run = Analyzer.RunIoc(path, iocFile, log);
                foreach (var h in run.Hits.Take(50))
                    log.WriteConsole($"   {h.IocKind,-7} {h.IocValue}  ->  {h.Artifact}.{h.Property}: {TextFile.OneLine(h.Sample)}");
                if (run.Hits.Count > 50) log.WriteConsole($"   ... {run.Hits.Count - 50} more in the CSV");
                log.Write("Matches: " + run.HitsPath, StatusLevel.Good);
                return run;
            });
        }

        /// <summary>The latest findings in the package: a workstation analyze, else the ones Collect wrote.</summary>
        static List<Dictionary<string, string?>> ExistingFindings(string caseRoot)
        {
            foreach (var f in new[] { Path.Combine(caseRoot, "analysis", "findings.csv"), Path.Combine(caseRoot, CaseTree.CollectionFolder, "findings.csv") })
                if (File.Exists(f)) return Csv.Read(f);
            return new List<Dictionary<string, string?>>();
        }

        static Dictionary<string, string?> FindingRow(Finding f) => new Dictionary<string, string?>
        {
            ["Severity"] = f.Severity, ["Tier"] = f.Tier.ToString(System.Globalization.CultureInfo.InvariantCulture), ["Category"] = f.Category,
            ["Title"] = f.Title, ["Observation"] = f.Observation, ["WhyItMatters"] = f.WhyItMatters, ["Artifact"] = f.Artifact, ["NextStep"] = f.NextStep,
        };

        static readonly string[] SeverityOrder = { "High", "Medium", "Low", "Info" };

        /// <summary>Findings in a grid, most severe first; column layout is applied when binding completes (FindingGrid).</summary>
        static void ShowFindings(DataGridView grid, IEnumerable<Dictionary<string, string?>> rows)
        {
            string V(Dictionary<string, string?> r, string k) => r.TryGetValue(k, out var v) ? v ?? "" : "";
            var table = new System.Data.DataTable();
            foreach (var c in new[] { "Severity", "Tier", "Category", "Title", "Observation", "WhyItMatters", "Artifact", "NextStep" }) table.Columns.Add(c);
            foreach (var r in rows.OrderBy(r => Array.IndexOf(SeverityOrder, V(r, "Severity")) is int i && i >= 0 ? i : SeverityOrder.Length))
                table.Rows.Add(V(r, "Severity"), V(r, "Tier"), V(r, "Category"), V(r, "Title"), V(r, "Observation"), V(r, "WhyItMatters"), V(r, "Artifact"), V(r, "NextStep"));
            grid.DataSource = table;
        }

        /// <summary>Wires a findings grid: column layout once bound (columns exist only then), details on selection.</summary>
        static void FindingGrid(DataGridView grid, TextBox details)
        {
            grid.DataBindingComplete += (s, e) =>
            {
                var weights = new Dictionary<string, float> { ["Category"] = 12, ["Title"] = 35, ["Observation"] = 60 };
                foreach (DataGridViewColumn c in grid.Columns)
                {
                    // Short values (High, Not reviewed, 2) are shown whole; the long ones share the rest of the width.
                    if (c.Name == "Severity" || c.Name == "Status" || c.Name == "Tier") c.AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells;
                    else if (weights.TryGetValue(c.Name, out var w)) c.FillWeight = w;
                    else c.Visible = false;
                }
            };
            grid.SelectionChanged += (s, e) => ShowDetails(grid, details);
            Cues.Severity(grid);
        }

        static void ShowDetails(DataGridView grid, TextBox details)
        {
            if (grid.CurrentRow?.DataBoundItem is System.Data.DataRowView row)
            {
                string V(string k) => Convert.ToString(row[k], System.Globalization.CultureInfo.InvariantCulture) ?? "";
                details.Text = string.Join(Environment.NewLine + Environment.NewLine, new[]
                {
                    $"{V("Severity")} - Tier {V("Tier")} - {V("Category")}", V("Title"),
                    "What was observed" + Environment.NewLine + V("Observation"),
                    "Why it matters" + Environment.NewLine + V("WhyItMatters"),
                    "Source artifact" + Environment.NewLine + V("Artifact"),
                    "Next step" + Environment.NewLine + V("NextStep"),
                });
            }
        }

        /// <summary>The report this console last built with Analyze.</summary>
        readonly BuiltReport _report = new BuiltReport();

        async Task OpenReport()
        {
            if (_caseRoot == null) return;
            if (!_report.Unchanged())
            {
                var answer = MessageBox.Show(this,
                    "The report in this package was written on the endpoint during collection, or has changed since this console built it. " +
                    "A browser runs whatever an HTML file contains, so it is not opened as it is.\r\n\r\nRun Analyze now to rebuild the report on this workstation, then open it?",
                    "Open report", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (answer != DialogResult.Yes) return;
                await Run("Analyze", Analyze);
                if (!_report.Unchanged()) { _status.Text = "Report not opened: Analyze did not build it."; return; }
            }
            Process.Start(new ProcessStartInfo(_report.Path!) { UseShellExecute = true });
        }

        /// <summary>
        /// UI thread: reloads the Viewer for a case root. Package files are untrusted input (a malformed hash list, an
        /// unreadable folder); a failure is a log warning and never ends an open or costs an action's results.
        /// </summary>
        void RefreshViewer(string caseRoot, StatusLog log)
        {
            try { _viewer.Load(caseRoot); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                || ex is ArgumentException || ex is NotSupportedException || ex is FormatException)
            {
                log.Write("Viewer not loaded: " + ex.Message, StatusLevel.Warn);
            }
        }

        void ShowArtifact()
        {
            var art = _findings.CurrentRow?.DataBoundItem is System.Data.DataRowView row
                ? Convert.ToString(row["Artifact"], System.Globalization.CultureInfo.InvariantCulture) ?? "" : "";
            if (art.Length == 0) { _status.Text = "Select a finding that names a source artifact."; return; }
            _tabs.SelectedTab = _viewer.Page;
            if (!_viewer.Select(art)) _status.Text = "Not in this package: " + art;
        }

        void ShowFolder()
        {
            if (_caseRoot != null && Directory.Exists(_caseRoot)) Process.Start(new ProcessStartInfo(_caseRoot) { UseShellExecute = true });
        }

        string? PickFolder()
        {
            using (var d = new FolderBrowserDialog { Description = "Choose a case folder (the Foton_... folder that holds 00_Collection)", ShowNewFolderButton = false })
                return d.ShowDialog(this) == DialogResult.OK ? d.SelectedPath : null;
        }

        string? PickZip()
        {
            using (var d = new OpenFileDialog { Title = "Choose a package ZIP", Filter = "Foton package (*.zip)|*.zip", CheckFileExists = true })
                return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
        }
    }
}
