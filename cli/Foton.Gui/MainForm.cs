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
    sealed class MainForm : Form
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
        readonly TextBox _log = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font(FontFamily.GenericMonospace, 9f) };
        readonly ToolStripStatusLabel _status = new ToolStripStatusLabel("Ready") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        readonly ToolStripProgressBar _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false };
        readonly List<Control> _actions = new List<Control>();
        string? _caseRoot;
        bool _busy;

        public MainForm(string? openPath)
        {
            Text = "Foton console " + FotonVersion.Product;
            Font = new Font("Segoe UI", 9f);
            Size = new Size(1280, 820);
            MinimumSize = new Size(900, 600);
            StartPosition = FormStartPosition.CenterScreen;

            var tabs = new TabControl { Dock = DockStyle.Fill };
            tabs.TabPages.Add(PackageTab());
            Controls.Add(tabs);
            var strip = new StatusStrip();
            strip.Items.Add(_status);
            strip.Items.Add(_progress);
            Controls.Add(strip);

            _findings.SelectionChanged += (s, e) => ShowDetails();
            if (openPath != null) Shown += async (s, e) => await Open(openPath);
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
            actions.Controls.Add(AddButton("Verify", () => Run("Verify", Verify), needsPackage: true));
            actions.Controls.Add(AddButton("Parse", () => Run("Parse", Parse), needsPackage: true));
            actions.Controls.Add(AddButton("Compose", () => Run("Compose", Compose), needsPackage: true));
            actions.Controls.Add(AddButton("Analyze", () => Run("Analyze", Analyze), needsPackage: true));
            actions.Controls.Add(AddButton("Parse, compose, analyze", () => Run("Parse, compose, analyze", (log, path) => { Parse(log, path); Compose(log, path); return Analyze(log, path); }), needsPackage: true));
            actions.Controls.Add(AddButton("Open report", OpenReport, needsPackage: true));
            actions.Controls.Add(AddButton("Show case folder", ShowFolder, needsPackage: true));
            actions.Controls.Add(_summary);

            var findingsSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            findingsSplit.Panel1.Controls.Add(_findings);
            findingsSplit.Panel2.Controls.Add(_details);
            var main = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            main.Panel1.Controls.Add(findingsSplit);
            main.Panel2.Controls.Add(_log);
            // A splitter position is checked against the control's current size, so set it once the window has its real
            // size, as a share of it (any window size or display scaling).
            Load += (s, e) =>
            {
                SetSplit(findingsSplit, 0.68);
                SetSplit(main, 0.62);
            };

            page.Controls.Add(main);
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
            foreach (var c in _actions) c.Enabled = !_busy && (!(c.Tag is bool needs && needs) || _caseRoot != null);
        }

        /// <summary>
        /// Runs one action on a worker thread with its own StatusLog; a failure is logged, never thrown at the operator.
        /// The package path is read here, on the UI thread, and handed to the work.
        /// </summary>
        Task Run(string label, Func<StatusLog, string, object?> work)
        {
            var path = _path.Text;
            return Run(label, log => work(log, path));
        }

        async Task Run(string label, Func<StatusLog, object?> work)
        {
            if (_busy) return;
            _busy = true;
            UpdateButtons();
            _status.Text = label + "...";
            _progress.Visible = true;
            var log = new StatusLog(new LogWriter(_log));
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
                }
            }
            catch (Exception ex)
            {
                log.Write(label + " stopped: " + ex.Message, StatusLevel.Error);
                _status.Text = label + " stopped: " + TextFile.OneLine(ex.Message);
            }
            finally
            {
                _busy = false;
                _progress.Visible = false;
                UpdateButtons();
            }
        }

        async Task Open(string path)
        {
            _path.Text = path;
            _caseRoot = null;
            _findings.DataSource = null;
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
                    ShowFindings(findings);
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

        static object Compose(StatusLog log, string path)
        {
            var run = Foton.Tools.ComposeRunner.Run(path, log);
            foreach (var r in run.Rows)
                log.WriteConsole($"   {r.Tool,-14} {(r.Version.Length > 0 ? r.Version : "-"),-12} {r.Status,-14} {(r.DestRelative.Length > 0 ? r.DestRelative : r.Note)}");
            log.Write("Inventory: " + run.InventoryPath, StatusLevel.Good);
            return run;
        }

        static object Analyze(StatusLog log, string path) => Analyzer.RunPackage(path, log, Foton.Patterns.WorkstationPatterns.SuspiciousCommands);

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

        void ShowFindings(IEnumerable<Dictionary<string, string?>> rows)
        {
            string V(Dictionary<string, string?> r, string k) => r.TryGetValue(k, out var v) ? v ?? "" : "";
            var table = new System.Data.DataTable();
            foreach (var c in new[] { "Severity", "Tier", "Category", "Title", "Observation", "WhyItMatters", "Artifact", "NextStep" }) table.Columns.Add(c);
            foreach (var r in rows.OrderBy(r => Array.IndexOf(SeverityOrder, V(r, "Severity")) is int i && i >= 0 ? i : SeverityOrder.Length))
                table.Rows.Add(V(r, "Severity"), V(r, "Tier"), V(r, "Category"), V(r, "Title"), V(r, "Observation"), V(r, "WhyItMatters"), V(r, "Artifact"), V(r, "NextStep"));
            _findings.DataSource = table;
            foreach (var hidden in new[] { "WhyItMatters", "Artifact", "NextStep" }) _findings.Columns[hidden].Visible = false;
            _findings.Columns["Severity"].FillWeight = 8;
            _findings.Columns["Tier"].FillWeight = 5;
            _findings.Columns["Category"].FillWeight = 12;
            _findings.Columns["Title"].FillWeight = 35;
            _findings.Columns["Observation"].FillWeight = 60;
        }

        void ShowDetails()
        {
            if (_findings.CurrentRow?.DataBoundItem is System.Data.DataRowView row)
            {
                string V(string k) => Convert.ToString(row[k], System.Globalization.CultureInfo.InvariantCulture) ?? "";
                _details.Text = string.Join(Environment.NewLine + Environment.NewLine, new[]
                {
                    $"{V("Severity")} - Tier {V("Tier")} - {V("Category")}", V("Title"),
                    "What was observed" + Environment.NewLine + V("Observation"),
                    "Why it matters" + Environment.NewLine + V("WhyItMatters"),
                    "Source artifact" + Environment.NewLine + V("Artifact"),
                    "Next step" + Environment.NewLine + V("NextStep"),
                });
            }
        }

        void OpenReport()
        {
            var report = _caseRoot == null ? null : Path.Combine(_caseRoot, CaseTree.ReportFileName);
            if (report == null || !File.Exists(report)) { _status.Text = "No report yet: run Analyze."; return; }
            Process.Start(new ProcessStartInfo(report) { UseShellExecute = true });
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
