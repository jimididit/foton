using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// The Cases tab: the case and baseline packages in C:\Foton\Cases, C:\Foton\Baselines, and folders the operator
    /// adds, read with CaseIndex (the same listing as foton cases). Read-only: it opens, verifies, and shows packages,
    /// and never deletes or renames them. Verify results last for this session only.
    /// </summary>
    sealed partial class MainForm
    {
        TabPage? _casesPage;
        TabPage? _packagePage;
        readonly ConsoleSettings _settings = ConsoleSettings.Load();
        readonly ComboBox _addedFolders = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 360 };
        readonly Label _casesSummary = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        readonly DataGridView _cases = CasesGrid();
        readonly DataGridView _baselines = CasesGrid();
        /// <summary>Package path to the result of this session's Verify of it.</summary>
        readonly Dictionary<string, string> _verified = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        CaseList? _caseList;

        static DataGridView CasesGrid() => new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = true, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells,
        };

        TabPage CasesTab()
        {
            var page = new TabPage("Cases");
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            bar.Controls.Add(AddButton("Refresh", RefreshCases));
            bar.Controls.Add(AddButton("Add folder...", AddCaseFolder));
            bar.Controls.Add(new Label { Text = "Added folders", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
            bar.Controls.Add(_addedFolders);
            bar.Controls.Add(AddButton("Remove folder", RemoveCaseFolder));
            bar.Controls.Add(_casesSummary);

            var caseBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(2) };
            caseBar.Controls.Add(new Label { Text = "Cases", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) });
            caseBar.Controls.Add(AddButton("Open", OpenSelectedCase));
            caseBar.Controls.Add(AddButton("Verify selected", VerifySelectedCases));
            caseBar.Controls.Add(AddButton("Show folder", () => ShowSelected(_cases)));
            var casePanel = new Panel { Dock = DockStyle.Fill };
            casePanel.Controls.Add(_cases);
            casePanel.Controls.Add(caseBar);

            var baselineBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(2) };
            baselineBar.Controls.Add(new Label { Text = "Baselines", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) });
            baselineBar.Controls.Add(AddButton("Use as reference", () => UseBaseline(reference: true)));
            baselineBar.Controls.Add(AddButton("Use as difference", () => UseBaseline(reference: false)));
            baselineBar.Controls.Add(AddButton("Compare these two", CompareSelectedBaselines));
            baselineBar.Controls.Add(AddButton("Show folder", () => ShowSelected(_baselines)));
            var baselinePanel = new Panel { Dock = DockStyle.Fill };
            baselinePanel.Controls.Add(_baselines);
            baselinePanel.Controls.Add(baselineBar);

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            split.Panel1.Controls.Add(casePanel);
            split.Panel2.Controls.Add(baselinePanel);
            Load += (s, e) => SetSplit(split, 0.62);
            _cases.CellDoubleClick += async (s, e) => { if (e.RowIndex >= 0) await OpenSelectedCase(); };

            page.Controls.Add(split);
            page.Controls.Add(bar);
            FillAddedFolders();
            return page;
        }

        IEnumerable<string> CaseFolders() =>
            new[] { CaseTree.DefaultOutput("Cases"), CaseTree.DefaultOutput("Baselines") }.Concat(_settings.CaseFolders);

        void FillAddedFolders()
        {
            _addedFolders.Items.Clear();
            foreach (var f in _settings.CaseFolders) _addedFolders.Items.Add(f);
            if (_addedFolders.Items.Count > 0) _addedFolders.SelectedIndex = 0;
        }

        async Task RefreshCases()
        {
            var folders = CaseFolders().ToList();
            CaseList? list = null;
            await Run("Refresh cases", log =>
            {
                list = CaseIndex.Scan(folders);
                log.Write($"{list.Cases.Count} case(s) and {list.Baselines.Count} baseline(s) in {folders.Count} folder(s)", StatusLevel.Good);
                foreach (var n in list.Notes) log.Write(n, StatusLevel.Info);
                return null;
            });
            if (list == null) return;
            _caseList = list;
            ShowCaseList();
        }

        void ShowCaseList()
        {
            var list = _caseList;
            if (list == null) return;
            string Who(bool? elevated) => elevated == null ? "" : elevated.Value ? "admin" : "standard";

            var cases = new System.Data.DataTable();
            foreach (var c in new[] { "Collected (UTC)", "Host", "Case", "Examiner", "Account", "Profile", "High", "Medium", "Low", "Info", "Findings from", "Done", "Kind", "Verified (this session)", "Unreadable", "Path" })
                cases.Columns.Add(c);
            foreach (var c in list.Cases)
            {
                var done = string.Join(", ", new[] { c.Parsed ? "parse" : null, c.Composed ? "compose" : null, c.Analyzed ? "analyze" : null }.Where(x => x != null));
                var kind = c.Kind == "Zip" ? "ZIP (not extracted)" : c.Kind == "ZipExtracted" ? "ZIP (extracted)" : c.HasZip ? "Folder + ZIP" : "Folder";
                cases.Rows.Add(c.CollectedUtc, c.Host, c.CaseNumber, c.Examiner, Who(c.Elevated), c.Profile,
                    c.FindingsSource.Length > 0 ? (object)c.High : "", c.FindingsSource.Length > 0 ? (object)c.Medium : "", c.FindingsSource.Length > 0 ? (object)c.Low : "", c.FindingsSource.Length > 0 ? (object)c.Info : "",
                    c.FindingsSource == "analysis" ? "workstation analyze" : c.FindingsSource == "collect" ? "collector" : "", done, kind,
                    _verified.TryGetValue(c.Path, out var v) ? v : c.Kind == "Zip" ? "(open it first)" : "not checked", c.Problem, c.Path);
            }
            _cases.DataSource = cases;

            var baselines = new System.Data.DataTable();
            foreach (var c in new[] { "Captured (UTC)", "Host", "Account", "Users not signed in", "Foton", "Payload SHA-256", "Unreadable", "Path" }) baselines.Columns.Add(c);
            foreach (var b in list.Baselines)
                baselines.Rows.Add(b.CapturedUtc, b.Host, Who(b.Elevated), b.LoadUserHives == true ? "included" : "", b.ToolVersion, b.PayloadSha256, b.Problem, b.JsonPath);
            _baselines.DataSource = baselines;
            _casesSummary.Text = $"{list.Cases.Count} case(s), {list.Baselines.Count} baseline(s)";
        }

        /// <summary>The Path column of the selected rows, in grid order.</summary>
        static List<string> SelectedPaths(DataGridView grid) =>
            grid.SelectedRows.Cast<DataGridViewRow>().OrderBy(r => r.Index)
                .Select(r => r.DataBoundItem is System.Data.DataRowView v ? Convert.ToString(v["Path"], System.Globalization.CultureInfo.InvariantCulture) ?? "" : "")
                .Where(p => p.Length > 0).ToList();

        CaseEntry? Case(string path) => _caseList?.Cases.FirstOrDefault(c => string.Equals(c.Path, path, StringComparison.OrdinalIgnoreCase));
        BaselineEntry? Baseline(string jsonPath) => _caseList?.Baselines.FirstOrDefault(b => string.Equals(b.JsonPath, jsonPath, StringComparison.OrdinalIgnoreCase));

        async Task OpenSelectedCase()
        {
            var path = SelectedPaths(_cases).FirstOrDefault();
            if (path == null) { _status.Text = "Select a case first."; return; }
            if (_packagePage != null) _tabs.SelectedTab = _packagePage;
            await Open(path);
        }

        async Task VerifySelectedCases()
        {
            var paths = SelectedPaths(_cases);
            var zips = paths.Where(p => Case(p)?.Kind == "Zip").ToList();
            var check = paths.Except(zips, StringComparer.OrdinalIgnoreCase).ToList();
            if (zips.Count > 0) _status.Text = $"{zips.Count} ZIP(s) not verified here: verifying would extract them beside the ZIP. Open them first.";
            if (check.Count == 0) return;
            var results = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            await Run("Verify cases", log =>
            {
                foreach (var p in check)
                {
                    log.WriteConsole("");
                    log.WriteConsole("   " + p);
                    try
                    {
                        var package = FotonPackage.Open(p);
                        var code = PackageCheck.Report(log, package);
                        // Report returns 2 both for a mismatch and for a package with no hash list; say which.
                        var listed = File.Exists(Path.Combine(package.CaseRoot, CaseTree.CollectionFolder, "hashes.csv"));
                        results[p] = (code == 0 ? "Matches hashes.csv" : listed ? "DOES NOT VERIFY (see the log)" : "No hashes.csv: cannot be checked")
                            + " at " + FotonTime.Format(DateTime.UtcNow).Substring(11) + " UTC";
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException || ex is NotSupportedException)
                    {
                        log.Write("Cannot verify: " + ex.Message, StatusLevel.Error);
                        results[p] = "Cannot verify: " + TextFile.OneLine(ex.Message);
                    }
                }
                return null;
            });
            foreach (var kv in results) _verified[kv.Key] = kv.Value;
            ShowCaseList();
        }

        void ShowSelected(DataGridView grid)
        {
            var path = SelectedPaths(grid).FirstOrDefault();
            if (path == null) { _status.Text = "Select a row first."; return; }
            var folder = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
            if (folder != null && Directory.Exists(folder)) Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
        }

        void UseBaseline(bool reference)
        {
            var path = SelectedPaths(_baselines).FirstOrDefault();
            if (path == null) { _status.Text = "Select a baseline first."; return; }
            (reference ? _reference : _difference).Text = path;
            if (_comparePage != null) _tabs.SelectedTab = _comparePage;
            _status.Text = (reference ? "Reference" : "Difference") + " set in Compare.";
        }

        async Task CompareSelectedBaselines()
        {
            var paths = SelectedPaths(_baselines);
            if (paths.Count != 2) { _status.Text = "Select exactly two baselines."; return; }
            // The earlier capture is the reference, the later one the difference.
            var ordered = paths.OrderBy(p => Baseline(p)?.CapturedUtc ?? "", StringComparer.Ordinal).ToList();
            _reference.Text = ordered[0];
            _difference.Text = ordered[1];
            if (_comparePage != null) _tabs.SelectedTab = _comparePage;
            await Compare();
        }

        async Task AddCaseFolder()
        {
            string folder;
            using (var d = new FolderBrowserDialog { Description = "Choose a folder that holds case or baseline packages", ShowNewFolderButton = false })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                folder = d.SelectedPath;
            }
            if (!_settings.CaseFolders.Contains(folder, StringComparer.OrdinalIgnoreCase)) _settings.CaseFolders.Add(folder);
            SaveSettings();
            FillAddedFolders();
            await RefreshCases();
        }

        async Task RemoveCaseFolder()
        {
            if (!(_addedFolders.SelectedItem is string folder)) { _status.Text = "No added folder to remove (the two default folders always stay)."; return; }
            _settings.CaseFolders.RemoveAll(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase));
            SaveSettings();
            FillAddedFolders();
            await RefreshCases();
        }

        void SaveSettings()
        {
            if (!_settings.Save(out var problem)) _status.Text = "Folder list not saved: " + TextFile.OneLine(problem ?? "");
        }
    }
}
