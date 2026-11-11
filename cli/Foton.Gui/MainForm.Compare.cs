using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Baseline.Compare;
using Foton.Core;

namespace Foton.Gui
{
    /// <summary>
    /// The Compare tab: foton compare on two baselines (folders or baseline.json), reference first. It writes what the
    /// verb writes (baseline_diff.csv and the compare report beside the difference baseline) and shows the findings and
    /// every field-level change. A diff records change between two observations, never when, who, or compromise.
    /// </summary>
    sealed partial class MainForm
    {
        /// <summary>Rows shown in the change table; the full list is in baseline_diff.csv.</summary>
        const int MaxChangeRows = 50000;

        // Editable: a baseline folder (or its baseline.json) can be typed or pasted, as foton compare accepts either.
        readonly TextBox _reference = new TextBox { Width = 520 };
        readonly TextBox _difference = new TextBox { Width = 520 };
        readonly Label _compareSummary = new Label { AutoSize = true, Padding = new Padding(0, 6, 0, 0) };
        readonly DataGridView _compareFindings = Grid();
        readonly TextBox _compareDetails = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true };
        readonly DataGridView _changes = Grid();
        readonly BuiltReport _compareReport = new BuiltReport();

        static DataGridView Grid() => new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };

        TabPage CompareTab()
        {
            var page = new TabPage("Compare");
            var pick = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Padding = new Padding(4) };
            pick.Controls.Add(new Label { Text = "Reference (earlier, or the golden image)", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, 0, 0);
            pick.Controls.Add(_reference, 1, 0);
            pick.Controls.Add(AddButton("Choose...", () => PickBaseline(_reference, "Choose the reference baseline.json")), 2, 0);
            pick.Controls.Add(new Label { Text = "Difference (later, or the host)", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, 0, 1);
            pick.Controls.Add(_difference, 1, 1);
            pick.Controls.Add(AddButton("Choose...", () => PickBaseline(_difference, "Choose the difference baseline.json")), 2, 1);

            var actions = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            actions.Controls.Add(AddButton("Compare", Compare));
            actions.Controls.Add(AddButton("Open compare report", OpenCompareReport));
            actions.Controls.Add(_compareSummary);

            FindingGrid(_compareFindings, _compareDetails);
            var findingsSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            findingsSplit.Panel1.Controls.Add(_compareFindings);
            findingsSplit.Panel2.Controls.Add(_compareDetails);
            var main = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            main.Panel1.Controls.Add(findingsSplit);
            main.Panel2.Controls.Add(_changes);
            Load += (s, e) => { SetSplit(findingsSplit, 0.68); SetSplit(main, 0.5); };

            page.Controls.Add(main);
            page.Controls.Add(actions);
            page.Controls.Add(pick);
            return page;
        }

        void PickBaseline(TextBox target, string title)
        {
            using (var d = new OpenFileDialog { Title = title, Filter = "Baseline (baseline.json)|baseline.json|JSON (*.json)|*.json", CheckFileExists = true })
                if (d.ShowDialog(this) == DialogResult.OK) target.Text = d.FileName;
        }

        async Task Compare()
        {
            var reference = _reference.Text.Trim().Trim('"');
            var difference = _difference.Text.Trim().Trim('"');
            if (reference.Length == 0 || difference.Length == 0) { _status.Text = "Choose both baselines first."; return; }
            _compareReport.Remember(null);
            CompareResult? result = null;
            string? html = null;
            await Run("Compare", log =>
            {
                var r = BaselineComparer.Run(reference, difference, log);
                foreach (var sev in SeverityOrder)
                {
                    var n = r.Findings.Count(f => f.Severity == sev);
                    if (n > 0) log.Write($"{sev}: {n}", sev == "High" ? StatusLevel.Warn : StatusLevel.Info);
                }
                if (r.DiffCsvPath != null) log.Write("Change table: " + r.DiffCsvPath, StatusLevel.Info);
                var path = Path.Combine(Path.GetDirectoryName(BaselineDocument.ResolveJsonPath(difference))!, BaselineCompareReport.FileName);
                try
                {
                    BaselineCompareReport.Write(r, path);
                    log.Write("Baseline compare report: " + path, StatusLevel.Good);
                    html = path;
                }
                catch (Exception ex)
                {
                    // The diff and baseline_diff.csv are already written; the HTML is a preview.
                    log.Write("Baseline compare report not written: " + ex.Message, StatusLevel.Warn);
                }
                log.WriteConsole("     A diff records change between two snapshots. It does not show when, who, or that the host is compromised.");
                result = r;
                return null;
            });
            if (result == null) return;
            _compareReport.Remember(html);
            ShowFindings(_compareFindings, result.Findings.Select(FindingRow));
            var table = new System.Data.DataTable();
            foreach (var c in new[] { "RecordType", "Identity", "ChangeType", "Field", "OldValue", "NewValue" }) table.Columns.Add(c);
            foreach (var c in result.Changes.Take(MaxChangeRows)) table.Rows.Add(c.RecordType, c.Identity, c.ChangeType, c.Field, c.OldValue, c.NewValue);
            _changes.DataSource = table;
            var intact = result.ReferencePayloadIntact && result.DifferencePayloadIntact ? "" : " - a baseline's records do not match its PayloadSha256 (see the log)";
            var shown = result.Changes.Count > MaxChangeRows ? $" (first {MaxChangeRows:N0} shown; all in baseline_diff.csv)" : "";
            _compareSummary.Text = $"{result.Mode}: {result.Changes.Count} change(s){shown}, {result.Findings.Count} finding(s){intact}";
            _status.Text = "Compare finished - " + _compareSummary.Text;
        }

        void OpenCompareReport()
        {
            if (!_compareReport.Unchanged())
            {
                _status.Text = "Run Compare first: only a compare report this console built, unchanged since, is opened.";
                return;
            }
            Process.Start(new ProcessStartInfo(_compareReport.Path!) { UseShellExecute = true });
        }
    }
}
