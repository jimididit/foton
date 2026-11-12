using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// The Search tab: foton search over the open package (every CSV, JSON, text, log, XML, and HTML file), with the
    /// hits listed and opened in the Viewer at their row. Results are also written to analysis\search_&lt;UTC&gt;.csv.
    /// </summary>
    sealed partial class MainForm
    {
        readonly TextBox _searchText = new TextBox { Width = 320 };
        readonly CheckBox _searchRegex = new CheckBox { Text = "Regular expression", AutoSize = true, Padding = new Padding(6, 4, 0, 0) };
        readonly Button _searchStop = new Button { Text = "Stop", AutoSize = true, Enabled = false };
        readonly Label _searchSummary = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        readonly DataGridView _searchHits = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };
        System.Threading.CancellationTokenSource? _searchCancel;

        TabPage SearchTab()
        {
            var page = new TabPage("Search");
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            bar.Controls.Add(new Label { Text = "Find", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            bar.Controls.Add(_searchText);
            bar.Controls.Add(_searchRegex);
            bar.Controls.Add(AddButton("Search", SearchPackage, needsPackage: true));
            bar.Controls.Add(_searchStop);
            bar.Controls.Add(AddButton("Open in Viewer", OpenSearchHit, needsPackage: true));
            bar.Controls.Add(_searchSummary);
            var note = new Label
            {
                Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4), ForeColor = System.Drawing.SystemColors.GrayText,
                Text = "Case-insensitive, in every CSV, JSON, text, log, XML, and HTML file. Binary artifacts (EVTX, hives, Prefetch) are not searched; compose turns them into CSVs. "
                    + "Saved to analysis\\search_<UTC>.csv and .txt.",
            };
            _searchStop.Click += (s, e) => _searchCancel?.Cancel();
            _searchText.KeyDown += async (s, e) => { if (e.KeyCode == Keys.Enter && !_busy && _caseRoot != null) { e.SuppressKeyPress = true; await SearchPackage(); } };
            _searchHits.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0) OpenSearchHit(); };
            _searchHits.DataBindingComplete += (s, e) =>
            {
                var weights = new Dictionary<string, float> { ["Artifact"] = 30, ["Where"] = 10, ["Column"] = 12, ["Snippet"] = 60 };
                foreach (DataGridViewColumn c in _searchHits.Columns)
                {
                    if (weights.TryGetValue(c.Name, out var w)) c.FillWeight = w;
                    else c.Visible = false;
                }
            };
            page.Controls.Add(_searchHits);
            page.Controls.Add(note);
            page.Controls.Add(bar);
            return page;
        }

        async Task SearchPackage()
        {
            var query = _searchText.Text;
            if (query.Length == 0) { _status.Text = "Type a text to search for."; return; }
            var options = new SearchOptions { Regex = _searchRegex.Checked };   // read on the UI thread
            var cancel = _searchCancel = new System.Threading.CancellationTokenSource();
            SearchRun? run = null;
            _searchStop.Enabled = true;
            _searchSummary.Text = "Searching...";
            try { await Run("Search", (log, path) => run = PackageSearch.Run(path, query, options, log, cancel.Token)); }
            finally { _searchStop.Enabled = false; }
            if (run == null) { _searchSummary.Text = "Search not run (see the log)."; return; }
            var table = new DataTable();
            foreach (var c in new[] { "Artifact", "Where", "Column", "Snippet" }) table.Columns.Add(c);
            table.Columns.Add("Row", typeof(int));
            foreach (var h in run.Hits)
                table.Rows.Add(h.Artifact, h.Line > 0 ? "line " + h.Line.ToString(CultureInfo.InvariantCulture) : h.Row > 0 ? "row " + h.Row.ToString(CultureInfo.InvariantCulture) : "header", h.Column, h.Snippet, h.Row);
            _searchHits.DataSource = table;
            _searchSummary.Text = $"{run.Matches:N0} match(es) in {run.FilesWithMatches} of {run.FilesSearched} file(s)"
                + (run.Matches > run.Hits.Count ? $"; the first {run.Hits.Count:N0} listed" : "")
                + (run.Binary.Count > 0 ? $"; {run.Binary.Count} binary file(s) not searched" : "")
                + (run.NotSearched.Count > 0 ? $"; {run.NotSearched.Count} not searched or in part (see the log)" : "")
                + (run.Stopped ? "; stopped early" : "");
        }

        /// <summary>A CSV hit opens at its row in the Viewer; a text hit opens the file (the line is in the status bar).</summary>
        void OpenSearchHit()
        {
            if (!(_searchHits.CurrentRow?.DataBoundItem is DataRowView v)) { _status.Text = "Select a hit first."; return; }
            var artifact = Convert.ToString(v["Artifact"], CultureInfo.InvariantCulture) ?? "";
            var row = v["Row"] is int n ? n : 0;
            _tabs.SelectedTab = _viewer.Page;
            if (!_viewer.Select(artifact, row)) { _status.Text = "Not in this package: " + artifact; return; }
            var where = Convert.ToString(v["Where"], CultureInfo.InvariantCulture) ?? "";
            if (row == 0) _status.Text = artifact + ", " + where + ": " + TextFile.OneLine(Convert.ToString(v["Snippet"], CultureInfo.InvariantCulture));
        }
    }
}
