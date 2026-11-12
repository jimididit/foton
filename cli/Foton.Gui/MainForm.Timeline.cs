using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Analyze.Timeline;
using Foton.Core;

namespace Foton.Gui
{
    /// <summary>
    /// The Timeline tab: builds analysis\timeline.csv with the same TimelineBuilder foton timeline runs, then shows it
    /// filtered (time window, source, text) by streaming the file, at most MaxTimelineRows rows at a time with the full
    /// match count. A reading aid: rows are what each source recorded, never a finding.
    /// </summary>
    sealed partial class MainForm
    {
        const int MaxTimelineRows = 10000;
        TabPage? _timelinePage;
        readonly CheckBox _timelineAll = new CheckBox { Text = "Include SRUM hourly counters", AutoSize = true, Padding = new Padding(8, 4, 0, 0) };
        readonly Label _timelineFile = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        readonly TextBox _timelineFrom = new TextBox { Width = 130 };
        readonly TextBox _timelineTo = new TextBox { Width = 130 };
        readonly ComboBox _timelineSource = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };
        readonly TextBox _timelineFind = new TextBox { Width = 200 };
        readonly NumericUpDown _timelineMinutes = new NumericUpDown { Minimum = 0, Maximum = 1440, Value = 5, Width = 60 };
        readonly Label _timelineMatches = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        readonly DataGridView _timeline = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };
        const string AllSources = "(all sources)";
        /// <summary>The case root whose timeline is on screen; another package reloads the tab when it is shown.</summary>
        string? _timelineFor;
        int _timelineVersion;
        System.Threading.CancellationTokenSource? _timelineCancel;

        TabPage TimelineTab()
        {
            var page = new TabPage("Timeline");
            var build = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            build.Controls.Add(AddButton("Build timeline", BuildTimeline, needsPackage: true));
            build.Controls.Add(_timelineAll);
            build.Controls.Add(_timelineFile);

            var filters = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            Label L(string text) => new Label { Text = text, AutoSize = true, Padding = new Padding(6, 6, 0, 0) };
            filters.Controls.Add(L("From (UTC)"));
            filters.Controls.Add(_timelineFrom);
            filters.Controls.Add(L("To (UTC)"));
            filters.Controls.Add(_timelineTo);
            filters.Controls.Add(L("Source"));
            filters.Controls.Add(_timelineSource);
            filters.Controls.Add(L("Find"));
            filters.Controls.Add(_timelineFind);
            filters.Controls.Add(AddButton("Apply", () => ApplyTimelineFilter(), needsPackage: true));
            filters.Controls.Add(AddButton("Clear", ClearTimelineFilter, needsPackage: true));
            filters.Controls.Add(L("+/-"));
            filters.Controls.Add(_timelineMinutes);
            filters.Controls.Add(L("minutes"));
            filters.Controls.Add(AddButton("Around selected row", AroundSelectedRow, needsPackage: true));
            filters.Controls.Add(AddButton("Show source row", ShowTimelineSource, needsPackage: true));
            filters.Controls.Add(AddButton("Note on source row...", NoteOnTimelineRow, needsPackage: true));
            filters.Controls.Add(_timelineMatches);

            var note = new Label
            {
                Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4), ForeColor = SystemColors.GrayText,
                Text = "A timeline orders recorded times: what each source recorded and when, not who did it or why. Each row's Meaning says what its time is. "
                    + "Grey rows fall inside the collection window, where the collector's own activity can appear.",
            };

            _timelineSource.Items.Add(AllSources);
            _timelineSource.SelectedIndex = 0;
            _timelineSource.SelectionChangeCommitted += async (s, e) => await ApplyTimelineFilter();
            foreach (var box in new[] { _timelineFrom, _timelineTo, _timelineFind })
                box.KeyDown += async (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ApplyTimelineFilter(); } };
            _timeline.DataBindingComplete += (s, e) =>
            {
                var weights = new Dictionary<string, float> { ["Time (UTC)"] = 12, ["Source"] = 9, ["Meaning"] = 20, ["Summary"] = 45, ["Artifact"] = 22, ["Row"] = 5, ["During collection"] = 7 };
                foreach (DataGridViewColumn c in _timeline.Columns) if (weights.TryGetValue(c.Name, out var w)) c.FillWeight = w;
                foreach (DataGridViewRow r in _timeline.Rows)
                    if (r.DataBoundItem is DataRowView v && Convert.ToString(v["During collection"], CultureInfo.InvariantCulture) == "yes")
                        r.DefaultCellStyle.ForeColor = SystemColors.GrayText;
            };
            _timeline.CellDoubleClick += (s, e) => { if (e.RowIndex >= 0) ShowTimelineSource(); };
            _viewer.ShowInTimeline += async (artifact, row, utc) => await TimelineAround(utc, artifact, row);
            _viewer.Message += text => _status.Text = text;
            _viewer.NoteOnRow += async (artifact, row) => await NoteOnRow(artifact, row);
            _tabs.Selected += async (s, e) => { if (e.TabPage == _timelinePage && _caseRoot != null && _timelineFor != _caseRoot) await ShowTimeline(new TimelineFilter(), null, 0); };

            page.Controls.Add(_timeline);
            page.Controls.Add(note);
            page.Controls.Add(filters);
            page.Controls.Add(build);
            return page;
        }

        /// <summary>A newly opened package starts with an empty Timeline tab; it reads that package's timeline when shown.</summary>
        void ClearTimeline()
        {
            _timelineVersion++;
            _timelineCancel?.Cancel();
            _timelineFor = null;
            _timeline.DataSource = null;
            _timelineFile.Text = "";
            _timelineMatches.Text = "";
            _timelineFrom.Text = _timelineTo.Text = _timelineFind.Text = "";
            FillTimelineSources(new string[0]);
        }

        async Task BuildTimeline()
        {
            var options = new TimelineOptions { All = _timelineAll.Checked };   // read on the UI thread
            TimelineRun? built = null;
            await Run("Build timeline", (log, path) => built = TimelineBuilder.Run(path, log, options));
            if (built == null) return;
            var filter = CurrentTimelineFilter();
            await ShowTimeline(filter ?? new TimelineFilter(), null, 0);
        }

        /// <summary>The filters as typed, or null (and a status line) when a time is not one.</summary>
        TimelineFilter? CurrentTimelineFilter()
        {
            var f = new TimelineFilter();
            if (_timelineFrom.Text.Trim().Length > 0)
            {
                if (!TimelineReader.ParseUtc(_timelineFrom.Text, false, out var from)) { _status.Text = "From needs a UTC time as yyyy-MM-dd or yyyy-MM-dd HH:mm:ss."; return null; }
                f.FromUtc = from;
            }
            if (_timelineTo.Text.Trim().Length > 0)
            {
                if (!TimelineReader.ParseUtc(_timelineTo.Text, true, out var to)) { _status.Text = "To needs a UTC time as yyyy-MM-dd or yyyy-MM-dd HH:mm:ss."; return null; }
                f.ToUtc = to;
            }
            if (_timelineSource.SelectedItem is string s && s != AllSources) f.Source = s;
            if (_timelineFind.Text.Length > 0) f.Text = _timelineFind.Text;
            return f;
        }

        Task ApplyTimelineFilter()
        {
            var f = CurrentTimelineFilter();
            return f == null ? Task.FromResult(0) : ShowTimeline(f, null, 0);
        }

        async Task ClearTimelineFilter()
        {
            _timelineFrom.Text = _timelineTo.Text = _timelineFind.Text = "";
            _timelineSource.SelectedIndex = 0;
            await ShowTimeline(new TimelineFilter(), null, 0);
        }

        /// <summary>Every source, +/- the chosen minutes around a time, with the row it came from selected when it is there.</summary>
        async Task TimelineAround(DateTime utc, string? artifact, int row)
        {
            if (_timelinePage != null) _tabs.SelectedTab = _timelinePage;
            utc = new DateTime(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);   // the timeline shows whole seconds
            var span = TimeSpan.FromMinutes((double)_timelineMinutes.Value);
            var from = utc.Ticks - DateTime.MinValue.Ticks < span.Ticks ? DateTime.MinValue : utc - span;
            var to = DateTime.MaxValue.Ticks - utc.Ticks < span.Ticks ? DateTime.MaxValue : utc + span;
            _timelineFrom.Text = FotonTime.Format(from);
            _timelineTo.Text = FotonTime.Format(to);
            _timelineFind.Text = "";
            _timelineSource.SelectedIndex = 0;
            await ShowTimeline(new TimelineFilter { FromUtc = from, ToUtc = to }, artifact, row);
        }

        async Task AroundSelectedRow()
        {
            var row = SelectedTimelineRow();
            if (row == null) { _status.Text = "Select a timeline row first."; return; }
            if (!TimelineReader.ParseUtc(row.TimeUtc, false, out var utc)) { _status.Text = "That row's time cannot be read."; return; }
            await TimelineAround(utc, row.Artifact, row.Row);
        }

        void ShowTimelineSource()
        {
            var row = SelectedTimelineRow();
            if (row == null) { _status.Text = "Select a timeline row first."; return; }
            _tabs.SelectedTab = _viewer.Page;
            if (!_viewer.Select(row.Artifact, row.Row)) _status.Text = "Not in this package: " + row.Artifact;
        }

        /// <summary>A note on the artifact row a timeline row came from (more lasting than the timeline row, which a rebuild renumbers).</summary>
        Task NoteOnTimelineRow()
        {
            var row = SelectedTimelineRow();
            if (row == null || row.Row < 1) { _status.Text = "Select a timeline row first."; return Task.FromResult(0); }
            return NoteOnRow(row.Artifact, row.Row);
        }

        TimelineRow? SelectedTimelineRow()
        {
            if (!(_timeline.CurrentRow?.DataBoundItem is DataRowView v)) return null;
            string V(string k) => Convert.ToString(v[k], CultureInfo.InvariantCulture) ?? "";
            return new TimelineRow { TimeUtc = V("Time (UTC)"), Source = V("Source"), Artifact = V("Artifact"), Row = v["Row"] is int n ? n : 0 };
        }

        /// <summary>
        /// Reads the open package's timeline.csv through the filter on a worker thread (a newer read cancels this one) and
        /// shows the first rows; selects the row from <paramref name="artifact"/> and <paramref name="row"/> when given.
        /// </summary>
        async Task ShowTimeline(TimelineFilter filter, string? artifact, int row)
        {
            var root = _caseRoot;
            if (root == null) return;
            var version = ++_timelineVersion;
            _timelineCancel?.Cancel();
            var cancel = _timelineCancel = new System.Threading.CancellationTokenSource();
            _timelineFor = root;
            var file = Path.Combine(root, "analysis", TimelineBuilder.FileName);
            if (!File.Exists(file))
            {
                _timeline.DataSource = null;
                _timelineFile.Text = "No timeline in this package yet: Build timeline reads the package's recorded times into analysis\\timeline.csv.";
                _timelineMatches.Text = "";
                FillTimelineSources(new string[0]);
                if (artifact != null) _status.Text = "Build the timeline first, then use Show in timeline again.";
                return;
            }
            _timelineMatches.Text = "Reading...";
            TimelineView view;
            try { view = await Task.Run(() => TimelineReader.Read(file, filter, MaxTimelineRows, cancel.Token)); }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                if (version == _timelineVersion) _timelineMatches.Text = "Could not read timeline.csv: " + TextFile.OneLine(ex.Message);
                return;
            }
            if (version != _timelineVersion) return;   // a newer read, or another package
            _timelineFile.Text = "analysis\\timeline.csv, written " + FotonTime.Format(File.GetLastWriteTimeUtc(file)) + " UTC. Build again after a new parse or compose.";
            if (view.Problem != null)
            {
                _timeline.DataSource = null;
                _timelineMatches.Text = "timeline.csv: " + view.Problem;
                return;
            }
            FillTimelineSources(view.Sources);
            var table = new DataTable();
            foreach (var c in new[] { "Time (UTC)", "Source", "Meaning", "Summary", "Artifact" }) table.Columns.Add(c);
            table.Columns.Add("Row", typeof(int));
            table.Columns.Add("During collection");
            foreach (var r in view.Rows) table.Rows.Add(r.TimeUtc, r.Source, r.Meaning, r.Summary, r.Artifact, r.Row, r.DuringCollection ? "yes" : "");
            _timeline.DataSource = table;
            _timelineMatches.Text = view.Matches > view.Rows.Count
                ? $"{view.Matches:N0} of {view.RowsRead:N0} rows match; showing the first {view.Rows.Count:N0}. Narrow the filters to see the rest."
                : $"{view.Matches:N0} of {view.RowsRead:N0} rows match.";
            _status.Text = "Timeline: " + _timelineMatches.Text;   // replaces an earlier filter error
            if (artifact == null) return;
            foreach (DataGridViewRow r in _timeline.Rows)
            {
                if (r.DataBoundItem is DataRowView v && v["Row"] is int n && n == row
                    && string.Equals(Convert.ToString(v["Artifact"], CultureInfo.InvariantCulture), artifact, StringComparison.OrdinalIgnoreCase))
                {
                    _timeline.CurrentCell = r.Cells[0];
                    _timeline.FirstDisplayedScrollingRowIndex = Math.Max(0, r.Index - 5);
                    return;
                }
            }
            _status.Text = "That row is not in this timeline (left out, or the timeline was built with other options: timeline_sources.csv says why). Showing the times around it.";
        }

        /// <summary>The source list, keeping the selection when it is still there.</summary>
        void FillTimelineSources(IEnumerable<string> sources)
        {
            var selected = _timelineSource.SelectedItem as string;
            var items = new[] { AllSources }.Concat(sources).ToList();
            if (items.SequenceEqual(_timelineSource.Items.Cast<string>())) return;
            _timelineSource.Items.Clear();
            foreach (var s in items) _timelineSource.Items.Add(s);
            var keep = selected == null ? -1 : items.FindIndex(s => string.Equals(s, selected, StringComparison.OrdinalIgnoreCase));
            _timelineSource.SelectedIndex = keep >= 0 ? keep : 0;
        }
    }
}
