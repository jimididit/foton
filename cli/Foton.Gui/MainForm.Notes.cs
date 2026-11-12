using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// Examiner notes (the same analysis\examiner_notes.json foton notes reads and writes): a review status and note per
    /// finding (Package tab: Status column, filters, note editor) and per artifact row (Note on row in the Viewer and
    /// Timeline), and the Notes tab listing them all. Shown as examiner input everywhere, never as a finding.
    /// </summary>
    sealed partial class MainForm
    {
        const string AnySeverity = "(any severity)", AnyStatus = "(any status)";
        List<Dictionary<string, string?>> _allFindings = new List<Dictionary<string, string?>>();
        ExaminerNotesFile? _notes;
        /// <summary>Why the package's notes cannot be read; notes are then not editable, so the file is never overwritten.</summary>
        string? _notesProblem;
        /// <summary>The examiner name last saved with a note this session.</summary>
        string _noteExaminerName = "";
        readonly ComboBox _severityFilter = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        readonly ComboBox _statusFilter = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        readonly TextBox _findingsFind = new TextBox { Width = 200 };
        readonly Label _findingsShown = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
        readonly ComboBox _noteStatus = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
        readonly TextBox _noteExaminer = new TextBox { Width = 160, MaxLength = ExaminerNotes.MaxExaminer };
        readonly TextBox _noteText = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true, MaxLength = ExaminerNotes.MaxText };
        readonly Button _noteSave = new Button { Text = "Save note", AutoSize = true };
        readonly Label _noteAbout = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 22, Padding = new Padding(2, 4, 0, 0), ForeColor = SystemColors.GrayText };
        TabPage? _notesPage;
        readonly DataGridView _notesGrid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };
        readonly Label _notesSummary = new Label { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };

        /// <summary>Severity, status, and text filters over the Package tab's findings.</summary>
        Control FindingsFilterBar()
        {
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(2) };
            _severityFilter.Items.AddRange(new object[] { AnySeverity }.Concat(SeverityOrder).ToArray());
            _statusFilter.Items.Add(AnyStatus);
            foreach (var s in NoteStatus.All) _statusFilter.Items.Add(NoteStatus.Label(s));
            _severityFilter.SelectedIndex = _statusFilter.SelectedIndex = 0;
            _severityFilter.SelectedIndexChanged += (s, e) => RefreshFindingsView();
            _statusFilter.SelectedIndexChanged += (s, e) => RefreshFindingsView();
            _findingsFind.TextChanged += (s, e) => RefreshFindingsView();
            bar.Controls.Add(new Label { Text = "Severity", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            bar.Controls.Add(_severityFilter);
            bar.Controls.Add(new Label { Text = "Status", AutoSize = true, Padding = new Padding(6, 6, 0, 0) });
            bar.Controls.Add(_statusFilter);
            bar.Controls.Add(new Label { Text = "Find", AutoSize = true, Padding = new Padding(6, 6, 0, 0) });
            bar.Controls.Add(_findingsFind);
            bar.Controls.Add(_findingsShown);
            return bar;
        }

        /// <summary>The note editor under a finding's details.</summary>
        Control NoteEditor()
        {
            var panel = new Panel { Dock = DockStyle.Bottom, Height = 170, Padding = new Padding(0, 4, 0, 0) };
            foreach (var s in NoteStatus.All) _noteStatus.Items.Add(NoteStatus.Label(s));
            _noteStatus.SelectedIndex = 0;
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false };
            bar.Controls.Add(new Label { Text = "Status", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            bar.Controls.Add(_noteStatus);
            bar.Controls.Add(new Label { Text = "Examiner", AutoSize = true, Padding = new Padding(4, 6, 0, 0) });
            bar.Controls.Add(_noteExaminer);
            bar.Controls.Add(_noteSave);
            _noteSave.Click += (s, e) => SaveFindingNote();
            panel.Controls.Add(_noteText);
            panel.Controls.Add(bar);
            panel.Controls.Add(_noteAbout);
            _findings.SelectionChanged += (s, e) => ShowSelectedNote();
            ShowSelectedNote();
            return panel;
        }

        /// <summary>UI thread: reads the open package's notes. A file that cannot be read stops note editing (it is never overwritten).</summary>
        void LoadNotes(string? caseRoot)
        {
            _notes = null;
            _notesProblem = null;
            if (caseRoot == null) return;
            try { _notes = ExaminerNotes.Load(caseRoot); }
            catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException)
            {
                _notesProblem = "Examiner notes cannot be read, so they are not editable here: " + TextFile.OneLine(ex.Message);
                _status.Text = _notesProblem;
            }
        }

        ExaminerNote? NoteFor(string kind, string key) =>
            _notes?.Notes.FirstOrDefault(n => n.Kind == kind && string.Equals(n.Key, key, StringComparison.OrdinalIgnoreCase));

        void ShowFindings(IEnumerable<Dictionary<string, string?>> rows)
        {
            _allFindings = rows.ToList();
            RefreshFindingsView();
        }

        /// <summary>The findings grid: every finding with its review status, through the filters, most severe first; keeps the selected finding.</summary>
        void RefreshFindingsView()
        {
            string V(Dictionary<string, string?> r, string k) => r.TryGetValue(k, out var v) ? v ?? "" : "";
            var keep = SelectedFindingKey();
            var severity = _severityFilter.SelectedItem as string;
            var statusIndex = _statusFilter.SelectedIndex - 1;
            var find = _findingsFind.Text;
            var table = new DataTable();
            foreach (var c in new[] { "Severity", "Status", "Tier", "Category", "Title", "Observation", "WhyItMatters", "Artifact", "NextStep", "Key" }) table.Columns.Add(c);
            foreach (var r in _allFindings.OrderBy(r => Array.IndexOf(SeverityOrder, V(r, "Severity")) is int i && i >= 0 ? i : SeverityOrder.Length))
            {
                var key = ExaminerNotes.FindingKey(r);
                var status = NoteFor(ExaminerNote.FindingKind, key)?.Status ?? NoteStatus.NotReviewed;
                if (severity != null && severity != AnySeverity && !string.Equals(V(r, "Severity"), severity, StringComparison.OrdinalIgnoreCase)) continue;
                if (statusIndex >= 0 && status != NoteStatus.All[statusIndex]) continue;
                if (find.Length > 0 && !new[] { "Title", "Observation", "Category", "Artifact", "WhyItMatters", "NextStep" }.Any(k => V(r, k).IndexOf(find, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                table.Rows.Add(V(r, "Severity"), NoteStatus.Label(status), V(r, "Tier"), V(r, "Category"), V(r, "Title"), V(r, "Observation"), V(r, "WhyItMatters"), V(r, "Artifact"), V(r, "NextStep"), key);
            }
            _findings.DataSource = table;
            var withStatus = _allFindings.Count(r => NoteFor(ExaminerNote.FindingKind, ExaminerNotes.FindingKey(r)) != null);
            _findingsShown.Text = $"{table.Rows.Count} of {_allFindings.Count} shown; {withStatus} with an examiner status";
            if (keep != null) SelectFinding(keep);
            // Selecting during a rebind does not always raise SelectionChanged: show the selected finding's details here.
            if (table.Rows.Count == 0) _details.Clear();
            else ShowDetails(_findings, _details);
            ShowSelectedNote();
        }

        string? SelectedFindingKey() =>
            _findings.CurrentRow?.DataBoundItem is DataRowView v && v.Row.Table.Columns.Contains("Key") ? Convert.ToString(v["Key"], CultureInfo.InvariantCulture) : null;

        bool SelectFinding(string key)
        {
            foreach (DataGridViewRow r in _findings.Rows)
            {
                if (r.DataBoundItem is DataRowView v && string.Equals(Convert.ToString(v["Key"], CultureInfo.InvariantCulture), key, StringComparison.OrdinalIgnoreCase))
                {
                    _findings.CurrentCell = r.Cells.Cast<DataGridViewCell>().First(c => c.Visible);
                    return true;
                }
            }
            return false;
        }

        /// <summary>The note editor for the selected finding.</summary>
        void ShowSelectedNote()
        {
            var key = SelectedFindingKey();
            var note = key == null ? null : NoteFor(ExaminerNote.FindingKind, key);
            var editable = key != null && _caseRoot != null && _notesProblem == null;
            _noteStatus.Enabled = _noteExaminer.Enabled = _noteText.Enabled = _noteSave.Enabled = editable;
            _noteStatus.SelectedIndex = Math.Max(0, Array.IndexOf(NoteStatus.All, note?.Status ?? NoteStatus.NotReviewed));
            _noteExaminer.Text = note?.Examiner ?? DefaultExaminer();
            _noteText.Text = note?.Text ?? "";
            _noteAbout.Text = _notesProblem ?? (note != null
                ? $"Examiner note (examiner input), saved {note.UpdatedUtc} UTC"
                : "Examiner note (examiner input, kept apart from the findings)");
        }

        string DefaultExaminer() => _noteExaminerName.Length > 0 ? _noteExaminerName : ChainOfCustody.ReadHeader(_caseRoot).Examiner ?? "";

        void SaveFindingNote()
        {
            if (!(_findings.CurrentRow?.DataBoundItem is DataRowView v)) return;
            string V(string k) => Convert.ToString(v[k], CultureInfo.InvariantCulture) ?? "";
            SaveNote(new ExaminerNote
            {
                Kind = ExaminerNote.FindingKind, Key = V("Key"), Label = V("Title"), Artifact = V("Artifact"),
                Status = NoteStatus.All[Math.Max(0, _noteStatus.SelectedIndex)], Text = _noteText.Text, Examiner = _noteExaminer.Text,
            });
        }

        /// <summary>Stores a note (foton notes' rules: re-read first, Not reviewed with no text removes it) and refreshes every view of notes.</summary>
        void SaveNote(ExaminerNote note)
        {
            var root = _caseRoot;
            if (root == null || _notesProblem != null) return;
            try
            {
                var stored = ExaminerNotes.Set(root, note);
                if (note.Examiner.Trim().Length > 0) _noteExaminerName = note.Examiner.Trim();
                _status.Text = stored == null ? "Note removed (Not reviewed, no text)." : "Note saved: " + NoteStatus.Label(stored.Status) + " - " + TextFile.OneLine(stored.Label);
            }
            catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                _status.Text = "Note not saved: " + TextFile.OneLine(ex.Message);
            }
            LoadNotes(root);
            RefreshFindingsView();
            if (_tabs.SelectedTab == _notesPage) _ = RefreshNotes();
        }

        /// <summary>Note on a row of a package CSV (Viewer, Timeline): reads the row now, so the note records what it said.</summary>
        async Task NoteOnRow(string artifact, int row)
        {
            var root = _caseRoot;
            if (root == null) return;
            if (_notesProblem != null) { _status.Text = _notesProblem; return; }
            List<string>? cells;
            try { cells = await Task.Run(() => ExaminerNotes.ReadRow(root, artifact, row)); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
            {
                _status.Text = "Row not read: " + TextFile.OneLine(ex.Message);
                return;
            }
            if (cells == null || root != _caseRoot) { _status.Text = $"{artifact} has no data row {row} in this package."; return; }
            var key = ExaminerNotes.RowKey(artifact, row);
            var existing = NoteFor(ExaminerNote.RowKind, key);
            var sha = ExaminerNotes.RowSha256(cells);
            var what = $"{artifact} row {row}: {ExaminerNotes.RowLabel(cells)}";
            if (existing != null && !string.Equals(existing.RowSha256, sha, StringComparison.OrdinalIgnoreCase))
                what += "\r\nThis row reads differently from when it was noted; saving records it as it reads now.";
            using (var d = new NoteDialog(what, existing?.Status ?? NoteStatus.Reviewed, existing?.Examiner ?? DefaultExaminer(), existing?.Text ?? ""))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                SaveNote(new ExaminerNote
                {
                    Kind = ExaminerNote.RowKind, Key = key, Artifact = artifact, Row = row, RowSha256 = sha, Label = ExaminerNotes.RowLabel(cells),
                    Status = d.Status, Text = d.NoteText, Examiner = d.Examiner,
                });
            }
        }

        TabPage NotesTab()
        {
            var page = new TabPage("Notes");
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            bar.Controls.Add(AddButton("Refresh", RefreshNotes, needsPackage: true));
            bar.Controls.Add(AddButton("Go to", GoToNote, needsPackage: true));
            bar.Controls.Add(AddButton("Edit note...", EditSelectedNote, needsPackage: true));
            bar.Controls.Add(_notesSummary);
            var note = new Label
            {
                Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4), ForeColor = SystemColors.GrayText,
                Text = "Examiner input from analysis\\examiner_notes.json (also listed by foton notes). Notes are never dropped: a note whose finding a later analyze no longer produces stays here.",
            };
            _notesGrid.DataBindingComplete += (s, e) =>
            {
                var weights = new Dictionary<string, float> { ["On"] = 12, ["Status"] = 9, ["Note"] = 34, ["What"] = 30, ["Artifact"] = 22, ["Row"] = 5, ["Row check"] = 12, ["Examiner"] = 9, ["Updated (UTC)"] = 12 };
                foreach (DataGridViewColumn c in _notesGrid.Columns)
                {
                    if (weights.TryGetValue(c.Name, out var w)) c.FillWeight = w;
                    else c.Visible = false;
                }
            };
            _notesGrid.CellDoubleClick += async (s, e) => { if (e.RowIndex >= 0) await GoToNote(); };
            _tabs.Selected += async (s, e) => { if (e.TabPage == _notesPage && _caseRoot != null) await RefreshNotes(); };
            page.Controls.Add(_notesGrid);
            page.Controls.Add(note);
            page.Controls.Add(bar);
            return page;
        }

        async Task RefreshNotes()
        {
            var root = _caseRoot;
            if (root == null) return;
            NotesReview review;
            try { review = await Task.Run(() => ExaminerNotes.Review(root)); }
            catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException)
            {
                _notesGrid.DataSource = null;
                _notesSummary.Text = "Examiner notes cannot be read: " + TextFile.OneLine(ex.Message);
                return;
            }
            if (root != _caseRoot) return;
            var table = new DataTable();
            foreach (var c in new[] { "On", "Status", "Note", "What", "Artifact" }) table.Columns.Add(c);
            table.Columns.Add("Row", typeof(int));
            foreach (var c in new[] { "Row check", "Examiner", "Updated (UTC)", "Kind", "Key" }) table.Columns.Add(c);
            string First(string text) => TextFile.OneLine(text.Split('\n')[0]);
            foreach (var f in review.Findings.Where(f => f.UpdatedUtc.Length > 0))
                table.Rows.Add("Finding (" + f.Severity + ")", NoteStatus.Label(f.Status), First(f.Text), f.Title, f.Artifact, DBNull.Value, "", f.Examiner, f.UpdatedUtc, ExaminerNote.FindingKind, f.Key);
            foreach (var n in review.NotInLatestFindings)
                table.Rows.Add("Finding not in the latest analyze", NoteStatus.Label(n.Status), First(n.Text), n.Label, n.Artifact, DBNull.Value, "", n.Examiner, n.UpdatedUtc, ExaminerNote.FindingKind, n.Key);
            foreach (var r in review.Rows)
                table.Rows.Add("Row", NoteStatus.Label(r.Note.Status), First(r.Note.Text), r.Note.Label, r.Note.Artifact, r.Note.Row, r.State, r.Note.Examiner, r.Note.UpdatedUtc, ExaminerNote.RowKind, r.Note.Key);
            _notesGrid.DataSource = table;
            int Count(string status) => review.Findings.Count(f => f.Status == status);
            _notesSummary.Text = review.FindingsSource.Length == 0
                ? $"No findings yet (run Analyze); {review.Rows.Count} row note(s)"
                : $"{review.Findings.Count} findings: {review.Findings.Count(f => f.Status != NoteStatus.NotReviewed)} with a status " +
                  $"({Count(NoteStatus.Relevant)} relevant, {Count(NoteStatus.FollowUp)} follow up, {Count(NoteStatus.NotRelevant)} not relevant, {Count(NoteStatus.Reviewed)} reviewed); " +
                  $"{review.NotInLatestFindings.Count} note(s) on findings not in the latest analyze; {review.Rows.Count} row note(s)";
        }

        DataRowView? SelectedNoteRow() => _notesGrid.CurrentRow?.DataBoundItem as DataRowView;

        /// <summary>A finding note opens the finding on the Package tab (filters cleared); a row note opens its row in the Viewer.</summary>
        Task GoToNote()
        {
            var v = SelectedNoteRow();
            if (v == null) { _status.Text = "Select a note first."; return Task.FromResult(0); }
            string V(string k) => Convert.ToString(v[k], CultureInfo.InvariantCulture) ?? "";
            if (V("Kind") == ExaminerNote.RowKind)
            {
                _tabs.SelectedTab = _viewer.Page;
                if (!_viewer.Select(V("Artifact"), v["Row"] is int n ? n : 0)) _status.Text = "Not in this package: " + V("Artifact");
                return Task.FromResult(0);
            }
            _severityFilter.SelectedIndex = _statusFilter.SelectedIndex = 0;
            _findingsFind.Text = "";
            if (_packagePage != null) _tabs.SelectedTab = _packagePage;
            if (!SelectFinding(V("Key"))) _status.Text = "That finding is not in the latest findings; its note is kept on the Notes tab.";
            return Task.FromResult(0);
        }

        async Task EditSelectedNote()
        {
            var v = SelectedNoteRow();
            if (v == null) { _status.Text = "Select a note first."; return; }
            string V(string k) => Convert.ToString(v[k], CultureInfo.InvariantCulture) ?? "";
            if (V("Kind") == ExaminerNote.RowKind) { await NoteOnRow(V("Artifact"), v["Row"] is int n ? n : 0); return; }
            var existing = NoteFor(ExaminerNote.FindingKind, V("Key"));
            if (existing == null) { _status.Text = "That note was not found; Refresh the list."; return; }
            using (var d = new NoteDialog("Finding: " + existing.Label, existing.Status, existing.Examiner, existing.Text))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                SaveNote(new ExaminerNote
                {
                    Kind = ExaminerNote.FindingKind, Key = existing.Key, Label = existing.Label, Artifact = existing.Artifact,
                    Status = d.Status, Text = d.NoteText, Examiner = d.Examiner,
                });
            }
            await RefreshNotes();
        }
    }
}
