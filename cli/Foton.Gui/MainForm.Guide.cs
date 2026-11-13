using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// Guided start for operators new to Foton: Start here on the Cases tab (collect, baseline, open), and on the Package
    /// tab a checklist of the workstation steps for the open case with Do this next, which runs the first step not done
    /// (the same actions as the buttons and tabs). Step states come from the case's own files and this session.
    /// </summary>
    sealed partial class MainForm
    {
        readonly FlowLayoutPanel _checklist = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4, 0, 4, 4) };
        readonly Button _doNext = new Button { AutoSize = true, Visible = false };
        /// <summary>Package path to whether Verify on the Package tab matched hashes.csv, this session.</summary>
        readonly Dictionary<string, bool> _packageVerified = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        /// <summary>Case roots a handoff was exported for this session.</summary>
        readonly HashSet<string> _handedOff = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Func<Task>? _nextStep;

        readonly ToolTip _stepTips = new ToolTip();
        Font? _stepBold;

        sealed class Step
        {
            public string Name = "";
            public string State = "";
            public bool Done;
            public bool Failed;
            /// <summary>What the step does, shown when the pointer rests on it.</summary>
            public string Hint = "";
            public Func<Task> Do = () => Task.FromResult(0);
        }

        /// <summary>Start here, on top of the Cases tab.</summary>
        Control StartPanel()
        {
            var panel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4, 6, 4, 6), BackColor = SystemColors.Info };
            panel.Controls.Add(new Label { Text = "Start here", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) });
            panel.Controls.Add(AddButton("Build a collector...", CollectorWizard));
            panel.Controls.Add(AddButton("Work a case...", WorkCaseWizard));
            panel.Controls.Add(AddButton("Compare baselines...", CompareWizard));
            panel.Controls.Add(new Label
            {
                AutoSize = true, Padding = new Padding(8, 6, 0, 0),
                Text = "Step-by-step: build a collector for the endpoint, then work the case it brings back. Or select a case below and press Open.",
            });
            return panel;
        }

        /// <summary>What each grid says while it is empty: the next thing to do, for the state the window is in.</summary>
        void EmptyStates()
        {
            Cues.EmptyText(_cases, () => "No case packages in the listed folders yet. Build a collector (Start here), run it on the endpoint, and copy its package here, or press Add folder to list the folder it is in.");
            Cues.EmptyText(_baselines, () => "No baselines yet. Build a baseline collector on the Collectors tab, run it on the host now and again later, then compare the two.");
            Cues.EmptyText(_findings, () => _caseRoot == null ? "Open a case to see its findings: Start here on the Cases tab, or File > Open (Ctrl+O)."
                : _allFindings.Count == 0 ? "No findings in this package yet. Run Analyze, or press Do this next."
                : "No findings match the filters above.");
            Cues.EmptyText(_timeline, () => _caseRoot == null ? "Open a case, then build its timeline here."
                : "No timeline rows to show. Build timeline reads the package's recorded times; run Parse and Compose first for more sources, or clear the filters.");
            Cues.EmptyText(_notesGrid, () => _caseRoot == null ? "Open a case to see its examiner notes."
                : "No examiner notes yet. Set a finding's status on the Package tab, or use Note on row in the Viewer.");
            Cues.EmptyText(_searchHits, () => _caseRoot == null ? "Open a case, then search it for a user name, file name, IP address, or hash."
                : "No hits to show. Type a value above and search: a user name, file name, IP address, or hash.");
            Cues.EmptyText(_compareFindings, () => "Choose the reference (earlier or golden) and the difference baseline above, then press Compare.");
            Cues.EmptyText(_changes, () => "Every field-level change between the two baselines appears here after Compare.");
        }

        /// <summary>The checklist row under the Package tab's buttons.</summary>
        Control Checklist()
        {
            _doNext.Click += async (s, e) => { if (_nextStep != null) await _nextStep(); };
            _actions.Add(_doNext);
            Theme.MarkPrimary(_doNext);
            RefreshChecklist();
            return _checklist;
        }

        List<Step> Steps(string root)
        {
            var stages = CaseIndex.Stages(root);
            var path = _path.Text;
            bool? verified = _packageVerified.TryGetValue(path, out var v) ? v
                : _verified.TryGetValue(path, out var c) ? c.StartsWith("Matches", StringComparison.Ordinal) : (bool?)null;
            var findings = _allFindings.Count;
            var reviewed = _allFindings.Count(HasStatus);
            return new List<Step>
            {
                // Checked is done either way: a package that does not verify stays red here, and the steps go on (they work on it as it is).
                new Step
                {
                    Name = "Verify", Done = verified != null, Failed = verified == false,
                    State = verified == null ? "not checked" : verified.Value ? "matches" : "does not verify",
                    Hint = "Checks every file against the package's hashes.csv.", Do = VerifyOpenPackage,
                },
                new Step { Name = "Parse", Done = stages.Parsed, State = "not yet", Hint = "Reads the copied Prefetch, shortcuts, jump lists, event logs, and Amcache.", Do = () => Run("Parse", Parse) },
                new Step { Name = "Compose", Done = stages.Composed, State = "not yet", Hint = "Runs EZ Tools, Hayabusa, and Chainsaw on the copied files, if installed (Tools tab).", Do = () => Run("Compose", ComposeStep()) },
                new Step { Name = "Analyze", Done = stages.Analyzed, State = "not yet", Hint = "Rebuilds the findings and the report from everything above.", Do = () => Run("Analyze", Analyze) },
                new Step { Name = "Timeline", Done = stages.Timeline, State = "not built", Hint = "Puts the package's recorded times in one list (Timeline tab).", Do = async () => { if (_timelinePage != null) _tabs.SelectedTab = _timelinePage; await BuildTimeline(); } },
                new Step
                {
                    // An analyze with no findings leaves nothing to review.
                    Name = "Review", Done = findings == 0 ? stages.Analyzed : reviewed == findings,
                    State = findings == 0 ? (stages.Analyzed ? "no findings" : "no findings yet") : $"{reviewed} of {findings} reviewed",
                    Hint = "Give each finding a status and note (Package tab, under its details).",
                    Do = () => { ReviewNextFinding(); return Task.FromResult(0); },
                },
                new Step { Name = "Hand off", Done = _handedOff.Contains(root), State = "not exported", Hint = "Writes the review for another examiner (Notes tab).", Do = () => ExportHandoff(_settings.HandoffsFolder) },
            };
        }

        /// <summary>UI thread: redraws the checklist for the open case (file checks only, cheap).</summary>
        void RefreshChecklist()
        {
            _checklist.SuspendLayout();
            var old = _checklist.Controls.Cast<Control>().Where(c => c != _doNext).ToList();
            _checklist.Controls.Clear();
            // The tooltip keeps every control given a tip; only step labels have one, so drop them all before disposing.
            _stepTips.RemoveAll();
            foreach (var c in old) c.Dispose();
            var root = _caseRoot;
            if (root == null)
            {
                _nextStep = null;
                _doNext.Visible = false;
                _checklist.ResumeLayout();
                return;
            }
            _checklist.Controls.Add(new Label { Text = "Next steps", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 6, 0), Margin = new Padding(0, 3, 3, 3) });
            List<Step> steps;
            try { steps = Steps(root); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                _checklist.Controls.Add(new Label { Text = "Steps not read: " + Foton.Core.TextFile.OneLine(ex.Message), AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
                _checklist.ResumeLayout();
                return;
            }
            var next = steps.FirstOrDefault(s => !s.Done);
            if (_stepBold == null || Math.Abs(_stepBold.Size - _checklist.Font.Size) > 0.01f)
            {
                _stepBold?.Dispose();
                _stepBold = new Font(_checklist.Font, FontStyle.Bold);
            }
            // One short entry per step: a check mark when done (a cross when the package does not verify), its state
            // otherwise, the next step in bold. The color repeats what the text says.
            foreach (var s in steps)
            {
                var label = new Label
                {
                    Text = s.Failed ? "\u2717 " + s.Name + ": " + s.State : s.Done ? "\u2713 " + s.Name : s.Name + ": " + s.State,
                    AutoSize = true, Padding = new Padding(4, 6, 8, 0),
                    ForeColor = s.Failed ? Color.DarkRed : s.Done ? Color.DarkGreen : SystemColors.ControlText,
                };
                if (s == next) label.Font = _stepBold;
                _stepTips.SetToolTip(label, s.Hint);
                _checklist.Controls.Add(label);
            }
            _nextStep = next?.Do;
            _doNext.Text = next == null ? "" : "Do this next: " + next.Name;
            _doNext.Visible = next != null;
            _checklist.Controls.Add(_doNext);
            _checklist.ResumeLayout();
        }

        /// <summary>Verify on the Package tab, with the result kept for the checklist.</summary>
        async Task VerifyOpenPackage()
        {
            var path = _path.Text;
            int? code = null;
            await Run("Verify", (log, p) => { var r = Verify(log, p); code = (int)r; return r; });
            if (code != null) _packageVerified[path] = code == 0;
            RefreshChecklist();
        }

        /// <summary>Review: the Package tab with only findings that have no status yet, the first one selected.</summary>
        void ReviewNextFinding()
        {
            if (_packagePage != null) _tabs.SelectedTab = _packagePage;
            _severityFilter.SelectedIndex = 0;
            _findingsFind.Text = "";
            _statusFilter.SelectedIndex = 1 + Array.IndexOf(NoteStatus.All, NoteStatus.NotReviewed);
            _status.Text = "Set each finding's status under its details and press Save note.";
        }
    }
}
