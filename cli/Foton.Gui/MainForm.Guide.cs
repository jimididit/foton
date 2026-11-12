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
        TabPage? _acquirePage;
        readonly FlowLayoutPanel _checklist = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4, 0, 4, 4) };
        readonly Button _doNext = new Button { AutoSize = true, Visible = false };
        /// <summary>Package path to whether Verify on the Package tab matched hashes.csv, this session.</summary>
        readonly Dictionary<string, bool> _packageVerified = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        /// <summary>Case roots a handoff was exported for this session.</summary>
        readonly HashSet<string> _handedOff = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Func<Task>? _nextStep;

        sealed class Step
        {
            public string Name = "";
            public string State = "";
            public bool Done;
            public Func<Task> Do = () => Task.FromResult(0);
        }

        /// <summary>Start here, on top of the Cases tab.</summary>
        Control StartPanel()
        {
            var panel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4, 6, 4, 6), BackColor = SystemColors.Info };
            panel.Controls.Add(new Label { Text = "Start here", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 8, 0) });
            panel.Controls.Add(AddButton("Collect this PC...", () => { if (_acquirePage != null) _tabs.SelectedTab = _acquirePage; _status.Text = "Acquire: fill in the case number and examiner, then Collect this PC."; }));
            panel.Controls.Add(AddButton("Baseline this PC...", () => { if (_acquirePage != null) _tabs.SelectedTab = _acquirePage; _status.Text = "Acquire: Baseline this PC records stable configuration to compare later."; }));
            panel.Controls.Add(AddButton("Open a case folder...", async () => { var p = PickFolder(); if (p != null) { if (_packagePage != null) _tabs.SelectedTab = _packagePage; await Open(p); } }));
            panel.Controls.Add(AddButton("Open a ZIP...", async () => { var p = PickZip(); if (p != null) { if (_packagePage != null) _tabs.SelectedTab = _packagePage; await Open(p); } }));
            panel.Controls.Add(new Label
            {
                AutoSize = true, Padding = new Padding(8, 6, 0, 0),
                Text = "Or select a case below and press Open. The Package tab then lists the next steps for it.",
            });
            return panel;
        }

        /// <summary>The checklist row under the Package tab's buttons.</summary>
        Control Checklist()
        {
            _doNext.Click += async (s, e) => { if (_nextStep != null) await _nextStep(); };
            _actions.Add(_doNext);
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
                new Step { Name = "Verify", Done = verified != null, State = verified == null ? "not checked" : verified.Value ? "matches" : "DOES NOT VERIFY", Do = VerifyOpenPackage },
                new Step { Name = "Parse", Done = stages.Parsed, State = stages.Parsed ? "done" : "not yet", Do = () => Run("Parse", Parse) },
                new Step { Name = "Compose", Done = stages.Composed, State = stages.Composed ? "done" : "not yet (EZ Tools, Hayabusa, Chainsaw: Tools tab)", Do = () => Run("Compose", ComposeStep()) },
                new Step { Name = "Analyze", Done = stages.Analyzed, State = stages.Analyzed ? "done" : "not yet", Do = () => Run("Analyze", Analyze) },
                new Step { Name = "Timeline", Done = stages.Timeline, State = stages.Timeline ? "built" : "not built", Do = async () => { if (_timelinePage != null) _tabs.SelectedTab = _timelinePage; await BuildTimeline(); } },
                new Step
                {
                    // An analyze with no findings leaves nothing to review.
                    Name = "Review", Done = findings == 0 ? stages.Analyzed : reviewed == findings,
                    State = findings == 0 ? (stages.Analyzed ? "no findings" : "no findings yet") : $"{reviewed} of {findings} findings have a status",
                    Do = () => { ReviewNextFinding(); return Task.FromResult(0); },
                },
                new Step { Name = "Hand off", Done = _handedOff.Contains(root), State = _handedOff.Contains(root) ? "exported" : "not exported", Do = () => ExportHandoff(_settings.HandoffsFolder) },
            };
        }

        /// <summary>UI thread: redraws the checklist for the open case (file checks only, cheap).</summary>
        void RefreshChecklist()
        {
            _checklist.SuspendLayout();
            var old = _checklist.Controls.Cast<Control>().Where(c => c != _doNext).ToList();
            _checklist.Controls.Clear();
            foreach (var c in old) c.Dispose();
            var root = _caseRoot;
            if (root == null)
            {
                _nextStep = null;
                _doNext.Visible = false;
                _checklist.ResumeLayout();
                return;
            }
            _checklist.Controls.Add(new Label { Text = "Next steps", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 6, 6, 0) });
            List<Step> steps;
            try { steps = Steps(root); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                _checklist.Controls.Add(new Label { Text = "Steps not read: " + Foton.Core.TextFile.OneLine(ex.Message), AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
                _checklist.ResumeLayout();
                return;
            }
            int n = 0;
            foreach (var s in steps)
            {
                _checklist.Controls.Add(new Label
                {
                    Text = $"{++n}. {s.Name}: {s.State}", AutoSize = true, Padding = new Padding(4, 6, 4, 0),
                    ForeColor = s.State.StartsWith("DOES NOT", StringComparison.Ordinal) ? Color.DarkRed : s.Done ? Color.DarkGreen : SystemColors.ControlText,
                });
            }
            var next = steps.FirstOrDefault(s => !s.Done);
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
