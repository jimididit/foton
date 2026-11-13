using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>What a step's Next did: go on (with a message for the status line), or stay and say why.</summary>
    sealed class StepResult
    {
        public bool Go { get; private set; }
        public string Message { get; private set; } = "";
        public static StepResult Next(string message = "") => new StepResult { Go = true, Message = message };
        public static StepResult Stay(string message) => new StepResult { Go = false, Message = message };
    }

    /// <summary>One step of a wizard: what it is for, its controls, and what Next does.</summary>
    sealed class WizardStep
    {
        public string Name = "";
        /// <summary>What this step does, in a sentence or two.</summary>
        public string Text = "";
        /// <summary>Builds the step's controls each time the step is shown (so they reflect the console's state).</summary>
        public Func<Control> Build = () => new Panel();
        /// <summary>The Next button's text on this step (an action such as "Verify", or plain "Next").</summary>
        public string NextText = "Next";
        /// <summary>
        /// Runs when Next is pressed: an action, a check, or nothing. Returns the message for the status line and whether
        /// to go on; a step that cannot go on says why.
        /// </summary>
        public Func<Task<StepResult>> Next = () => Task.FromResult(StepResult.Next());
        /// <summary>Whether Skip may pass this step without running it.</summary>
        public bool Skippable;
        /// <summary>A closing step (Done): Next closes the wizard once its action, if any, succeeds.</summary>
        public bool Final;
    }

    /// <summary>
    /// A guided sequence over the console's own actions: a step bar (done, current, still to come), what the step does,
    /// its controls, and Back, Skip, Next, and Close. Each step runs the same code as the tab it stands for; nothing here
    /// acquires or changes evidence by itself. While a step runs, the buttons wait and the wizard cannot be closed.
    /// </summary>
    sealed class WizardDialog : Form
    {
        readonly IReadOnlyList<WizardStep> _steps;
        readonly FlowLayoutPanel _bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(12, 10, 12, 4) };
        readonly Label _stepOf = new Label { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(14, 0, 12, 0), ForeColor = SystemColors.GrayText };
        readonly Label _text = new Label { Dock = DockStyle.Top, AutoSize = true, MaximumSize = new Size(640, 0), Padding = new Padding(14, 6, 12, 10) };
        readonly Panel _body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 0, 14, 6) };
        readonly Label _message = new Label { Dock = DockStyle.Bottom, AutoSize = true, MaximumSize = new Size(640, 0), Padding = new Padding(14, 4, 12, 4) };
        readonly Button _back = new Button { Text = "< Back", AutoSize = true };
        readonly Button _skip = new Button { Text = "Skip", AutoSize = true };
        readonly Button _next = new Button { AutoSize = true };
        readonly Button _close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        readonly HashSet<int> _done = new HashSet<int>();
        int _at;
        bool _running;
        bool _finished;
        Font? _bold;

        public WizardDialog(string title, IReadOnlyList<WizardStep> steps)
        {
            _steps = steps;
            Text = title;
            Font = new Font("Segoe UI", 9f);
            Size = new Size(720, 520);
            MinimumSize = new Size(620, 440);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            ShowIcon = false;
            MinimizeBox = MaximizeBox = false;

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            buttons.Controls.Add(_close);
            buttons.Controls.Add(_next);
            buttons.Controls.Add(_skip);
            buttons.Controls.Add(_back);
            _back.Click += (s, e) => { if (_at > 0) Show(_at - 1, ""); };
            _skip.Click += (s, e) => { if (_at < _steps.Count - 1) Show(_at + 1, _steps[_at].Name + " skipped."); };
            _next.Click += async (s, e) => await NextClicked();
            AcceptButton = _next;
            CancelButton = _close;
            FormClosing += (s, e) => { if (_running) e.Cancel = true; };

            Controls.Add(_body);
            Controls.Add(_message);
            Controls.Add(buttons);
            Controls.Add(_text);
            Controls.Add(_stepOf);
            Controls.Add(_bar);
            Theme.MarkPrimary(_next);
            Theme.Adopt(this);
            Show(0, "");
        }

        /// <summary>Shows a step: the bar, its text, freshly built controls, and the buttons it allows.</summary>
        void Show(int index, string message)
        {
            _at = index;
            var step = _steps[index];
            _bar.SuspendLayout();
            foreach (Control c in _bar.Controls) c.Dispose();
            _bar.Controls.Clear();
            if (_bold == null || Math.Abs(_bold.Size - Font.Size) > 0.01f) { _bold?.Dispose(); _bold = new Font(Font, FontStyle.Bold); }
            for (int i = 0; i < _steps.Count; i++)
            {
                var label = new Label { AutoSize = true, Padding = new Padding(0, 2, 14, 2), Text = (_done.Contains(i) ? "\u2713 " : (i + 1) + ". ") + _steps[i].Name };
                label.ForeColor = i == index ? SystemColors.ControlText : _done.Contains(i) ? Color.DarkGreen : SystemColors.GrayText;
                if (i == index) label.Font = _bold;
                _bar.Controls.Add(label);
            }
            _bar.ResumeLayout();
            _stepOf.Text = $"Step {index + 1} of {_steps.Count}";
            _text.Text = step.Text;
            foreach (Control c in _body.Controls) c.Dispose();
            _body.Controls.Clear();
            var content = step.Build();
            content.Dock = DockStyle.Fill;
            _body.Controls.Add(content);
            SetMessage(message);
            _finished = false;
            Buttons();
        }

        void Buttons()
        {
            var step = _steps[_at];
            _back.Enabled = !_running && _at > 0 && !_finished;
            _skip.Visible = step.Skippable && _at < _steps.Count - 1;
            _skip.Enabled = !_running;
            _next.Text = _finished ? "Finish" : step.NextText;
            _next.Enabled = !_running;
            _close.Enabled = !_running;
        }

        void SetMessage(string message)
        {
            _message.Text = message;
            Theme.SetFore(_message, message.StartsWith("Not ", StringComparison.Ordinal) || message.StartsWith("Stopped", StringComparison.Ordinal) ? Color.DarkRed : SystemColors.ControlText);
        }

        async Task NextClicked()
        {
            if (_finished) { DialogResult = DialogResult.OK; Close(); return; }
            _running = true;
            Buttons();
            SetMessage("Working...");
            StepResult result;
            try { result = await _steps[_at].Next(); }
            catch (Exception ex) { result = StepResult.Stay("Stopped: " + Foton.Core.TextFile.OneLine(ex.Message)); }
            _running = false;
            if (!result.Go) { SetMessage(result.Message); Buttons(); return; }
            _done.Add(_at);
            if (_steps[_at].Final) { DialogResult = DialogResult.OK; Close(); return; }
            if (_at < _steps.Count - 1) { Show(_at + 1, result.Message); return; }
            // Last step done: say so and offer Finish.
            Show(_at, result.Message);
            _finished = true;
            Buttons();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _bold?.Dispose();
            base.Dispose(disposing);
        }
    }
}
