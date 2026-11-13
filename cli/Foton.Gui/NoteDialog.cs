using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>Edits one examiner note: status, examiner, and text. Labelled as examiner input, apart from findings.</summary>
    sealed class NoteDialog : Form
    {
        readonly ComboBox _status = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        readonly TextBox _examiner = new TextBox { Width = 260 };
        readonly TextBox _text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true, MaxLength = ExaminerNotes.MaxText };

        public NoteDialog(string what, string status, string examiner, string text)
        {
            Text = "Examiner note";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(640, 420);
            MinimumSize = new Size(480, 320);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            MinimizeBox = MaximizeBox = false;
            foreach (var s in NoteStatus.All) _status.Items.Add(NoteStatus.Label(s));
            _status.SelectedIndex = System.Math.Max(0, System.Array.IndexOf(NoteStatus.All, status));
            _examiner.Text = examiner;
            _examiner.MaxLength = ExaminerNotes.MaxExaminer;
            _text.Text = text;

            var header = new Label
            {
                Dock = DockStyle.Top, AutoSize = false, Height = 52, Padding = new Padding(6),
                Text = what + "\r\nExaminer input: kept in analysis\\examiner_notes.json, apart from Foton's findings.",
            };
            var fields = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4) };
            fields.Controls.Add(new Label { Text = "Status", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            fields.Controls.Add(_status);
            fields.Controls.Add(new Label { Text = "Examiner", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
            fields.Controls.Add(_examiner);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var save = new Button { Text = "Save note", DialogResult = DialogResult.OK, AutoSize = true };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(save);
            AcceptButton = null;   // Enter adds a line to the note
            CancelButton = cancel;
            var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(6, 0, 6, 0) };
            body.Controls.Add(_text);
            Controls.Add(body);
            Controls.Add(buttons);
            Controls.Add(fields);
            Controls.Add(header);
            Theme.Adopt(this);
        }

        public string Status => NoteStatus.All[_status.SelectedIndex < 0 ? 0 : _status.SelectedIndex];
        public string Examiner => _examiner.Text;
        public string NoteText => _text.Text;
    }
}
