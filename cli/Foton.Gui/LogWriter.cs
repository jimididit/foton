using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>
    /// The StatusLog console stream for the log pane: lines written from a worker thread are appended on the UI thread.
    /// The pane keeps the most recent text only; collection.log and the package outputs are the record.
    /// </summary>
    sealed class LogWriter : TextWriter
    {
        const int MaxChars = 2000000;
        readonly TextBox _box;

        public LogWriter(TextBox box) { _box = box; }

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value) => Append(value.ToString());
        public override void Write(string? value) => Append(value ?? "");
        public override void WriteLine(string? value) => Append((value ?? "") + Environment.NewLine);

        void Append(string text)
        {
            // A run can outlive the window: once the pane is gone its lines are dropped, never thrown at the worker.
            if (_box.IsDisposed || !_box.IsHandleCreated) return;
            if (_box.InvokeRequired)
            {
                try { _box.BeginInvoke(new Action<string>(Append), text); }
                catch (Exception ex) when (ex is InvalidOperationException || ex is ObjectDisposedException) { }
                return;
            }
            if (_box.TextLength + text.Length > MaxChars) _box.Text = _box.Text.Substring(_box.TextLength / 2);
            _box.AppendText(text);
        }
    }
}
