using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Foton.Gui
{
    /// <summary>
    /// The StatusLog console stream for the log pane. Worker threads queue text; one UI-thread flush at a time drains the
    /// queue, so a burst of lines is one update, not one posted message per line. The pane keeps the most recent text
    /// only; collection.log and the package outputs are the record.
    /// </summary>
    sealed class LogWriter : TextWriter
    {
        const int MaxChars = 2000000;
        readonly TextBox _box;
        readonly ConcurrentQueue<string> _pending = new ConcurrentQueue<string>();
        int _flushQueued;

        public LogWriter(TextBox box) { _box = box; }

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value) => Append(value.ToString());
        public override void Write(char[] buffer, int index, int count) => Append(new string(buffer, index, count));
        public override void Write(string? value) => Append(value ?? "");
        public override void WriteLine(string? value) => Append((value ?? "") + Environment.NewLine);

        void Append(string text)
        {
            if (text.Length == 0) return;
            _pending.Enqueue(text);
            if (Interlocked.CompareExchange(ref _flushQueued, 1, 0) != 0) return;
            // A run can outlive the window: once the pane is gone its lines are dropped, never thrown at the worker.
            if (_box.IsDisposed || !_box.IsHandleCreated) { Interlocked.Exchange(ref _flushQueued, 0); return; }
            if (!_box.InvokeRequired) { Drain(); return; }
            try { _box.BeginInvoke(new Action(Drain)); }
            catch (Exception ex) when (ex is InvalidOperationException || ex is ObjectDisposedException) { Interlocked.Exchange(ref _flushQueued, 0); }
        }

        /// <summary>UI thread only: appends everything queued so far.</summary>
        void Drain()
        {
            if (_box.IsDisposed) return;
            Interlocked.Exchange(ref _flushQueued, 0);
            var sb = new StringBuilder();
            while (_pending.TryDequeue(out var s)) sb.Append(s);
            if (sb.Length == 0) return;
            if (_box.TextLength + sb.Length > MaxChars) _box.Text = _box.Text.Substring(_box.TextLength / 2);
            _box.AppendText(sb.ToString());
        }
    }
}
