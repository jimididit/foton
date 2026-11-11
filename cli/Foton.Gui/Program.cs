using System;
using System.Windows.Forms;

namespace Foton.Gui
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args.Length == 1 ? args[0] : null));
        }
    }
}
