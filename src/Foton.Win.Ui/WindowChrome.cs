using System;
using System.Drawing;
using System.Runtime.InteropServices;

namespace Foton.Win.Ui
{
    /// <summary>
    /// The parts of a window Windows draws itself: the title bar (DWM) and the scroll bars, tree glyphs, and drop-down
    /// buttons of common controls (visual-style themes). Only documented calls: DwmSetWindowAttribute with the dark-mode
    /// and caption-color attributes, and SetWindowTheme with the DarkMode_* class names Windows ships. On a Windows build
    /// without them the call fails and the window keeps Windows' light drawing; nothing here throws.
    /// </summary>
    public static class WindowChrome
    {
        // Windows 10 20H1 and later; Windows 11 adds the caption, text, and border colors.
        const int DwmUseImmersiveDarkMode = 20;
        const int DwmBorderColor = 34;
        const int DwmCaptionColor = 35;
        const int DwmTextColor = 36;
        /// <summary>DWMWA_COLOR_DEFAULT: Windows' own color for that part.</summary>
        const int DwmColorDefault = unchecked((int)0xFFFFFFFF);

        [DllImport("dwmapi.dll", ExactSpelling = true)]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

        [DllImport("uxtheme.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        static extern int SetWindowTheme(IntPtr hwnd, string? subAppName, string? subIdList);

        /// <summary>
        /// Title bar of a top-level window: dark or light, and on Windows 11 the caption, its text, and the frame in the
        /// palette's colors (null restores Windows' own).
        /// </summary>
        public static void TitleBar(IntPtr hwnd, Palette? palette)
        {
            if (hwnd == IntPtr.Zero) return;
            Set(hwnd, DwmUseImmersiveDarkMode, palette != null && palette.IsDark ? 1 : 0);
            Set(hwnd, DwmCaptionColor, palette == null ? DwmColorDefault : ColorRef(palette.Back));
            Set(hwnd, DwmTextColor, palette == null ? DwmColorDefault : ColorRef(palette.Text));
            Set(hwnd, DwmBorderColor, palette == null ? DwmColorDefault : ColorRef(palette.Border));
        }

        /// <summary>What a control's Windows-drawn parts should look like.</summary>
        public enum Parts
        {
            /// <summary>Windows' default theme for the control.</summary>
            Default,
            /// <summary>Scroll bars, tree expand glyphs, list headers (Explorer's dark theme).</summary>
            DarkExplorer,
            /// <summary>Drop-down button and list of a combo box (the common file dialog's dark theme).</summary>
            DarkComboBox,
        }

        public static void Control(IntPtr hwnd, Parts parts)
        {
            if (hwnd == IntPtr.Zero) return;
            try
            {
                switch (parts)
                {
                    case Parts.DarkExplorer: SetWindowTheme(hwnd, "DarkMode_Explorer", null); break;
                    case Parts.DarkComboBox: SetWindowTheme(hwnd, "DarkMode_CFD", null); break;
                    default: SetWindowTheme(hwnd, null, null); break;   // both null: back to the default association
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException) { }
        }

        static void Set(IntPtr hwnd, int attribute, int value)
        {
            try { DwmSetWindowAttribute(hwnd, attribute, ref value, sizeof(int)); }
            catch (Exception ex) when (ex is DllNotFoundException || ex is EntryPointNotFoundException) { }
        }

        /// <summary>COLORREF is 0x00BBGGRR.</summary>
        static int ColorRef(Color c) => c.R | (c.G << 8) | (c.B << 16);
    }
}
