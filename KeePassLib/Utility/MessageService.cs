/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2023 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using KeePassLib.Resources;
using KeePassLib.Serialization;
using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

namespace KeePassLib.Utility
{
    public static class MessageService
    {
        private const MessageBoxIcon m_mbiFatal = MessageBoxIcon.Error;
        private const MessageBoxIcon m_mbiInfo = MessageBoxIcon.Information;
        private const MessageBoxIcon m_mbiQuestion = MessageBoxIcon.Question;
        private const MessageBoxIcon m_mbiWarning = MessageBoxIcon.Warning;
        private const MessageBoxOptions m_mboRtl = MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign;
        private static volatile uint m_uCurrentMessageCount = 0;

        internal delegate DialogResult SafeShowMessageBoxInternalDelegate(IWin32Window iParent, string strText, string strTitle, MessageBoxButtons mb, MessageBoxIcon mi, MessageBoxDefaultButton mdb);

        public static event EventHandler<MessageServiceEventArgs> MessageShowing;

        public static uint CurrentMessageCount => m_uCurrentMessageCount;
        public static string NewLine => Environment.NewLine;
        public static string NewParagraph => Environment.NewLine + Environment.NewLine;

        public static DialogResult Ask(string strText, string strTitle, MessageBoxButtons mbb)
        {
            ++m_uCurrentMessageCount;

            string strTextEx = (strText ?? string.Empty);
            string strTitleEx = (strTitle ?? PwDefs.ShortProductName);

            MessageShowing?.Invoke(null, new MessageServiceEventArgs(strTitleEx, strTextEx, mbb, m_mbiQuestion));

            DialogResult dr = SafeShowMessageBox(strTextEx, strTitleEx, mbb, m_mbiQuestion, MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
            return dr;
        }

        public static bool AskYesNo(string strText, string strTitle = null, bool bDefaultToYes = true, MessageBoxIcon mbi = m_mbiQuestion)
        {
            ++m_uCurrentMessageCount;

            string strTextEx = (strText ?? string.Empty);
            string strTitleEx = (strTitle ?? PwDefs.ShortProductName);

            MessageShowing?.Invoke(null, new MessageServiceEventArgs(strTitleEx, strTextEx, MessageBoxButtons.YesNo, mbi));

            DialogResult dr = SafeShowMessageBox(strTextEx, strTitleEx, MessageBoxButtons.YesNo, mbi, bDefaultToYes ? MessageBoxDefaultButton.Button1 : MessageBoxDefaultButton.Button2);

            --m_uCurrentMessageCount;
            return (dr == DialogResult.Yes);
        }

        public static void ExternalDecrementMessageCount()
        {
            --m_uCurrentMessageCount;
        }

        public static void ExternalIncrementMessageCount()
        {
            ++m_uCurrentMessageCount;
        }

        public static void ShowFatal(params object[] vLines)
        {
            ++m_uCurrentMessageCount;

            string strTitle = $"{PwDefs.ShortProductName} - {KLRes.FatalError}";
            string strText = $"{KLRes.FatalErrorText}{NewParagraph}{KLRes.ErrorInClipboard}{NewParagraph}{ObjectsToMessage(vLines)}";

            try
            {
                string strDetails = ObjectsToMessage(vLines, true);

                Clipboard.Clear();
                Clipboard.SetText(strDetails);
            }
            catch (Exception) { Debug.Assert(false); }

            MessageShowing?.Invoke(null, new MessageServiceEventArgs(strTitle, strText, MessageBoxButtons.OK, m_mbiFatal));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiFatal, MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }

        public static void ShowInfo(params object[] vLines) => ShowInfoEx(null, vLines);

        public static void ShowInfoEx(string strTitle, params object[] vLines)
        {
            ++m_uCurrentMessageCount;

            strTitle = (strTitle ?? PwDefs.ShortProductName);
            string strText = ObjectsToMessage(vLines);

            MessageShowing?.Invoke(null, new MessageServiceEventArgs(strTitle, strText, MessageBoxButtons.OK, m_mbiInfo));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiInfo, MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }

        public static void ShowLoadWarning(string strFilePath, Exception ex, bool bFullException = false) => ShowWarning(GetLoadWarningMessage(strFilePath, ex, bFullException));

        public static void ShowLoadWarning(IOConnectionInfo ioConnection, Exception ex)
        {
            if (ioConnection != null)
                ShowLoadWarning(ioConnection.GetDisplayName(), ex, false);
            else ShowWarning(ex);
        }

        public static void ShowSaveWarning(string strFilePath, Exception ex, bool bCorruptionWarning)
        {
            FileLockException fl = (ex as FileLockException);
            if (fl != null)
            {
                ShowWarning(fl.Message);
                return;
            }

            string str = GetSaveWarningMessage(strFilePath, ex, bCorruptionWarning);
            ShowWarning(str);
        }

        public static void ShowSaveWarning(IOConnectionInfo ioConnection, Exception ex, bool bCorruptionWarning)
        {
            if (ioConnection != null)
                ShowSaveWarning(ioConnection.GetDisplayName(), ex, bCorruptionWarning);
            else ShowWarning(ex);
        }

        public static void ShowWarning(params object[] vLines)
        {
            ShowWarningPriv(vLines, false);
        }

        internal static string GetLoadWarningMessage(string strFilePath, Exception ex, bool bFullException)
        {
            string str = string.Empty;

            if (!string.IsNullOrEmpty(strFilePath))
                str += $"{strFilePath}{NewParagraph}";

            str += KLRes.FileLoadFailed;

            if ((ex != null) && !string.IsNullOrEmpty(ex.Message))
            {
                str += NewParagraph;
                if (!bFullException) str += ex.Message;
                else str += ObjectsToMessage(new object[] { ex }, true);
            }

            return str;
        }

        internal static string GetSaveWarningMessage(string strFilePath, Exception ex, bool bCorruptionWarning)
        {
            string str = string.Empty;
            if (!string.IsNullOrEmpty(strFilePath))
                str += strFilePath + NewParagraph;

            str += KLRes.FileSaveFailed;

            if ((ex != null) && !string.IsNullOrEmpty(ex.Message))
                str += $"{NewParagraph}{ex.Message}";

            if (bCorruptionWarning)
                str += $"{NewParagraph}{KLRes.FileSaveCorruptionWarning}";

            return str;
        }

        internal static Form GetTopForm()
        {
            FormCollection fc = Application.OpenForms;
            if ((fc == null) || (fc.Count == 0)) return null;

            return fc[fc.Count - 1];
        }

        internal static DialogResult SafeShowMessageBox(string strText, string strTitle, MessageBoxButtons mb, MessageBoxIcon mi, MessageBoxDefaultButton mdb)
        {
            IWin32Window wnd = null;
            try
            {
                Form f = GetTopForm();
                if ((f != null) && f.InvokeRequired)
                    return (DialogResult)f.Invoke(new SafeShowMessageBoxInternalDelegate(
                        SafeShowMessageBoxInternal), f, strText, strTitle, mb, mi, mdb);
                else wnd = f;
            }
            catch (Exception) { Debug.Assert(false); }

            if (wnd == null)
            {
                if (StrUtil.RightToLeft)
                    return MessageBox.Show(strText, strTitle, mb, mi, mdb, m_mboRtl);
                return MessageBox.Show(strText, strTitle, mb, mi, mdb);
            }

            try
            {
                if (StrUtil.RightToLeft)
                    return MessageBox.Show(wnd, strText, strTitle, mb, mi, mdb, m_mboRtl);
                return MessageBox.Show(wnd, strText, strTitle, mb, mi, mdb);
            }
            catch (Exception) { Debug.Assert(false); }

            if (StrUtil.RightToLeft)
                return MessageBox.Show(strText, strTitle, mb, mi, mdb, m_mboRtl);
            return MessageBox.Show(strText, strTitle, mb, mi, mdb);
        }

        internal static DialogResult SafeShowMessageBoxInternal(IWin32Window iParent,
            string strText, string strTitle, MessageBoxButtons mb, MessageBoxIcon mi,
            MessageBoxDefaultButton mdb)
        {
            if (StrUtil.RightToLeft)
                return MessageBox.Show(iParent, strText, strTitle, mb, mi, mdb, m_mboRtl);
            return MessageBox.Show(iParent, strText, strTitle, mb, mi, mdb);
        }

        internal static void ShowWarningExcp(params object[] vLines) => ShowWarningPriv(vLines, true);

        private static string ObjectsToMessage(object[] vLines, bool bFullExceptions = false)
        {
            if (vLines == null) return string.Empty;

            string strNewPara = MessageService.NewParagraph;

            StringBuilder sbText = new StringBuilder();
            bool bSeparator = false;

            foreach (object obj in vLines)
            {
                if (obj == null) continue;

                string strAppend = null;

                Exception exObj = (obj as Exception);
                string strObj = (obj as string);
                StringCollection scObj = (obj as StringCollection);

                if (exObj != null)
                {
                    if (bFullExceptions)
                        strAppend = StrUtil.FormatException(exObj);
                    else if (!string.IsNullOrEmpty(exObj.Message))
                        strAppend = exObj.Message;
                }
                else if (scObj != null)
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (string strCollLine in scObj)
                    {
                        if (sb.Length > 0) sb.AppendLine();
                        sb.Append(strCollLine.TrimEnd());
                    }
                    strAppend = sb.ToString();
                }
                else if (strObj != null)
                    strAppend = strObj;
                else
                    strAppend = obj.ToString();

                if (!string.IsNullOrEmpty(strAppend))
                {
                    if (bSeparator) sbText.Append(strNewPara);
                    else bSeparator = true;

                    sbText.Append(strAppend);
                }
            }

            return sbText.ToString();
        }

        private static void ShowWarningPriv(object[] vLines, bool bFullExceptions)
        {
            ++m_uCurrentMessageCount;

            string strTitle = PwDefs.ShortProductName;
            string strText = ObjectsToMessage(vLines, bFullExceptions);

            if (MessageService.MessageShowing != null)
                MessageService.MessageShowing(null, new MessageServiceEventArgs(
                    strTitle, strText, MessageBoxButtons.OK, m_mbiWarning));

            SafeShowMessageBox(strText, strTitle, MessageBoxButtons.OK, m_mbiWarning,
                MessageBoxDefaultButton.Button1);

            --m_uCurrentMessageCount;
        }
    }

    public sealed class MessageServiceEventArgs : EventArgs
    {
        public MessageServiceEventArgs()
        { }

        public MessageServiceEventArgs(string strTitle, string strText,
            MessageBoxButtons msgButtons, MessageBoxIcon msgIcon)
        {
            Title = (strTitle ?? string.Empty);
            Text = (strText ?? string.Empty);
            Buttons = msgButtons;
            Icon = msgIcon;
        }

        public MessageBoxButtons Buttons { get; private set; } = MessageBoxButtons.OK;

        public MessageBoxIcon Icon { get; private set; } = MessageBoxIcon.None;

        public string Text { get; private set; } = string.Empty;

        public string Title { get; private set; } = string.Empty;
    }
}
