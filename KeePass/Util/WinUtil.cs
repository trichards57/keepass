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

using KeePass.Forms;
using KeePass.Native;
using KeePass.Resources;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Delegates;
using KeePassLib.Serialization;
using KeePassLib.Utility;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using NativeLib = KeePassLib.Native.NativeLib;

namespace KeePass.Util
{
    public static class WinUtil
    {
        private static readonly Lazy<string> g_strAsmVersion = new Lazy<string>(() => typeof(WinUtil).Assembly.GetName().Version.ToString(4));
        private static readonly Lazy<string> m_strExePath = new Lazy<string>(() => Assembly.GetExecutingAssembly().Location);
        private static ulong m_uFrameworkVersion = 0;
        public static event EventHandler<OpenUrlEventArgs> OpenUrlPre;

        /// <summary>
        /// Shorten a path.
        /// </summary>
        /// <param name="strPath">Path to make shorter.</param>
        /// <param name="cchMax">Maximum number of characters in the returned string.</param>
        /// <returns>Shortened path.</returns>
        public static string CompactPath(string strPath, int cchMax)
        {
            if (strPath == null) throw new ArgumentNullException("strPath");
            if (cchMax < 0) throw new ArgumentOutOfRangeException("cchMax");

            if (strPath.Length <= cchMax) return strPath;
            if (cchMax == 0) return string.Empty;

            try
            {
                var sb = new StringBuilder(strPath.Length + 2);

                if (NativeMethods.PathCompactPathEx(sb, strPath, (uint)cchMax + 1, 0))
                {
                    if ((sb.Length <= cchMax) && (sb.Length != 0))
                        return sb.ToString();
                    else { Debug.Assert(false); }
                }
            }
            catch (Exception) { Debug.Assert(false); }

            return StrUtil.CompactString3Dots(strPath, cchMax);
        }

        public static bool FlushStorageBuffers(char chDriveLetter, bool bOnlyIfRemovable)
        {
            var strDriveLetter = new string(chDriveLetter, 1);
            var bResult = true;

            try
            {
                if (bOnlyIfRemovable)
                {
                    var di = new DriveInfo(strDriveLetter);
                    if (di.DriveType != DriveType.Removable) return true;
                }

                var strDevice = "\\\\.\\" + strDriveLetter + ":";

                var hDevice = NativeMethods.CreateFile(strDevice,
                    NativeMethods.EFileAccess.GenericRead | NativeMethods.EFileAccess.GenericWrite,
                    NativeMethods.EFileShare.Read | NativeMethods.EFileShare.Write,
                    IntPtr.Zero, NativeMethods.ECreationDisposition.OpenExisting,
                    0, IntPtr.Zero);
                if (NativeMethods.IsInvalidHandleValue(hDevice))
                {
                    Debug.Assert(false);
                    return false;
                }

                var strDir = FreeDriveIfCurrent(chDriveLetter);

                if (NativeMethods.DeviceIoControl(hDevice, NativeMethods.FSCTL_LOCK_VOLUME,
                    IntPtr.Zero, 0, IntPtr.Zero, 0, out var dwDummy, IntPtr.Zero))
                {
                    if (!NativeMethods.DeviceIoControl(hDevice, NativeMethods.FSCTL_UNLOCK_VOLUME,
                        IntPtr.Zero, 0, IntPtr.Zero, 0, out dwDummy, IntPtr.Zero))
                    {
                        Debug.Assert(false);
                    }
                }
                else bResult = false;

                if (strDir.Length > 0) SetWorkingDirectory(strDir);

                if (!NativeMethods.CloseHandle(hDevice)) { Debug.Assert(false); }
            }
            catch (Exception)
            {
                Debug.Assert(false);
                return false;
            }

            return bResult;
        }

        public static bool FlushStorageBuffers(string strFileOnStorage, bool bOnlyIfRemovable)
        {
            if (strFileOnStorage == null) { Debug.Assert(false); return false; }
            if (strFileOnStorage.Length < 3) return false;
            if (strFileOnStorage[1] != ':') return false;
            if (strFileOnStorage[2] != '\\') return false;

            return FlushStorageBuffers(char.ToUpper(strFileOnStorage[0]), bOnlyIfRemovable);
        }

        // See IsCommandLineUrl when editing this method
        public static string GetCommandLineFromUrl(string strUrl)
        {
            if (strUrl == null) { Debug.Assert(false); return string.Empty; }

            if (strUrl.StartsWith("cmd://", StringComparison.InvariantCultureIgnoreCase)) return strUrl.Remove(0, 6);
            if (strUrl.StartsWith("\\\\", StringComparison.InvariantCultureIgnoreCase)) return strUrl; // UNC path support

            return strUrl;
        }

        public static string GetExecutable() => m_strExePath.Value;

        public static ulong GetMaxNetFrameworkVersion()
        {
            var u = m_uFrameworkVersion;
            if (u != 0) return u;

            // https://www.mono-project.com/docs/about-mono/releases/
            ulong m = NativeLib.MonoVersion;
            if (m >= 0x0006000600000000UL) u = 0x0004000800000000UL;
            else if (m >= 0x0005001200000000UL) u = 0x0004000700020000UL;
            else if (m >= 0x0005000A00000000UL) u = 0x0004000700010000UL;
            else if (m >= 0x0005000400000000UL) u = 0x0004000700000000UL;
            else if (m >= 0x0004000600000000UL) u = 0x0004000600020000UL;
            else if (m >= 0x0004000400000000UL) u = 0x0004000600010000UL;
            else if (m >= 0x0003000800000000UL) u = 0x0004000500010000UL;
            else if (m >= 0x0003000000000000UL) u = 0x0004000500000000UL;

            if (u == 0)
            {
                try { u = GetMaxNetVersionPriv(); }
                catch (Exception) { Debug.Assert(false); }
            }

            if (u == 0)
            {
                Version v = Environment.Version;
                if (v.Major > 0) u |= (uint)v.Major;
                u <<= 16;
                if (v.Minor > 0) u |= (uint)v.Minor;
                u <<= 16;
                if (v.Build > 0) u |= (uint)v.Build;
                u <<= 16;
                if (v.Revision > 0) u |= (uint)v.Revision;
            }

            m_uFrameworkVersion = u;
            return u;
        }

        public static byte[] HashFile(IOConnectionInfo iocFile)
        {
            if (iocFile == null) { Debug.Assert(false); return null; } // Assert only

            Stream sIn;
            try
            {
                sIn = IOConnection.OpenRead(iocFile);
                if (sIn == null) throw new FileNotFoundException();
            }
            catch (Exception) { return null; }

            byte[] pbHash;
            try
            {
                using (SHA256Managed sha256 = new SHA256Managed())
                {
                    pbHash = sha256.ComputeHash(sIn);
                }
            }
            catch (Exception) { Debug.Assert(false); sIn.Close(); return null; }

            sIn.Close();
            return pbHash;
        }

        // See GetCommandLineFromUrl when editing this method
        public static bool IsCommandLineUrl(string strUrl)
        {
            if (strUrl == null) { Debug.Assert(false); return false; }

            if (strUrl.StartsWith("cmd://", StringComparison.InvariantCultureIgnoreCase)) return true;
            if (strUrl.StartsWith("\\\\", StringComparison.InvariantCultureIgnoreCase)) return true; // UNC path support

            return false;
        }

        public static string LocateSystemApp(string strExeName)
        {
            if (strExeName == null) { Debug.Assert(false); return string.Empty; }
            if (strExeName.Length == 0) return strExeName;

            try
            {
                string str = null;
                for (int i = 0; i < 3; ++i)
                {
                    if (i == 0)
                        str = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    else if (i == 1)
                        str = Environment.GetEnvironmentVariable("WinDir");
                    else if (i == 2)
                        str = Environment.GetEnvironmentVariable("SystemRoot");

                    if (!string.IsNullOrEmpty(str))
                    {
                        str = UrlUtil.EnsureTerminatingSeparator(str, false);
                        str += strExeName;

                        if (File.Exists(str)) return str;
                    }
                }
            }
            catch (Exception) { Debug.Assert(false); }

            return strExeName;
        }

        public static void OpenEntryUrl(PwEntry pe)
        {
            if (pe == null) { Debug.Assert(false); throw new ArgumentNullException("pe"); }

            string strUrl = pe.Strings.ReadSafe(PwDefs.UrlField);

            // The user interface enables the URL open command if and
            // only if the URL is not empty, i.e. it ignores overrides
            if (strUrl.Length == 0) return;

            if (pe.OverrideUrl.Length > 0)
                OpenUrl(pe.OverrideUrl, pe, true, strUrl);
            else
            {
                string strOverride = Program.Config.Integration.UrlOverride;
                if (strOverride.Length > 0)
                    OpenUrl(strOverride, pe, true, strUrl);
                else
                    OpenUrl(strUrl, pe, true);
            }
        }

        public static void OpenUrl(string strUrlToOpen, PwEntry peDataSource)
        {
            OpenUrl(strUrlToOpen, peDataSource, true, null);
        }

        public static void OpenUrl(string strUrlToOpen, PwEntry peDataSource,
            bool bAllowOverride)
        {
            OpenUrl(strUrlToOpen, peDataSource, bAllowOverride, null);
        }

        public static void OpenUrl(string strUrlToOpen, PwEntry peDataSource, bool bAllowOverride, string strBaseRaw)
        {
            VoidDelegate f = delegate ()
            {
                try { OpenUrlPriv(strUrlToOpen, peDataSource, bAllowOverride, strBaseRaw); }
                catch (Exception) { Debug.Assert(false); }
            };

            MainForm mf = Program.MainForm;
            if ((mf != null) && mf.InvokeRequired) mf.Invoke(f);
            else f();
        }

        public static void OpenUrlWithApp(string strUrlToOpen, PwEntry peDataSource, string strAppPath)
        {
            if (string.IsNullOrEmpty(strUrlToOpen)) { Debug.Assert(false); return; }
            if (string.IsNullOrEmpty(strAppPath)) { Debug.Assert(false); return; }

            string strUrl = strUrlToOpen.Trim();
            if (strUrl.Length == 0) { Debug.Assert(false); return; }
            strUrl = SprEncoding.EncodeForCommandLine(strUrl);

            string strApp = strAppPath.Trim();
            if (strApp.Length == 0) { Debug.Assert(false); return; }
            strApp = SprEncoding.EncodeForCommandLine(strApp);

            string str = "cmd://\"" + strApp + "\" \"" + strUrl + "\"";
            OpenUrl(str, peDataSource, false);
        }

        public static void RemoveZoneIdentifier(string strFilePath)
        {
            if (string.IsNullOrEmpty(strFilePath)) { Debug.Assert(false); return; }

            try
            {
                string strZoneId = strFilePath + ":Zone.Identifier";

                if (NativeMethods.FileExists(strZoneId))
                    NativeMethods.DeleteFile(strZoneId);
            }
            catch (Exception) { Debug.Assert(false); }
        }

        public static void Restart()
        {
            try { NativeLib.StartProcess(GetExecutable()); }
            catch (Exception ex) { MessageService.ShowWarning(ex); }
        }

        public static bool RunElevated(string strExe, string strArgs, bool bShowMessageIfFailed)
        {
            if (strExe == null)
                throw new ArgumentNullException("strExe");

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = strExe
                };
                if (!string.IsNullOrEmpty(strArgs)) psi.Arguments = strArgs;
                psi.UseShellExecute = true;

                psi.Verb = "runas";

                NativeLib.StartProcess(psi);
            }
            catch (Exception ex)
            {
                if (bShowMessageIfFailed) MessageService.ShowWarning(ex);
                return false;
            }

            return true;
        }

        public static void SetWorkingDirectory(string strWorkDir)
        {
            string str = strWorkDir; // May be null

            if (!string.IsNullOrEmpty(str))
            {
                try { if (!Directory.Exists(str)) str = null; }
                catch (Exception) { Debug.Assert(false); str = null; }
            }

            if (string.IsNullOrEmpty(str))
                str = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            try { Directory.SetCurrentDirectory(str); }
            catch (Exception) { Debug.Assert(false); }
        }

        internal static string CompileUrl(string strUrlToOpen, PwEntry pe, bool bAllowOverride, string strBaseRaw, bool? obForceEncCmd)
        {
            MainForm mf = Program.MainForm;
            PwDatabase pd = null;
            try { if (mf != null) pd = mf.DocumentManager.SafeFindContainerOf(pe); }
            catch (Exception) { Debug.Assert(false); }

            string strUrlFlt = strUrlToOpen;
            strUrlFlt = strUrlFlt.TrimStart(new char[] { ' ', '\t', '\r', '\n' });

            bool bEncCmd = obForceEncCmd ?? IsCommandLineUrl(strUrlFlt);

            SprContext ctx = new SprContext(pe, pd, SprCompileFlags.All, false, bEncCmd)
            {
                Base = strBaseRaw,
                BaseIsEncoded = false
            };

            string strUrl = SprEngine.Compile(strUrlFlt, ctx);

            string strOvr = Program.Config.Integration.UrlSchemeOverrides.GetOverrideForUrl(strUrl);
            if (!bAllowOverride) strOvr = null;
            if (strOvr != null)
            {
                bool bEncCmdOvr = WinUtil.IsCommandLineUrl(strOvr);

                var ctxOvr = new SprContext(pe, pd, SprCompileFlags.All, false, bEncCmdOvr)
                {
                    Base = strUrl,
                    BaseIsEncoded = bEncCmd
                };

                strUrl = SprEngine.Compile(strOvr, ctxOvr);
            }

            return strUrl;
        }

        internal static string GetAssemblyVersion() => g_strAsmVersion.Value;

        internal static void OpenUrlDirectly(string strUrl)
        {
            if (string.IsNullOrEmpty(strUrl)) { Debug.Assert(false); return; }

            try { NativeLib.StartProcess(strUrl); }
            catch (Exception ex) { MessageService.ShowWarning(strUrl, ex); }
        }

        internal static void ShowFileInFileManager(string strFilePath, bool bShowError)
        {
            if (string.IsNullOrEmpty(strFilePath)) { Debug.Assert(false); return; }

            try
            {
                string strDir = UrlUtil.GetFileDirectory(strFilePath, false, true);

                string strExplorer = WinUtil.LocateSystemApp("Explorer.exe");

                if (File.Exists(strFilePath))
                    NativeLib.StartProcess(strExplorer, "/select,\"" +
                        NativeLib.EncodeDataToArgs(strFilePath) + "\"");
                else
                    NativeLib.StartProcess(strDir);
            }
            catch (Exception ex)
            {
                if (bShowError)
                    MessageService.ShowWarning(strFilePath, ex.Message);
            }
        }

        private static string FreeDriveIfCurrent(char chDriveLetter)
        {
            try
            {
                string strCur = Directory.GetCurrentDirectory();
                if ((strCur == null) || (strCur.Length < 3)) return string.Empty;
                if (strCur[1] != ':') return string.Empty;
                if (strCur[2] != '\\') return string.Empty;

                char chPar = char.ToUpper(chDriveLetter);
                char chCur = char.ToUpper(strCur[0]);
                if (chPar != chCur) return string.Empty;

                string strTemp = UrlUtil.GetTempPath();
                WinUtil.SetWorkingDirectory(strTemp);

                return strCur;
            }
            catch (Exception) { Debug.Assert(false); }

            return string.Empty;
        }

        private static ulong GetMaxNetVersionPriv()
        {
            RegistryKey kNdp = Registry.LocalMachine.OpenSubKey(
                "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP", false);
            if (kNdp == null) { Debug.Assert(false); return 0; }

            ulong uMaxVer = 0;

            string[] vInNdp = kNdp.GetSubKeyNames();
            foreach (string strInNdp in vInNdp)
            {
                if (strInNdp == null) { Debug.Assert(false); continue; }
                if (!strInNdp.StartsWith("v", StrUtil.CaseIgnoreCmp)) continue;

                RegistryKey kVer = kNdp.OpenSubKey(strInNdp, false);
                if (kVer != null)
                {
                    UpdateNetVersionFromRegKey(kVer, ref uMaxVer);

                    string[] vProfiles = kVer.GetSubKeyNames();
                    foreach (string strProfile in vProfiles)
                    {
                        if (string.IsNullOrEmpty(strProfile)) { Debug.Assert(false); continue; }

                        RegistryKey kPro = kVer.OpenSubKey(strProfile, false);
                        UpdateNetVersionFromRegKey(kPro, ref uMaxVer);
                        kPro?.Close();
                    }

                    kVer.Close();
                }
                else { Debug.Assert(false); }
            }

            kNdp.Close();
            return uMaxVer;
        }

        private static void OpenUrlPriv(string strUrlToOpen, PwEntry peDataSource, bool bAllowOverride, string strBaseRaw)
        {
            if (string.IsNullOrEmpty(strUrlToOpen)) { Debug.Assert(false); return; }

            if (WinUtil.OpenUrlPre != null)
            {
                OpenUrlEventArgs e = new OpenUrlEventArgs(strUrlToOpen, peDataSource,
                    bAllowOverride, strBaseRaw);
                WinUtil.OpenUrlPre(null, e);
                strUrlToOpen = e.Url;

                if (string.IsNullOrEmpty(strUrlToOpen)) return;
            }

            string strPrevWorkDir = Directory.GetCurrentDirectory();
            string strThisExe = WinUtil.GetExecutable();

            string strExeDir = UrlUtil.GetFileDirectory(strThisExe, false, true);
            WinUtil.SetWorkingDirectory(strExeDir);

            string strUrl = CompileUrl(strUrlToOpen, peDataSource, bAllowOverride,
                strBaseRaw, null);

            if (string.IsNullOrEmpty(strUrl)) { } // Might be placeholder only
            else if (WinUtil.IsCommandLineUrl(strUrl))
            {
                StrUtil.SplitCommandLine(WinUtil.GetCommandLineFromUrl(strUrl), out var strApp, out var strArgs);

                try
                {
                    try { NativeLib.StartProcess(strApp, strArgs); }
                    catch (Win32Exception)
                    {
                        ProcessStartInfo psi = new ProcessStartInfo
                        {
                            FileName = strApp
                        };
                        if (!string.IsNullOrEmpty(strArgs)) psi.Arguments = strArgs;
                        psi.UseShellExecute = false;

                        NativeLib.StartProcess(psi);
                    }
                }
                catch (Exception exCmd)
                {
                    string strMsg = KPRes.FileOrUrl + ": " + strApp;
                    if (!string.IsNullOrEmpty(strArgs))
                        strMsg += MessageService.NewParagraph +
                            KPRes.Arguments + ": " + strArgs;

                    MessageService.ShowWarning(strMsg, exCmd);
                }
            }
            else // Standard URL
            {
                try { NativeLib.StartProcess(strUrl); }
                catch (Exception exUrl)
                {
                    MessageService.ShowWarning(strUrl, exUrl);
                }
            }

            // Restore previous working directory
            WinUtil.SetWorkingDirectory(strPrevWorkDir);

            peDataSource?.Touch(false);

            // SprEngine.Compile might have modified the database
            MainForm mf = Program.MainForm;
            if (mf != null)
            {
                mf.RefreshEntriesList();
                mf.UpdateUI(false, null, false, null, false, null, false);
            }
        }

        private static void UpdateNetVersionFromRegKey(RegistryKey k, ref ulong uMaxVer)
        {
            if (k == null) { Debug.Assert(false); return; }

            try
            {
                // https://msdn.microsoft.com/en-us/library/hh925568.aspx
                string strInstall = k.GetValue("Install", string.Empty).ToString();
                if ((strInstall.Length > 0) && (strInstall != "1")) return;

                string strVer = k.GetValue("Version", string.Empty).ToString();
                if (strVer.Length > 0)
                {
                    ulong uVer = StrUtil.ParseVersion(strVer);
                    if (uVer > uMaxVer) uMaxVer = uVer;
                }
            }
            catch (Exception) { Debug.Assert(false); }
        }
    }

    public sealed class OpenUrlEventArgs : EventArgs
    {
        public OpenUrlEventArgs(string strUrlToOpen, PwEntry peDataSource,
            bool bAllowOverride, string strBaseRaw)
        {
            Url = strUrlToOpen;
            Entry = peDataSource;
            AllowOverride = bAllowOverride;
            BaseRaw = strBaseRaw;
        }

        public bool AllowOverride { get; }

        public string BaseRaw { get; }

        public PwEntry Entry { get; }

        public string Url { get; set; }
    }
}
