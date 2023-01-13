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

using KeePass.App;
using KeePass.App.Configuration;
using KeePass.DataExchange;
using KeePass.Ecas;
using KeePass.Forms;
using KeePass.Native;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass.UI;
using KeePass.Util;
using KeePass.Util.Archive;
using KeePass.Util.XmlSerialization;
using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Keys;
using KeePassLib.Resources;
using KeePassLib.Serialization;
using KeePassLib.Translation;
using KeePassLib.Utility;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace KeePass
{
    public static class Program
    {
        private const string m_strWndMsgID = "EB2FE38E1A6A4A138CF561442F1CF25A";

        private static CommandLineArgs m_cmdLineArgs = null;
        private static AppConfigEx m_appConfig = null;
        private static KeyProviderPool m_keyProviderPool = null;
        private static KeyValidatorPool m_keyValidatorPool = null;
        private static FileFormatPool m_fmtPool = null;
        private static TempFilesPool m_tempFilesPool = null;
        private static EcasPool m_ecasPool = null;
        private static EcasTriggerSystem m_ecasTriggers = null;
        private static CustomPwGeneratorPool m_pwGenPool = null;
        private static ColumnProviderPool m_colProvPool = null;

        private static bool m_bDesignMode = true;

        public enum AppMessage // int
        {
            Null = 0,
            RestoreWindow = 1,
            Exit = 2,
            IpcByFile = 3, // Handled by all other instances
            AutoType = 4,
            Lock = 5,
            Unlock = 6,
            AutoTypeSelected = 7,
            Cancel = 8,
            AutoTypePassword = 9,
            IpcByFile1 = 10 // Handled by 1 other instance
        }

        public static CommandLineArgs CommandLineArgs
        {
            get
            {
                if (m_cmdLineArgs == null) // No assert (KeePass as library)
                    m_cmdLineArgs = new CommandLineArgs(null);

                return m_cmdLineArgs;
            }
        }

        public static Random GlobalRandom { get; private set; } = null;

        public static int ApplicationMessage { get; private set; } = 0;

        public static MainForm MainForm { get; private set; } = null;

        public static AppConfigEx Config
        {
            get
            {
                if (m_appConfig == null) m_appConfig = new AppConfigEx();
                return m_appConfig;
            }
        }

        public static KeyProviderPool KeyProviderPool
        {
            get
            {
                if (m_keyProviderPool == null) m_keyProviderPool = new KeyProviderPool();
                return m_keyProviderPool;
            }
        }

        public static KeyValidatorPool KeyValidatorPool
        {
            get
            {
                if (m_keyValidatorPool == null) m_keyValidatorPool = new KeyValidatorPool();
                return m_keyValidatorPool;
            }
        }

        public static FileFormatPool FileFormatPool
        {
            get
            {
                if (m_fmtPool == null) m_fmtPool = new FileFormatPool();
                return m_fmtPool;
            }
        }

        public static KPTranslation Translation { get; private set; } = new KPTranslation();

        public static TempFilesPool TempFilesPool
        {
            get
            {
                if (m_tempFilesPool == null) m_tempFilesPool = new TempFilesPool();
                return m_tempFilesPool;
            }
        }

        public static EcasPool EcasPool
        {
            get
            {
                if (m_ecasPool == null) m_ecasPool = new EcasPool(true);
                return m_ecasPool;
            }
        }

        public static EcasTriggerSystem TriggerSystem
        {
            get
            {
                if (m_ecasTriggers == null) m_ecasTriggers = new EcasTriggerSystem();
                return m_ecasTriggers;
            }
        }

        public static CustomPwGeneratorPool PwGeneratorPool
        {
            get
            {
                if (m_pwGenPool == null) m_pwGenPool = new CustomPwGeneratorPool();
                return m_pwGenPool;
            }
        }

        public static ColumnProviderPool ColumnProviderPool
        {
            get
            {
                if (m_colProvPool == null) m_colProvPool = new ColumnProviderPool();
                return m_colProvPool;
            }
        }

        public static ResourceManager Resources => Properties.Resources.ResourceManager;

        public static bool DesignMode => m_bDesignMode;

        public static bool EnableTranslation { get; set; } = true;

        /// <summary>
        /// Main entry point for the application.
        /// </summary>
        [STAThread]
        public static void Main(string[] args)
        {
#if DEBUG
            MainPriv(args);
#else
            try
            {
                MainPriv(args);
            }
			catch(Exception ex)
            {
                // Catch message box exception;
                // https://sourceforge.net/p/keepass/patches/86/
                try { MessageService.ShowFatal(ex); }
                catch (Exception) { Console.Error.WriteLine(ex.ToString()); }
            }
#endif
        }

        private static void MainPriv(string[] args)
        {
            m_bDesignMode = false; // Designer doesn't call Main method
            m_cmdLineArgs = new CommandLineArgs(args);

            // Before loading the configuration
            string strWa = m_cmdLineArgs[AppDefs.CommandLineOptions.WorkaroundDisable];
            strWa = m_cmdLineArgs[AppDefs.CommandLineOptions.WorkaroundEnable];

            DpiUtil.ConfigureProcess();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.DoEvents(); // Required

            if (!CommonInit()) { CommonTerminate(); return; }

            KdbxFile.ConfirmOpenUnknownVersion = delegate ()
            {
                if (!Config.UI.ShowDbOpenUnkVerDialog) return true;

                string strMsg = KPRes.DatabaseOpenUnknownVersionInfo +
                    MessageService.NewParagraph + KPRes.DatabaseOpenUnknownVersionRec +
                    MessageService.NewParagraph + KPRes.DatabaseOpenUnknownVersionQ;
                // No 'Do not show this dialog again' option;
                // https://sourceforge.net/p/keepass/discussion/329220/thread/096c122154/
                return MessageService.AskYesNo(strMsg, PwDefs.ShortProductName,
                    false, MessageBoxIcon.Warning);
            };

            if (m_appConfig.Application.Start.PluginCacheClearOnce)
            {
                PlgxCache.Clear();
                m_appConfig.Application.Start.PluginCacheClearOnce = false;
                AppConfigSerializer.Save(Program.Config);
            }

            if (m_cmdLineArgs[AppDefs.CommandLineOptions.FileExtRegister] != null)
            {
                ShellUtil.RegisterExtension(AppDefs.FileExtension.FileExt,
                    AppDefs.FileExtension.FileExtId, KPRes.FileExtName2,
                    WinUtil.GetExecutable(), PwDefs.ShortProductName, false);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.FileExtUnregister] != null)
            {
                ShellUtil.UnregisterExtension(AppDefs.FileExtension.FileExt,
                    AppDefs.FileExtension.FileExtId);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.PreLoad] != null)
            {
                // All important .NET assemblies are in memory now already
                try { SelfTest.Perform(); }
                catch (Exception) { Debug.Assert(false); }
                MainCleanUp();
                return;
            }
            if ((m_cmdLineArgs[AppDefs.CommandLineOptions.Help] != null) ||
                (m_cmdLineArgs[AppDefs.CommandLineOptions.HelpLong] != null))
            {
                AppHelp.ShowHelp(AppDefs.HelpTopics.CommandLine, null);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigSetUrlOverride] != null)
            {
                Config.Integration.UrlOverride = m_cmdLineArgs[
                    AppDefs.CommandLineOptions.ConfigSetUrlOverride];
                AppConfigSerializer.Save(Program.Config);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigClearUrlOverride] != null)
            {
                Config.Integration.UrlOverride = string.Empty;
                AppConfigSerializer.Save(Config);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigGetUrlOverride] != null)
            {
                try
                {
                    string strFileOut = UrlUtil.EnsureTerminatingSeparator(UrlUtil.GetTempPath(), false) + "KeePass_UrlOverride.tmp";
                    string strContent = ("[KeePass]\r\nKeeURLOverride=" +                        Config.Integration.UrlOverride + "\r\n");
                    File.WriteAllText(strFileOut, strContent);
                }
                catch (Exception) { Debug.Assert(false); }
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigAddUrlOverride] != null)
            {
                bool bAct = (m_cmdLineArgs[AppDefs.CommandLineOptions.Activate] != null);
                Config.Integration.UrlSchemeOverrides.AddCustomOverride(m_cmdLineArgs[AppDefs.CommandLineOptions.Scheme], m_cmdLineArgs[AppDefs.CommandLineOptions.Value], bAct, bAct);
                AppConfigSerializer.Save(Config);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigRemoveUrlOverride] != null)
            {
                Config.Integration.UrlSchemeOverrides.RemoveCustomOverride(m_cmdLineArgs[AppDefs.CommandLineOptions.Scheme], m_cmdLineArgs[AppDefs.CommandLineOptions.Value]);
                AppConfigSerializer.Save(Config);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigSetLanguageFile] != null)
            {
                Config.Application.LanguageFile = m_cmdLineArgs[AppDefs.CommandLineOptions.ConfigSetLanguageFile];
                AppConfigSerializer.Save(Config);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.PlgxCreate] != null)
            {
                PlgxPlugin.CreateFromCommandLine();
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.PlgxCreateInfo] != null)
            {
                PlgxPlugin.CreateInfoFile(m_cmdLineArgs.FileName);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ShowAssemblyInfo] != null)
            {
                MessageService.ShowInfo(Assembly.GetExecutingAssembly().ToString());
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.MakeXmlSerializerEx] != null)
            {
                XmlSerializerEx.GenerateSerializers(m_cmdLineArgs);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.MakeXspFile] != null)
            {
                XspArchive.CreateFile(m_cmdLineArgs.FileName, m_cmdLineArgs["d"]);
                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.Version] != null)
            {
                Console.WriteLine(PwDefs.ShortProductName + " " + PwDefs.VersionString);
                Console.WriteLine(PwDefs.Copyright);
                MainCleanUp();
                return;
            }

            try { ApplicationMessage = NativeMethods.RegisterWindowMessage(m_strWndMsgID); }
            catch (Exception) { Debug.Assert(false); }

            if (m_cmdLineArgs[AppDefs.CommandLineOptions.ExitAll] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.Exit);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.AutoType] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.AutoType);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.AutoTypePassword] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.AutoTypePassword);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.AutoTypeSelected] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.AutoTypeSelected);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.OpenEntryUrl] != null)
            {
                string strEntryUuid = m_cmdLineArgs[AppDefs.CommandLineOptions.Uuid];
                if (!string.IsNullOrEmpty(strEntryUuid))
                {
                    IpcParamEx ipUrl = new IpcParamEx(IpcUtilEx.CmdOpenEntryUrl,
                        strEntryUuid, null, null, null, null);
                    IpcUtilEx.SendGlobalMessage(ipUrl, false);
                }

                MainCleanUp();
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.LockAll] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.Lock);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.UnlockAll] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.Unlock);
                return;
            }
            if (m_cmdLineArgs[AppDefs.CommandLineOptions.Cancel] != null)
            {
                BroadcastAppMessageAndCleanUp(AppMessage.Cancel);
                return;
            }

            string strIpc = m_cmdLineArgs[AppDefs.CommandLineOptions.IpcEvent];
            string strIpc1 = m_cmdLineArgs[AppDefs.CommandLineOptions.IpcEvent1];
            if ((strIpc != null) || (strIpc1 != null))
            {
                bool bIpc1 = (strIpc1 != null);
                string strName = (bIpc1 ? strIpc1 : strIpc);
                if (strName.Length != 0)
                {
                    string[] vFlt = KeyUtil.MakeCtxIndependent(args);

                    IpcParamEx ipcP = new IpcParamEx(IpcUtilEx.CmdIpcEvent, strName, CommandLineArgs.SafeSerialize(vFlt), null, null, null);
                    IpcUtilEx.SendGlobalMessage(ipcP, bIpc1);
                }

                MainCleanUp();
                return;
            }

            bool bSingleLock = GlobalMutexPool.CreateMutex(AppDefs.MutexName, true);

            if (!bSingleLock && m_appConfig.Integration.LimitToSingleInstance)
            {
                ActivatePreviousInstance(args);
                MainCleanUp();
                return;
            }

            Mutex mGlobalNotify = TryGlobalInstanceNotify(AppDefs.MutexNameGlobal);

            AutoType.InitStatic();

            CustomMessageFilterEx cmfx = new CustomMessageFilterEx();
            Application.AddMessageFilter(cmfx);

            MainForm = new MainForm();
            Application.Run(MainForm);

            Application.RemoveMessageFilter(cmfx);

            Debug.Assert(GlobalWindowManager.WindowCount == 0);
            Debug.Assert(MessageService.CurrentMessageCount == 0);

            MainCleanUp();

            if (mGlobalNotify != null) { GC.KeepAlive(mGlobalNotify); }
        }

        /// <summary>
        /// Common program initialization function that can also be
        /// used by applications that use KeePass as a library
        /// (like e.g. KPScript).
        /// </summary>
        public static bool CommonInit()
        {
            m_bDesignMode = false; // Again, for the ones not calling Main

            GlobalRandom = CryptoRandom.NewWeakRandom();

            InitEnvSecurity();
            InitAppContext();

            try { SelfTest.TestFipsComplianceProblems(); }
            catch (Exception exFips)
            {
                MessageService.ShowWarning(KPRes.SelfTestFailed, exFips);
                return false;
            }

            // Set global localized strings
            PwDatabase.LocalizedAppName = PwDefs.ShortProductName;
            KdbxFile.DetermineLanguageId();

            m_appConfig = AppConfigSerializer.Load();
            if (m_appConfig.Logging.Enabled)
                AppLogEx.Open(PwDefs.ShortProductName);

            AppPolicy.Current = m_appConfig.Security.Policy.CloneDeep();
            AppPolicy.ApplyToConfig();

            if (m_appConfig.Security.ProtectProcessWithDacl)
                KeePassLib.Native.NativeMethods.ProtectProcessWithDacl();

            m_appConfig.Apply(AceApplyFlags.All);

            m_ecasTriggers = m_appConfig.Application.TriggerSystem;
            m_ecasTriggers.SetToInitialState();

            LoadTranslation();

            CustomResourceManager.Override(typeof(KeePass.Properties.Resources));

            return true;
        }

        public static void CommonTerminate()
        {
            AppLogEx.Close();

            if (m_tempFilesPool != null)
            {
                m_tempFilesPool.Clear(TempClearFlags.All);
                m_tempFilesPool.WaitForThreads();
            }

            EnableThemingInScope.StaticDispose();
        }

        private static void MainCleanUp()
        {
            IpcBroadcast.StopServer();

            EntryMenu.Destroy();

            GlobalMutexPool.ReleaseAll();

            CommonTerminate();
        }

        private static void InitEnvSecurity()
        {
            try
            {
                // Do not load libraries from the current working directory
                if (!NativeMethods.SetDllDirectory(string.Empty)) { Debug.Assert(false); }
            }
            catch (Exception) { Debug.Assert(false); }

            try
            {
                if (NativeMethods.WerAddExcludedApplication(AppDefs.FileNames.Program, false) < 0)
                {
                    Debug.Assert(false);
                }
            }
            catch (Exception) { Debug.Assert(false); }
        }

        private static void InitAppContext()
        {
            AppContext.SetSwitch("Switch.System.Drawing.Printing.OptimizePrintPreview", true);
        }

        internal static Mutex TryGlobalInstanceNotify(string strBaseName)
        {
            if (strBaseName == null) throw new ArgumentNullException("strBaseName");

            string strName = "Global\\" + strBaseName;
            string strIdentity = Environment.UserDomainName + "\\" +                Environment.UserName;
            MutexSecurity ms = new MutexSecurity();

            MutexAccessRule mar = new MutexAccessRule(strIdentity, MutexRights.FullControl, AccessControlType.Allow);
            ms.AddAccessRule(mar);

            SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            mar = new MutexAccessRule(sid, MutexRights.ReadPermissions | MutexRights.Synchronize, AccessControlType.Allow);
            ms.AddAccessRule(mar);

            return new Mutex(false, strName, out bool _, ms);
        }

        private static void ActivatePreviousInstance(string[] args)
        {
            if ((ApplicationMessage == 0))
            {
                Debug.Assert(false);
                return;
            }

            try
            {
                if (string.IsNullOrEmpty(m_cmdLineArgs.FileName))
                {
                    // NativeMethods.PostMessage((IntPtr)NativeMethods.HWND_BROADCAST,
                    //	m_nAppMessage, (IntPtr)AppMessage.RestoreWindow, IntPtr.Zero);
                    IpcBroadcast.Send(AppMessage.RestoreWindow, 0, false);
                }
                else
                {
                    string[] vFlt = KeyUtil.MakeCtxIndependent(args);

                    IpcParamEx ipcMsg = new IpcParamEx(IpcUtilEx.CmdOpenDatabase,
                        CommandLineArgs.SafeSerialize(vFlt), null, null, null, null);
                    IpcUtilEx.SendGlobalMessage(ipcMsg, true);
                }
            }
            catch (Exception) { Debug.Assert(false); }
        }

        // For plugins
        public static void NotifyUserActivity()
        {
            MainForm mf = MainForm;
            if (mf != null) mf.NotifyUserActivity();
        }

        public static IntPtr GetSafeMainWindowHandle()
        {
            try
            {
                MainForm mf = MainForm;
                if (mf != null) return mf.Handle;
            }
            catch (Exception) { Debug.Assert(false); }

            return IntPtr.Zero;
        }

        private static void BroadcastAppMessageAndCleanUp(AppMessage msg)
        {
            try
            {
                IpcBroadcast.Send(msg, 0, false);
            }
            catch (Exception) { Debug.Assert(false); }

            MainCleanUp();
        }

        private static void LoadTranslation()
        {
            if (!EnableTranslation) return;

            string strPath = m_appConfig.Application.GetLanguageFilePath();
            if (string.IsNullOrEmpty(strPath)) return;

            try
            {
                // Performance optimization
                if (!File.Exists(strPath)) return;

                XmlSerializerEx xs = new XmlSerializerEx(typeof(KPTranslation));
                Translation = KPTranslation.Load(strPath, xs);

                KPRes.SetTranslatedStrings(Translation.SafeGetStringTableDictionary("KeePass.Resources.KPRes"));
                KLRes.SetTranslatedStrings(Translation.SafeGetStringTableDictionary("KeePassLib.Resources.KLRes"));

                StrUtil.RightToLeft = Translation.Properties.RightToLeft;
            }
            catch (Exception) { Debug.Assert(false); }
        }

        internal static bool IsStableAssembly()
        {
            try
            {
                Assembly asm = typeof(Program).Assembly;
                byte[] pk = asm.GetName().GetPublicKeyToken();
                string strPk = MemUtil.ByteArrayToHexString(pk);
                Debug.Assert(string.IsNullOrEmpty(strPk) || (strPk.Length == 16));
                return string.Equals(strPk, "fed2ed7716aecf5c", StrUtil.CaseIgnoreCmp);
            }
            catch (Exception) { Debug.Assert(false); }

            return false;
        }

        internal static bool IsDevelopmentSnapshot()
        {
            return !IsStableAssembly();
        }
    }
}
