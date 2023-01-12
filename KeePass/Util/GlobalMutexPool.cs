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

using KeePassLib.Cryptography;
using KeePassLib.Native;
using KeePassLib.Utility;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace KeePass.Util
{
    /// <summary>
    /// Low performance, system-wide mutex objects pool.
    /// </summary>
    public static class GlobalMutexPool
    {
        private const int GmpMutexRefreshMs = 60 * 1000;

        private const double GmpMutexValidSecs = 190.0;

        private static readonly byte[] GmpOptEnt = { 0x08, 0xA6, 0x5E, 0x40 };

        private static int m_iLastRefresh = 0;

        private static List<KeyValuePair<string, string>> m_vMutexesUnix =
            new List<KeyValuePair<string, string>>();

        private static List<KeyValuePair<string, Mutex>> m_vMutexesWin =
                                                    new List<KeyValuePair<string, Mutex>>();

        public static bool CreateMutex(string strName, bool bInitiallyOwned)
        {
            
                return CreateMutexWin(strName, bInitiallyOwned);

        }

        public static void Refresh()
        {
            return; // Windows, no refresh required
        }

        public static void ReleaseAll()
        {
            
                for (int i = m_vMutexesWin.Count - 1; i >= 0; --i)
                    ReleaseMutexWin(m_vMutexesWin[i].Key);
            
        }

        public static bool ReleaseMutex(string strName)
        {
                return ReleaseMutexWin(strName);

        }

        private static bool CreateMutexUnix(string strName, bool bInitiallyOwned)
        {
            string strPath = GetMutexPath(strName);
            try
            {
                if (File.Exists(strPath))
                {
                    byte[] pbEnc = File.ReadAllBytes(strPath);
                    byte[] pb = CryptoUtil.UnprotectData(pbEnc, GmpOptEnt,
                        DataProtectionScope.CurrentUser);
                    if (pb.Length == 12)
                    {
                        long lTime = MemUtil.BytesToInt64(pb, 0);
                        DateTime dt = DateTime.FromBinary(lTime);

                        if ((DateTime.UtcNow - dt).TotalSeconds < GmpMutexValidSecs)
                        {
                            int pid = MemUtil.BytesToInt32(pb, 8);
                            try
                            {
                                Process.GetProcessById(pid); // Throws if process is not running
                                return false; // Actively owned by other process
                            }
                            catch (Exception) { }
                        }

                        // Release the old mutex since process is not running
                        ReleaseMutexUnix(strName);
                    }
                    else { Debug.Assert(false); }
                }
            }
            catch (Exception) { Debug.Assert(false); }

            try { WriteMutexFilePriv(strPath); }
            catch (Exception) { Debug.Assert(false); }

            m_vMutexesUnix.Add(new KeyValuePair<string, string>(strName, strPath));
            return true;
        }

        private static bool CreateMutexWin(string strName, bool bInitiallyOwned)
        {
            try
            {
                bool bCreatedNew;
                Mutex m = new Mutex(bInitiallyOwned, strName, out bCreatedNew);

                if (bCreatedNew)
                {
                    m_vMutexesWin.Add(new KeyValuePair<string, Mutex>(strName, m));
                    return true;
                }
            }
            catch (Exception) { }

            return false;
        }

        private static string GetMutexPath(string strName)
        {
            string strDir = UrlUtil.EnsureTerminatingSeparator(
                UrlUtil.GetTempPath(), false);
            return (strDir + IpcUtilEx.IpcMsgFilePreID + IpcBroadcast.GetUserID() +
                "-Mutex-" + strName + ".tmp");
        }

        private static bool ReleaseMutexUnix(string strName)
        {
            for (int i = 0; i < m_vMutexesUnix.Count; ++i)
            {
                if (m_vMutexesUnix[i].Key.Equals(strName, StrUtil.CaseIgnoreCmp))
                {
                    for (int r = 0; r < 12; ++r)
                    {
                        try
                        {
                            if (!File.Exists(m_vMutexesUnix[i].Value)) break;

                            File.Delete(m_vMutexesUnix[i].Value);
                            break;
                        }
                        catch (Exception) { }

                        Thread.Sleep(10);
                    }

                    m_vMutexesUnix.RemoveAt(i);
                    return true;
                }
            }

            return false;
        }

        private static bool ReleaseMutexWin(string strName)
        {
            for (int i = 0; i < m_vMutexesWin.Count; ++i)
            {
                if (m_vMutexesWin[i].Key.Equals(strName, StrUtil.CaseIgnoreCmp))
                {
                    try { m_vMutexesWin[i].Value.ReleaseMutex(); }
                    catch (Exception) { Debug.Assert(false); }

                    try { m_vMutexesWin[i].Value.Close(); }
                    catch (Exception) { Debug.Assert(false); }

                    m_vMutexesWin.RemoveAt(i);
                    return true;
                }
            }

            return false;
        }

        private static void WriteMutexFilePriv(string strPath)
        {
            byte[] pb = new byte[12];
            MemUtil.Int64ToBytes(DateTime.UtcNow.ToBinary()).CopyTo(pb, 0);
            MemUtil.Int32ToBytes(Process.GetCurrentProcess().Id).CopyTo(pb, 8);
            byte[] pbEnc = CryptoUtil.ProtectData(pb, GmpOptEnt,
                DataProtectionScope.CurrentUser);
            File.WriteAllBytes(strPath, pbEnc);
        }
    }
}
