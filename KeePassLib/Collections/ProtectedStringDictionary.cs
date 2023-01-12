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

using KeePassLib.Interfaces;
using KeePassLib.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;

namespace KeePassLib.Collections
{
    /// <summary>
    /// A dictionary of <c>ProtectedString</c> objects.
    /// </summary>
    public sealed class ProtectedStringDictionary :
        IDeepCloneable<ProtectedStringDictionary>,
        IEnumerable<KeyValuePair<string, ProtectedString>>
    {
        private readonly SortedDictionary<string, ProtectedString> m_vStrings =
            new SortedDictionary<string, ProtectedString>();

        /// <summary>
        /// Construct a new dictionary of protected strings.
        /// </summary>
        public ProtectedStringDictionary()
        {
        }

        /// <summary>
        /// Get the number of strings.
        /// </summary>
        public uint UCount => (uint)m_vStrings.Count;

        public void Clear() => m_vStrings.Clear();

        public ProtectedStringDictionary CloneDeep()
        {
            ProtectedStringDictionary d = new ProtectedStringDictionary();
            CopyTo(d);
            return d;
        }

        public void EnableProtection(string strField, bool bProtect)
        {
            ProtectedString ps = Get(strField);

            if (ps == null)
                return;

            if (ps.IsProtected != bProtect)
                Set(strField, ps.WithProtection(bProtect));
        }

        public bool EqualsDictionary(ProtectedStringDictionary dict, PwCompareOptions pwOpt, MemProtCmpMode mpCompare)
        {
            if (dict == null)
            {
                Debug.Assert(false);
                return false;
            }

            bool bNeEqStd = ((pwOpt & PwCompareOptions.NullEmptyEquivStd) != PwCompareOptions.None);

            if (!bNeEqStd && m_vStrings.Count != dict.m_vStrings.Count)
                return false;

            foreach (var kvp in m_vStrings)
            {
                var bStdField = PwDefs.IsStandardField(kvp.Key);
                var ps = dict.Get(kvp.Key);

                if (bNeEqStd && (ps == null) && bStdField)
                    ps = ProtectedString.Empty;

                if (ps == null)
                    return false;

                if (mpCompare == MemProtCmpMode.Full)
                {
                    if (ps.IsProtected != kvp.Value.IsProtected)
                        return false;
                }
                else if (mpCompare == MemProtCmpMode.CustomOnly)
                {
                    if (!bStdField && (ps.IsProtected != kvp.Value.IsProtected))
                        return false;
                }

                if (!ps.Equals(kvp.Value, false)) return false;
            }

            if (bNeEqStd)
            {
                foreach (var kvp in dict.m_vStrings)
                {
                    var ps = Get(kvp.Key);

                    if (ps != null)
                        continue; // Compared previously

                    if (!PwDefs.IsStandardField(kvp.Key))
                        return false;

                    if (!kvp.Value.IsEmpty)
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Test if a named string exists.
        /// </summary>
        /// <param name="strName">Name of the string to try.</param>
        /// <returns>Returns <c>true</c> if the string exists, otherwise <c>false</c>.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if
        /// <paramref name="strName" /> is <c>null</c>.</exception>
        public bool Exists(string strName)
        {
            if (strName == null)
                throw new ArgumentNullException("strName");

            return m_vStrings.ContainsKey(strName);
        }

        /// <summary>
        /// Get one of the protected strings.
        /// </summary>
        /// <param name="strName">String identifier.</param>
        /// <returns>Protected string. If the string identified by
        /// <paramref name="strName" /> cannot be found, the function
        /// returns <c>null</c>.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the input
        /// parameter is <c>null</c>.</exception>
        public ProtectedString Get(string strName)
        {
            if (strName == null)
                throw new ArgumentNullException("strName");

            if (m_vStrings.TryGetValue(strName, out var ps)) return ps;

            return null;
        }

        public IEnumerator<KeyValuePair<string, ProtectedString>> GetEnumerator() => m_vStrings.GetEnumerator();

        public List<string> GetKeys() => new List<string>(m_vStrings.Keys);

        /// <summary>
        /// Get one of the protected strings. The return value is never <c>null</c>.
        /// If the requested string cannot be found, an empty protected string
        /// object is returned.
        /// </summary>
        /// <param name="strName">String identifier.</param>
        /// <returns>Returns a protected string object. If the standard string
        /// has not been set yet, the return value is an empty string (<c>""</c>).</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the input
        /// parameter is <c>null</c>.</exception>
        public ProtectedString GetSafe(string strName)
        {
            if (strName == null) throw new ArgumentNullException("strName");

            if (m_vStrings.TryGetValue(strName, out var ps))
                return ps;

            return ProtectedString.Empty;
        }

        /// <summary>
        /// Get one of the protected strings. If the string doesn't exist, the
        /// return value is an empty string (<c>""</c>).
        /// </summary>
        /// <param name="strName">Name of the requested string.</param>
        /// <returns>Requested string value or an empty string, if the named
        /// string doesn't exist.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the input
        /// parameter is <c>null</c>.</exception>
        public string ReadSafe(string strName)
        {
            if (strName == null)
                throw new ArgumentNullException("strName");

            if (m_vStrings.TryGetValue(strName, out var ps))
                return ps.ReadString();

            return string.Empty;
        }

        /// <summary>
        /// Get one of the entry strings. If the string doesn't exist, the
        /// return value is an empty string (<c>""</c>). If the string is
        /// in-memory protected, the return value is <c>PwDefs.HiddenPassword</c>.
        /// </summary>
        /// <param name="strName">Name of the requested string.</param>
        /// <returns>Returns the requested string in plain-text or
        /// <c>PwDefs.HiddenPassword</c> if the string cannot be found.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the input
        /// parameter is <c>null</c>.</exception>
        public string ReadSafeEx(string strName)
        {
            if (strName == null)
                throw new ArgumentNullException("strName");

            if (m_vStrings.TryGetValue(strName, out var ps))
            {
                if (ps.IsProtected)
                    return PwDefs.HiddenPassword;

                return ps.ReadString();
            }

            return string.Empty;
        }

        /// <summary>
        /// Delete a string.
        /// </summary>
        /// <param name="strField">Name of the string field to delete.</param>
        /// <returns>Returns <c>true</c> if the field has been successfully
        /// removed, otherwise the return value is <c>false</c>.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if the input
        /// parameter is <c>null</c>.</exception>
        public bool Remove(string strField)
        {
            if (strField == null)
                throw new ArgumentNullException("strField");

            return m_vStrings.Remove(strField);
        }

        /// <summary>
        /// Set a string.
        /// </summary>
        /// <param name="strField">Identifier of the string field to modify.</param>
        /// <param name="psNewValue">New value. This parameter must not be <c>null</c>.</param>
        /// <exception cref="System.ArgumentNullException">Thrown if one of the input
        /// parameters is <c>null</c>.</exception>
        public void Set(string strField, ProtectedString psNewValue)
        {
            if (strField == null)
                throw new ArgumentNullException("strField");

            if (psNewValue == null)
                throw new ArgumentNullException("psNewValue");

            m_vStrings[strField] = psNewValue;
        }

        IEnumerator IEnumerable.GetEnumerator() => m_vStrings.GetEnumerator();

        internal void CopyTo(ProtectedStringDictionary d)
        {
            if (d == null)
            { 
                Debug.Assert(false);
                return;
            }

            foreach (var kvp in m_vStrings)
                d.Set(kvp.Key, kvp.Value);
        }
    }
}
