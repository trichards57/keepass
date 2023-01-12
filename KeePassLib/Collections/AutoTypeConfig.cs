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
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace KeePassLib.Collections
{
    [Flags]
    public enum AutoTypeObfuscationOptions
    {
        None = 0,
        UseClipboard = 1
    }

    public sealed class AutoTypeAssociation : IEquatable<AutoTypeAssociation>,
        IDeepCloneable<AutoTypeAssociation>
    {
        private string m_strSequence = string.Empty;
        private string m_strWindow = string.Empty;

        public AutoTypeAssociation()
        { }

        public AutoTypeAssociation(string strWindow, string strSeq)
        {
            m_strWindow = strWindow ?? throw new ArgumentNullException("strWindow");
            m_strSequence = strSeq ?? throw new ArgumentNullException("strSeq");
        }

        public string Sequence
        {
            get
            {
                return m_strSequence;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                m_strSequence = value;
            }
        }

        public string WindowName
        {
            get
            {
                return m_strWindow;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_strWindow = value;
            }
        }

        public AutoTypeAssociation CloneDeep() => (AutoTypeAssociation)MemberwiseClone();

        public bool Equals(AutoTypeAssociation other)
        {
            if (other == null)
                return false;

            if (m_strWindow != other.m_strWindow)
                return false;

            if (m_strSequence != other.m_strSequence)
                return false;

            return true;
        }
    }

    /// <summary>
    /// A list of auto-type associations.
    /// </summary>
    public sealed class AutoTypeConfig : IEquatable<AutoTypeConfig>,
        IDeepCloneable<AutoTypeConfig>
    {
        private readonly List<AutoTypeAssociation> m_lWindowAssocs =
            new List<AutoTypeAssociation>();

        private string m_strDefaultSequence = string.Empty;

        /// <summary>
        /// Construct a new auto-type associations list.
        /// </summary>
        public AutoTypeConfig()
        { }

        /// <summary>
        /// Get all auto-type window/keystroke sequence pairs.
        /// </summary>
        public IEnumerable<AutoTypeAssociation> Associations => m_lWindowAssocs;

        public int AssociationsCount => m_lWindowAssocs.Count;

        /// <summary>
        /// The default keystroke sequence that is auto-typed if
        /// no matching window is found in the <c>Associations</c>
        /// container.
        /// </summary>
        public string DefaultSequence
        {
            get
            {
                return m_strDefaultSequence;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_strDefaultSequence = value;
            }
        }

        /// <summary>
        /// Specify whether auto-type is enabled or not.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Specify whether the typing should be obfuscated.
        /// </summary>
        public AutoTypeObfuscationOptions ObfuscationOptions { get; set; } = AutoTypeObfuscationOptions.None;

        public void Add(AutoTypeAssociation a)
        {
            if (a == null)
                throw new ArgumentNullException("a");

            m_lWindowAssocs.Add(a);
        }

        /// <summary>
        /// Remove all associations.
        /// </summary>
        public void Clear() => m_lWindowAssocs.Clear();

        /// <summary>
        /// Clone the auto-type associations list.
        /// </summary>
        /// <returns>New, cloned object.</returns>
        public AutoTypeConfig CloneDeep()
        {
            AutoTypeConfig newCfg = new AutoTypeConfig
            {
                Enabled = Enabled,
                ObfuscationOptions = ObfuscationOptions,
                m_strDefaultSequence = m_strDefaultSequence
            };

            foreach (AutoTypeAssociation a in m_lWindowAssocs)
                newCfg.Add(a.CloneDeep());

            return newCfg;
        }

        public bool Equals(AutoTypeConfig other)
        {
            if (other == null)
            {
                Debug.Assert(false);
                return false;
            }

            if (Enabled != other.Enabled)
                return false;

            if (ObfuscationOptions != other.ObfuscationOptions)
                return false;

            if (m_strDefaultSequence != other.m_strDefaultSequence)
                return false;

            if (m_lWindowAssocs.Count != other.m_lWindowAssocs.Count)
                return false;

            for (int i = 0; i < m_lWindowAssocs.Count; ++i)
            {
                if (!m_lWindowAssocs[i].Equals(other.m_lWindowAssocs[i]))
                    return false;
            }

            return true;
        }

        public AutoTypeAssociation GetAt(int iIndex)
        {
            if ((iIndex < 0) || (iIndex >= m_lWindowAssocs.Count))
                throw new ArgumentOutOfRangeException("iIndex");

            return m_lWindowAssocs[iIndex];
        }

        public void Insert(int iIndex, AutoTypeAssociation a)
        {
            if ((iIndex < 0) || (iIndex > m_lWindowAssocs.Count))
                throw new ArgumentOutOfRangeException("iIndex");

            if (a == null)
                throw new ArgumentNullException("a");

            m_lWindowAssocs.Insert(iIndex, a);
        }

        public void RemoveAt(int iIndex)
        {
            if ((iIndex < 0) || (iIndex >= m_lWindowAssocs.Count))
                throw new ArgumentOutOfRangeException("iIndex");

            m_lWindowAssocs.RemoveAt(iIndex);
        }
    }
}
