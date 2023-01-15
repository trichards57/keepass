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

using System;
using System.Security.Cryptography;

namespace KeePassLib.Cryptography
{
    /// <summary>
    /// Cryptographically secure pseudo-random number generator.
    /// The returned values are unpredictable and cannot be reproduced.
    /// <c>CryptoRandom</c> is a singleton class.
    /// </summary>
    public sealed class CryptoRandom
    {
        private static readonly object g_oSyncRoot = new object();
        private static int g_iWeakSeed = 0;
        private static CryptoRandom g_pInstance = null;

        private CryptoRandom()
        {
        }

        public static CryptoRandom Instance
        {
            get
            {
                CryptoRandom cr;
                lock (g_oSyncRoot)
                {
                    cr = g_pInstance;
                    if (cr == null)
                    {
                        cr = new CryptoRandom();
                        g_pInstance = cr;
                    }
                }

                return cr;
            }
        }

        public static Random NewWeakRandom()
        {
            long s64 = DateTime.UtcNow.ToBinary();
            int s32 = (int)((s64 >> 32) ^ s64);

            lock (g_oSyncRoot)
            {
                unchecked
                {
                    g_iWeakSeed += 0x78A8C4B7; // Prime number
                    s32 ^= g_iWeakSeed;
                }
            }

            // Prevent overflow in the Random constructor of .NET 2.0
            if (s32 == int.MinValue) s32 = int.MaxValue;

            return new Random(s32);
        }

        /// <summary>
        /// Get a number of cryptographically strong random bytes.
        /// This method is thread-safe.
        /// </summary>
        /// <param name="uRequestedBytes">Number of requested random bytes.</param>
        /// <returns>A byte array consisting of <paramref name="uRequestedBytes" />
        /// random bytes.</returns>
        public byte[] GetRandomBytes(uint uRequestedBytes)
        {
            var rng = RandomNumberGenerator.Create();
            var buffer = new byte[uRequestedBytes];
            rng.GetBytes(buffer);

            return buffer;
        }
    }
}
