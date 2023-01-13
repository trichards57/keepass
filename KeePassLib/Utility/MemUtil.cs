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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace KeePassLib.Utility
{
    /// <summary>
    /// Buffer manipulation and conversion routines.
    /// </summary>
    public static class MemUtil
    {
        internal static readonly ArrayHelperEx<char> ArrayHelperExOfChar =
            new ArrayHelperEx<char>();

        internal static readonly byte[] EmptyByteArray = new byte[0];

        private const MethodImplOptions MioNoOptimize =
            (MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining);

        private static byte[] g_pbZero = null;

        public static bool ArraysEqual(byte[] x, byte[] y)
        {
            // Return false if one of them is null (not comparable)!
            if ((x == null) || (y == null)) { Debug.Assert(false); return false; }

            if (x.Length != y.Length) return false;

            for (int i = 0; i < x.Length; ++i)
            {
                if (x[i] != y[i]) return false;
            }

            return true;
        }

        /// <summary>
        /// Convert a byte array to a hexadecimal string.
        /// </summary>
        /// <param name="pbArray">Input byte array.</param>
        /// <returns>Returns the hexadecimal string representing the byte
        /// array. Returns <c>null</c>, if the input byte array was <c>null</c>. Returns
        /// an empty string, if the input byte array has length 0.</returns>
        public static string ByteArrayToHexString(byte[] pbArray) => BitConverter.ToString(pbArray);

        public static int BytesToInt32(byte[] pb, int iOffset = 0) => BitConverter.ToInt32(pb, iOffset);

        public static long BytesToInt64(byte[] pb, int iOffset = 0) => BitConverter.ToInt64(pb, iOffset);

        public static ushort BytesToUInt16(byte[] pb, int iOffset = 0) => BitConverter.ToUInt16(pb, iOffset);

        public static uint BytesToUInt32(byte[] pb, int iOffset = 0) => BitConverter.ToUInt32(pb, iOffset);

        public static ulong BytesToUInt64(byte[] pb, int iOffset = 0) => BitConverter.ToUInt64(pb, iOffset);

        public static byte[] Compress(byte[] pbData)
        {
            if (pbData == null) throw new ArgumentNullException("pbData");
            if (pbData.Length == 0) return pbData;

            byte[] pbCompressed;
            using (MemoryStream msSource = new MemoryStream(pbData, false))
            {
                using (MemoryStream msCompressed = new MemoryStream())
                {
                    using (GZipStream gz = new GZipStream(msCompressed, CompressionMode.Compress))
                    {
                        msSource.CopyTo(gz);
                    }

                    pbCompressed = msCompressed.ToArray();
                }
            }

            return pbCompressed;
        }

        public static byte[] Decompress(byte[] pbCompressed)
        {
            if (pbCompressed == null) throw new ArgumentNullException("pbCompressed");
            if (pbCompressed.Length == 0) return pbCompressed;

            byte[] pbData;
            using (MemoryStream msData = new MemoryStream())
            {
                using (MemoryStream msCompressed = new MemoryStream(pbCompressed, false))
                {
                    using (GZipStream gz = new GZipStream(msCompressed, CompressionMode.Decompress))
                    {
                        gz.CopyTo(msData);
                    }
                }

                pbData = msData.ToArray();
            }

            return pbData;
        }

        /// <summary>
        /// Fast 32-bit hash (e.g. for hash tables).
        /// The algorithm might change in the future; do not store
        /// the hashes for later use.
        /// </summary>
        public static uint Hash32(byte[] pb, int iOffset, int cb)
        {
            const ulong hI = 0x4295DC458269ED9DUL;
            const uint hI32 = (uint)(hI >> 32);

            if (pb == null) { Debug.Assert(false); return hI32; }
            if (iOffset < 0) { Debug.Assert(false); return hI32; }
            if (cb < 0) { Debug.Assert(false); return hI32; }

            int m = iOffset + cb;
            if ((m < 0) || (m > pb.Length)) { Debug.Assert(false); return hI32; }

            int m4 = iOffset + (cb & ~3), cbR = cb & 3;
            ulong h = hI;

            for (int i = iOffset; i < m4; i += 4)
                h = (pb[i] ^ ((ulong)pb[i + 1] << 8) ^ ((ulong)pb[i + 2] << 16) ^
                    ((ulong)pb[i + 3] << 24) ^ h) * 0x5EA4A1E35C8ACDA3UL;

            switch (cbR)
            {
                case 1:
                    Debug.Assert(m4 == (m - 1));
                    h = (pb[m4] ^ h) * 0x54A1CC5970AF27BBUL;
                    break;

                case 2:
                    Debug.Assert(m4 == (m - 2));
                    h = (pb[m4] ^ ((ulong)pb[m4 + 1] << 8) ^ h) *
                        0x6C45CB2537A4271DUL;
                    break;

                case 3:
                    Debug.Assert(m4 == (m - 3));
                    h = (pb[m4] ^ ((ulong)pb[m4 + 1] << 8) ^
                        ((ulong)pb[m4 + 2] << 16) ^ h) * 0x59B8E8939E19695DUL;
                    break;

                default:
                    Debug.Assert(m4 == m);
                    break;
            }

            Debug.Assert((cb != 0) || ((uint)(h >> 32) == hI32));
            return (uint)(h >> 32);
        }

        /// <summary>
        /// Convert a hexadecimal string to a byte array. The input string must be
        /// even (i.e. its length is a multiple of 2).
        /// </summary>
        /// <param name="strHex">String containing hexadecimal characters.</param>
        /// <returns>Returns a byte array. Returns <c>null</c> if the string parameter
        /// was <c>null</c> or is an uneven string (i.e. if its length isn't a
        /// multiple of 2).</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if <paramref name="strHex" />
        /// is <c>null</c>.</exception>
        public static byte[] HexStringToByteArray(string strHex)
        {
            if (strHex == null)
                throw new ArgumentNullException("strHex");

            int nStrLen = strHex.Length;
            if ((nStrLen % 2) != 0)
            {
                Debug.Assert(false);
                return null;
            }

            byte[] pb = new byte[nStrLen / 2];

            for (int i = 0; i < nStrLen; i += 2)
                pb[i/2] = Convert.ToByte(strHex.Substring(i, 2));

            return pb;
        }

        public static int IndexOf<T>(T[] vHaystack, T[] vNeedle)
                    where T : IEquatable<T>
        {
            if (vHaystack == null) throw new ArgumentNullException("vHaystack");
            if (vNeedle == null) throw new ArgumentNullException("vNeedle");
            if (vNeedle.Length == 0) return 0;

            for (int i = 0; i <= (vHaystack.Length - vNeedle.Length); ++i)
            {
                bool bFound = true;
                for (int m = 0; m < vNeedle.Length; ++m)
                {
                    if (!vHaystack[i + m].Equals(vNeedle[m]))
                    {
                        bFound = false;
                        break;
                    }
                }
                if (bFound) return i;
            }

            return -1;
        }

        public static byte[] Int32ToBytes(int iValue) => UInt32ToBytes((uint)iValue);

        public static void Int32ToBytesEx(int iValue, byte[] pb, int iOffset) => UInt32ToBytesEx((uint)iValue, pb, iOffset);

        public static byte[] Int64ToBytes(long lValue) => UInt64ToBytes((ulong)lValue);

        public static void Int64ToBytesEx(long lValue, byte[] pb, int iOffset) => UInt64ToBytesEx((ulong)lValue, pb, iOffset);

        public static T[] Mid<T>(T[] v, int iOffset, int iLength)
        {
            if (v == null) throw new ArgumentNullException("v");
            if (iOffset < 0) throw new ArgumentOutOfRangeException("iOffset");
            if (iLength < 0) throw new ArgumentOutOfRangeException("iLength");
            if ((iOffset + iLength) > v.Length) throw new ArgumentException();

            T[] r = new T[iLength];
            Array.Copy(v, iOffset, r, 0, iLength);
            return r;
        }

        /// <summary>
        /// Decode Base32 strings according to RFC 4648.
        /// </summary>
        public static byte[] ParseBase32(string str)
        {
            if ((str == null) || ((str.Length % 8) != 0))
            {
                Debug.Assert(false);
                return null;
            }

            ulong uMaxBits = (ulong)str.Length * 5UL;
            List<byte> l = new List<byte>((int)(uMaxBits / 8UL) + 1);
            Debug.Assert(l.Count == 0);

            for (int i = 0; i < str.Length; i += 8)
            {
                ulong u = 0;
                int nBits = 0;

                for (int j = 0; j < 8; ++j)
                {
                    char ch = str[i + j];
                    if (ch == '=') break;

                    ulong uValue;
                    if ((ch >= 'A') && (ch <= 'Z'))
                        uValue = (ulong)(ch - 'A');
                    else if ((ch >= 'a') && (ch <= 'z'))
                        uValue = (ulong)(ch - 'a');
                    else if ((ch >= '2') && (ch <= '7'))
                        uValue = (ulong)(ch - '2') + 26UL;
                    else { Debug.Assert(false); return null; }

                    u <<= 5;
                    u += uValue;
                    nBits += 5;
                }

                int nBitsTooMany = (nBits % 8);
                u >>= nBitsTooMany;
                nBits -= nBitsTooMany;
                Debug.Assert((nBits % 8) == 0);

                int idxNewBytes = l.Count;
                while (nBits > 0)
                {
                    l.Add((byte)(u & 0xFF));
                    u >>= 8;
                    nBits -= 8;
                }
                l.Reverse(idxNewBytes, l.Count - idxNewBytes);
            }

            return l.ToArray();
        }

        public static byte[] Read(Stream s)
        {
            if (s == null) throw new ArgumentNullException("s");

            byte[] pb;
            using (MemoryStream ms = new MemoryStream())
            {
                s.CopyTo(ms);
                pb = ms.ToArray();
            }

            return pb;
        }

        public static byte[] Read(Stream s, int nCount)
        {
            if (s == null) throw new ArgumentNullException("s");
            if (nCount < 0) throw new ArgumentOutOfRangeException("nCount");

            byte[] pb = new byte[nCount];
            int iOffset = 0;
            while (nCount > 0)
            {
                int iRead = s.Read(pb, iOffset, nCount);
                if (iRead == 0) break;

                iOffset += iRead;
                nCount -= iRead;
            }

            if (iOffset != pb.Length)
            {
                byte[] pbPart = new byte[iOffset];
                Array.Copy(pb, pbPart, iOffset);
                return pbPart;
            }

            return pb;
        }

        public static uint RotateLeft32(uint u, int nBits)
        {
            return ((u << nBits) | (u >> (32 - nBits)));
        }

        public static ulong RotateLeft64(ulong u, int nBits)
        {
            return ((u << nBits) | (u >> (64 - nBits)));
        }

        public static uint RotateRight32(uint u, int nBits)
        {
            return ((u >> nBits) | (u << (32 - nBits)));
        }

        public static ulong RotateRight64(ulong u, int nBits)
        {
            return ((u >> nBits) | (u << (64 - nBits)));
        }

        /// <summary>
        /// Convert a 16-bit unsigned integer to 2 bytes (little-endian).
        /// </summary>
        public static byte[] UInt16ToBytes(ushort uValue)
        {
            byte[] pb = new byte[2];

            unchecked
            {
                pb[0] = (byte)uValue;
                pb[1] = (byte)(uValue >> 8);
            }

            return pb;
        }

        /// <summary>
        /// Convert a 32-bit unsigned integer to 4 bytes (little-endian).
        /// </summary>
        public static byte[] UInt32ToBytes(uint uValue)
        {
            byte[] pb = new byte[4];

            unchecked
            {
                pb[0] = (byte)uValue;
                pb[1] = (byte)(uValue >> 8);
                pb[2] = (byte)(uValue >> 16);
                pb[3] = (byte)(uValue >> 24);
            }

            return pb;
        }

        /// <summary>
        /// Convert a 32-bit unsigned integer to 4 bytes (little-endian).
        /// </summary>
        public static void UInt32ToBytesEx(uint uValue, byte[] pb, int iOffset)
        {
            if (pb == null) { Debug.Assert(false); throw new ArgumentNullException("pb"); }
            if ((iOffset < 0) || ((iOffset + 3) >= pb.Length))
            {
                Debug.Assert(false);
                throw new ArgumentOutOfRangeException("iOffset");
            }

            unchecked
            {
                pb[iOffset] = (byte)uValue;
                pb[iOffset + 1] = (byte)(uValue >> 8);
                pb[iOffset + 2] = (byte)(uValue >> 16);
                pb[iOffset + 3] = (byte)(uValue >> 24);
            }
        }

        /// <summary>
        /// Convert a 64-bit unsigned integer to 8 bytes (little-endian).
        /// </summary>
        public static byte[] UInt64ToBytes(ulong uValue)
        {
            byte[] pb = new byte[8];

            unchecked
            {
                pb[0] = (byte)uValue;
                pb[1] = (byte)(uValue >> 8);
                pb[2] = (byte)(uValue >> 16);
                pb[3] = (byte)(uValue >> 24);
                pb[4] = (byte)(uValue >> 32);
                pb[5] = (byte)(uValue >> 40);
                pb[6] = (byte)(uValue >> 48);
                pb[7] = (byte)(uValue >> 56);
            }

            return pb;
        }

        /// <summary>
        /// Convert a 64-bit unsigned integer to 8 bytes (little-endian).
        /// </summary>
        public static void UInt64ToBytesEx(ulong uValue, byte[] pb, int iOffset)
        {
            if (pb == null) { Debug.Assert(false); throw new ArgumentNullException("pb"); }
            if ((iOffset < 0) || ((iOffset + 7) >= pb.Length))
            {
                Debug.Assert(false);
                throw new ArgumentOutOfRangeException("iOffset");
            }

            unchecked
            {
                pb[iOffset] = (byte)uValue;
                pb[iOffset + 1] = (byte)(uValue >> 8);
                pb[iOffset + 2] = (byte)(uValue >> 16);
                pb[iOffset + 3] = (byte)(uValue >> 24);
                pb[iOffset + 4] = (byte)(uValue >> 32);
                pb[iOffset + 5] = (byte)(uValue >> 40);
                pb[iOffset + 6] = (byte)(uValue >> 48);
                pb[iOffset + 7] = (byte)(uValue >> 56);
            }
        }

        public static IEnumerable<T> Union<T>(IEnumerable<T> a, IEnumerable<T> b,
            IEqualityComparer<T> cmp)
        {
            if (a == null) throw new ArgumentNullException("a");
            if (b == null) throw new ArgumentNullException("b");

            Dictionary<T, bool> d = ((cmp != null) ?
                (new Dictionary<T, bool>(cmp)) : (new Dictionary<T, bool>()));

            foreach (T ta in a)
            {
                if (d.ContainsKey(ta)) continue; // Prevent duplicates

                d[ta] = true;
                yield return ta;
            }

            foreach (T tb in b)
            {
                if (d.ContainsKey(tb)) continue; // Prevent duplicates

                d[tb] = true;
                yield return tb;
            }

            yield break;
        }

        public static void Write(Stream s, byte[] pbData)
        {
            if (s == null) { Debug.Assert(false); return; }
            if (pbData == null) { Debug.Assert(false); return; }

            Debug.Assert(pbData.Length >= 0);
            if (pbData.Length > 0) s.Write(pbData, 0, pbData.Length);
        }

        public static void XorArray(byte[] pbSource, int iSourceOffset,
            byte[] pbBuffer, int iBufferOffset, int cb)
        {
            if (pbSource == null) throw new ArgumentNullException("pbSource");
            if (iSourceOffset < 0) throw new ArgumentOutOfRangeException("iSourceOffset");
            if (pbBuffer == null) throw new ArgumentNullException("pbBuffer");
            if (iBufferOffset < 0) throw new ArgumentOutOfRangeException("iBufferOffset");
            if (cb < 0) throw new ArgumentOutOfRangeException("cb");
            if (iSourceOffset > (pbSource.Length - cb))
                throw new ArgumentOutOfRangeException("cb");
            if (iBufferOffset > (pbBuffer.Length - cb))
                throw new ArgumentOutOfRangeException("cb");

            for (int i = 0; i < cb; ++i)
                pbBuffer[iBufferOffset + i] ^= pbSource[iSourceOffset + i];
        }

        /// <summary>
        /// Set all elements of an array to the default value.
        /// </summary>
        /// <param name="v">Input array.</param>
        [MethodImpl(MioNoOptimize)]
        public static void ZeroArray<T>(T[] v)
        {
            if (v == null) { Debug.Assert(false); return; }

            Array.Clear(v, 0, v.Length);
        }

        /// <summary>
        /// Set all bytes in a byte array to zero.
        /// </summary>
        /// <param name="pbArray">Input array. All bytes of this array
        /// will be set to zero.</param>
        [MethodImpl(MioNoOptimize)]
        public static void ZeroByteArray(byte[] pbArray)
        {
            if (pbArray == null) { Debug.Assert(false); return; }

            Array.Clear(pbArray, 0, pbArray.Length);
        }

        [MethodImpl(MioNoOptimize)]
        public static void ZeroMemory(IntPtr pb, long cb)
        {
            if (pb == IntPtr.Zero) { Debug.Assert(false); return; }
            if (cb < 0) { Debug.Assert(false); return; }

            byte[] pbZero = g_pbZero;
            if (pbZero == null)
            {
                pbZero = new byte[4096];
                g_pbZero = pbZero;
            }

            long cbZero = pbZero.Length;

            while (cb != 0)
            {
                long cbBlock = Math.Min(cb, cbZero);

                Marshal.Copy(pbZero, 0, pb, (int)cbBlock);

                pb = AddPtr(pb, cbBlock);
                cb -= cbBlock;
            }
        }

        internal static IntPtr AddPtr(IntPtr p, long cb)
        {
            // IntPtr.operator+ and IntPtr.Add are not available in .NET 2.0

            if (IntPtr.Size >= 8)
                return new IntPtr(unchecked(p.ToInt64() + cb));
            return new IntPtr(unchecked(p.ToInt32() + (int)cb));
        }

        internal static T BytesToStruct<T>(byte[] pb, int iOffset)
            where T : struct
        {
            if (pb == null) throw new ArgumentNullException("pb");
            if (iOffset < 0) throw new ArgumentOutOfRangeException("iOffset");

            int cb = Marshal.SizeOf(typeof(T));
            if (cb <= 0) { Debug.Assert(false); return default(T); }

            if (iOffset > (pb.Length - cb)) throw new ArgumentOutOfRangeException("iOffset");

            IntPtr p = Marshal.AllocCoTaskMem(cb);
            if (p == IntPtr.Zero) throw new OutOfMemoryException();

            object o;
            try
            {
                Marshal.Copy(pb, iOffset, p, cb);
                o = Marshal.PtrToStructure(p, typeof(T));
            }
            finally { Marshal.FreeCoTaskMem(p); }

            return (T)o;
        }

        internal static uint Hash32Ex<T>(T[] v, int iOffset, int c)
        {
            const ulong hI = 0x4295DC458269ED9DUL;
            const uint hI32 = (uint)(hI >> 32);

            if (v == null) { Debug.Assert(false); return hI32; }
            if (iOffset < 0) { Debug.Assert(false); return hI32; }
            if (c < 0) { Debug.Assert(false); return hI32; }

            int m = iOffset + c;
            if ((m < 0) || (m > v.Length)) { Debug.Assert(false); return hI32; }

            ulong h = hI;

            for (int i = iOffset; i < m; ++i)
                h = (h ^ (uint)v[i].GetHashCode()) * 0x5EA4A1E35C8ACDA3UL;

            Debug.Assert((c != 0) || ((uint)(h >> 32) == hI32));
            return (uint)(h >> 32);
        }

        internal static ulong Hash64(int[] v, int iOffset, int ci)
        {
            ulong h = 0x4295DC458269ED9DUL;

            if (v == null) { Debug.Assert(false); return h; }
            if (iOffset < 0) { Debug.Assert(false); return h; }
            if (ci < 0) { Debug.Assert(false); return h; }

            int m = iOffset + ci;
            if ((m < 0) || (m > v.Length)) { Debug.Assert(false); return h; }

            for (int i = iOffset; i < m; ++i)
                h = (h ^ (uint)v[i]) * 0x5EA4A1E35C8ACDA3UL;

            return ((h ^ (h >> 32)) * 0x59B8E8939E19695DUL);
        }

        internal static bool ListsEqual<T>(List<T> a, List<T> b)
            where T : class, IEquatable<T>
        {
            if (object.ReferenceEquals(a, b)) return true;
            if ((a == null) || (b == null)) return false;

            int n = a.Count;
            if (n != b.Count) return false;

            for (int i = 0; i < n; ++i)
            {
                T tA = a[i], tB = b[i];

                if (tA == null)
                {
                    if (tB != null) return false;
                }
                else if (tB == null) return false;
                else if (!tA.Equals(tB)) return false;
            }

            return true;
        }

        internal static byte[] ParseBase32(string str, bool bAutoPad)
        {
            if (str == null) { Debug.Assert(false); return null; }

            // https://sourceforge.net/p/keepass/discussion/329220/thread/59b61fddea/
            if (bAutoPad && ((str.Length % 8) != 0))
                str = str.PadRight((str.Length & ~7) + 8, '=');

            return ParseBase32(str);
        }

        internal static byte[] StructToBytes<T>(ref T t)
            where T : struct
        {
            int cb = Marshal.SizeOf(typeof(T));
            if (cb <= 0) { Debug.Assert(false); return MemUtil.EmptyByteArray; }

            byte[] pb = new byte[cb];

            IntPtr p = Marshal.AllocCoTaskMem(cb);
            if (p == IntPtr.Zero) throw new OutOfMemoryException();

            try
            {
                Marshal.StructureToPtr(t, p, false);
                Marshal.Copy(p, pb, 0, cb);
            }
            finally { Marshal.FreeCoTaskMem(p); }

            return pb;
        }
    }

    internal sealed class ArrayHelperEx<T> : IEqualityComparer<T[]>, IComparer<T[]>
        where T : IEquatable<T>, IComparable<T>
    {
        public int Compare(T[] x, T[] y)
        {
            if (object.ReferenceEquals(x, y)) return 0;
            if (x == null) return -1;
            if (y == null) return 1;

            int n = x.Length, m = y.Length;
            if (n != m) return ((n < m) ? -1 : 1);

            for (int i = 0; i < n; ++i)
            {
                T tX = x[i], tY = y[i];
                if (!tX.Equals(tY)) return tX.CompareTo(tY);
            }

            return 0;
        }

        public bool Equals(T[] x, T[] y)
        {
            if (object.ReferenceEquals(x, y)) return true;
            if ((x == null) || (y == null)) return false;

            int n = x.Length;
            if (n != y.Length) return false;

            for (int i = 0; i < n; ++i)
            {
                if (!x[i].Equals(y[i])) return false;
            }

            return true;
        }

        public int GetHashCode(T[] obj)
        {
            if (obj == null) { Debug.Assert(false); throw new ArgumentNullException("obj"); }

            return (int)MemUtil.Hash32Ex<T>(obj, 0, obj.Length);
        }
    }
}
