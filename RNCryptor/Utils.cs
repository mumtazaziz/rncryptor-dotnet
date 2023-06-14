using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
namespace RNCryptor
{
    internal class Utils
    {
        private static volatile RandomNumberGenerator _rng;
        internal static RandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (_rng == null) _rng = RandomNumberGenerator.Create();
                return _rng;
            }
        }
        internal static byte[] GenerateRandom(int keySize)
        {
            byte[] array = new byte[keySize];
            RandomNumberGenerator.GetBytes(array);
            return array;
        }
        internal static byte[] Concaternate(List<byte[]> buffers)
        {
            byte[] outputBuffer = new byte[buffers.Sum(buffer => buffer.Length)];
            int offset = 0;
            foreach (byte[] buffer in buffers)
            {
                Array.Copy(buffer, 0, outputBuffer, offset, buffer.Length);
                offset += buffer.Length;
            }
            return outputBuffer;
        }
    }
}