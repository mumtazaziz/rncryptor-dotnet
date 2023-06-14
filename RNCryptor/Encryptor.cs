using System;
using System.Collections.Generic;
using System.Security.Cryptography;
namespace RNCryptor
{
    internal class Encryptor : ICryptoTransform
    {
        private const int HMACSize = 32;
        private readonly ICryptoTransform _cipher;
        private readonly HMACSHA256 _hmac;
        private byte[] _header;
        public Encryptor(byte[] encryptionKey, byte[] hmacKey, byte[] iv, FormatVersion version, byte[] header)
        {
            _header = header;
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = encryptionKey;
                aes.IV = iv;
                _cipher = aes.CreateEncryptor();
            }
            _hmac = new HMACSHA256(hmacKey);
            if (version >= FormatVersion.V2) _hmac.TransformBlock(_header, 0, _header.Length, _header, 0);
        }
        public bool CanReuseTransform => _cipher.CanReuseTransform;
        public bool CanTransformMultipleBlocks => _header == null && _cipher.CanTransformMultipleBlocks;
        public int InputBlockSize => _cipher.InputBlockSize;
        public int OutputBlockSize => (_header?.Length ?? 0) + _cipher.OutputBlockSize;
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            byte[] ciphertext = new byte[inputCount];
            _cipher.TransformBlock(inputBuffer, inputOffset, inputCount, ciphertext, 0);
            byte[] result = Handle(ciphertext);
            Array.Copy(result, 0, outputBuffer, outputOffset, result.Length);
            return result.Length;
        }
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] ciphertext = _cipher.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            List<byte[]> buffers = new List<byte[]>() { Handle(ciphertext) };
            byte[] hmac = new byte[HMACSize];
            _hmac.ComputeHash(new byte[0]).CopyTo(hmac, 0);
            buffers.Add(hmac);
            byte[] outputBuffer = Utils.Concaternate(buffers);
            return outputBuffer;
        }
        private byte[] Handle(byte[] inputBuffer)
        {
            List<byte[]> buffers = new List<byte[]>();
            if (_header != null)
            {
                buffers.Add(_header);
                _header = null;
            }
            buffers.Add(inputBuffer);
            byte[] outputBuffer = Utils.Concaternate(buffers);
            _hmac.TransformBlock(inputBuffer, 0, inputBuffer.Length, inputBuffer, 0);
            return outputBuffer;
        }
        protected virtual void Dispose(bool disposing)
        {
            if (!disposing) return;
            _cipher.Dispose();
            _hmac.Dispose();
            if (_header != null)
            {
                Array.Clear(_header, 0, _header.Length);
                _header = null;
            }
        }
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}