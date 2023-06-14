using System.Security.Cryptography;
using System.Text;

namespace RNCryptor
{
    public enum EncryptionMode
    {
        Key,
        Password
    }
    public enum FormatVersion
    {
        V0,
        V1,
        V2,
        V3,
    }
    public class Cryptor : IDisposable
    {
        public const int KeySize = 32;
        public const int SaltSize = 8;
        public const int IVSize = 16;
        public const int Iterations = 10000;
        protected FormatVersion VersionValue = FormatVersion.V3;
        protected EncryptionMode ModeValue = EncryptionMode.Key;
        protected byte[]? EncryptionKeyValue;
        protected byte[]? HMACKeyValue;
        protected string PasswordValue = string.Empty;
        protected byte[]? EncryptionSaltValue;
        protected byte[]? HMACSaltValue;
        protected byte[]? IVValue;

        public virtual FormatVersion Version
        {
            get => VersionValue;
            set
            {
                if (value == FormatVersion.V0) Mode = EncryptionMode.Password;
                VersionValue = value;
            }
        }

        public virtual EncryptionMode Mode
        {
            get => ModeValue;
            set
            {
                if (value == EncryptionMode.Password)
                {
                    if (PasswordValue == null) throw new CryptographicException();
                    DeriveKeys();
                }
                else if (VersionValue == FormatVersion.V0) throw new CryptographicException();
                ModeValue = value;
            }
        }

        public virtual byte[] EncryptionKey
        {
            get => (byte[])(EncryptionKeyValue ??= Utils.GenerateRandom(KeySize)).Clone();
            set
            {
                if (value.Length != KeySize) throw new CryptographicException();
                EncryptionKeyValue = value;
                ModeValue = EncryptionMode.Key;
            }
        }
        public virtual byte[] HMACKey
        {
            get => (byte[])(HMACKeyValue ??= Utils.GenerateRandom(KeySize)).Clone();
            set
            {
                if (value.Length != KeySize) throw new CryptographicException();
                HMACKeyValue = value;
                ModeValue = EncryptionMode.Key;
            }
        }
        public virtual byte[] IV
        {
            get => (byte[])(IVValue ??= Utils.GenerateRandom(IVSize)).Clone();
            set
            {
                if (value.Length != IVSize) throw new CryptographicException();
                IVValue = value;
            }
        }

        public virtual string Password
        {
            get => PasswordValue;
            set
            {
                if (value == string.Empty) throw new CryptographicException();
                DeriveKeys(password: value);
                ModeValue = EncryptionMode.Password;
                PasswordValue = value;
            }
        }
        public virtual byte[] EncryptionSalt
        {
            get => (byte[])(EncryptionSaltValue ??= Utils.GenerateRandom(SaltSize)).Clone();
            set
            {
                if (value.Length != SaltSize) throw new CryptographicException();
                if (ModeValue == EncryptionMode.Password) DeriveKeys(encryptionSalt: value);
                EncryptionSaltValue = value;
            }
        }
        public virtual byte[] HMACSalt
        {
            get => (byte[])(HMACSaltValue ??= Utils.GenerateRandom(SaltSize)).Clone();
            set
            {
                if (value.Length != SaltSize) throw new CryptographicException();
                if (ModeValue == EncryptionMode.Password) DeriveKeys(hmacSalt: value);
                HMACSaltValue = value;
            }
        }

        public void GenerateEncryptionKey() => EncryptionKeyValue = Utils.GenerateRandom(KeySize);
        public void GenerateHMACKey() => HMACKeyValue = Utils.GenerateRandom(KeySize);
        public void GenerateEncryptionSalt() => EncryptionSaltValue = Utils.GenerateRandom(SaltSize);
        public void GenerateHMACSalt() => HMACSaltValue = Utils.GenerateRandom(SaltSize);
        public void GenerateIV() => IVValue = Utils.GenerateRandom(IVSize);

        protected void DeriveKeys(string? password = null, byte[]? encryptionSalt = null, byte[]? hmacSalt = null)
        {
            password ??= Password;
            encryptionSalt ??= EncryptionSalt;
            hmacSalt ??= HMACSalt;
            byte[] passwordBuffer = Encoding.Default.GetBytes(password);
            if (VersionValue <= FormatVersion.V2)
            {
                int passwordCharCount = password.Length;
                passwordBuffer = passwordBuffer[..passwordCharCount];
            }
            EncryptionKeyValue = Rfc2898DeriveBytes.Pbkdf2(passwordBuffer, encryptionSalt, Iterations, HashAlgorithmName.SHA1, KeySize);
            HMACKeyValue = Rfc2898DeriveBytes.Pbkdf2(passwordBuffer, hmacSalt, Iterations, HashAlgorithmName.SHA1, KeySize);
        }

        public virtual ICryptoTransform CreateEncryptor()
        {
            List<byte[]> headers = new() {
                new byte[] { (byte)VersionValue, (byte)(VersionValue >= FormatVersion.V1 ? ModeValue : 0) }
            };
            if (ModeValue == EncryptionMode.Password)
            {
                headers.Add(EncryptionSalt);
                headers.Add(HMACSalt);
            }
            headers.Add(IV);
            byte[] header = Utils.Concaternate(headers);
            return new Encryptor(EncryptionKey, HMACKey, IV, VersionValue, header);
        }
        public virtual ICryptoTransform CreateDecryptor()
        {
            throw new NotImplementedException();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing) return;
            if (EncryptionKeyValue != null)
            {
                Array.Clear(EncryptionKeyValue);
                EncryptionKeyValue = null;
            }
            if (HMACKeyValue != null)
            {
                Array.Clear(HMACKeyValue);
                EncryptionKeyValue = null;
            }
            if (PasswordValue != string.Empty) PasswordValue = string.Empty;
            if (EncryptionSaltValue != null)
            {
                Array.Clear(EncryptionSaltValue);
                EncryptionSaltValue = null;
            }
            if (HMACSaltValue != null)
            {
                Array.Clear(HMACSaltValue);
                EncryptionKeyValue = null;
            }
            if (IVValue != null)
            {
                Array.Clear(IVValue);
                EncryptionKeyValue = null;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
    internal class Encryptor : ICryptoTransform
    {
        private const int HMACSize = 32;
        private readonly ICryptoTransform _cipher;
        private readonly HMACSHA256 _hmac;
        private byte[]? _header;

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
            List<byte[]> buffers = new() { Handle(ciphertext) };
            byte[] hmac = new byte[HMACSize];
            _hmac.ComputeHash(new byte[0]).CopyTo(hmac, 0);
            buffers.Add(hmac);
            byte[] outputBuffer = Utils.Concaternate(buffers);
            return outputBuffer;
        }

        private byte[] Handle(byte[] inputBuffer)
        {
            List<byte[]> buffers = new();
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
                Array.Clear(_header);
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