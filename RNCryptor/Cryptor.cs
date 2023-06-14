using System;
using System.Collections.Generic;
using System.Linq;
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
        protected byte[] EncryptionKeyValue;
        protected byte[] HMACKeyValue;
        protected string PasswordValue = string.Empty;
        protected byte[] EncryptionSaltValue;
        protected byte[] HMACSaltValue;
        protected byte[] IVValue;
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
            get
            {
                if (EncryptionKeyValue == null) GenerateEncryptionKey();
                return (byte[])EncryptionKeyValue.Clone();
            }
            set
            {
                if (value.Length != KeySize) throw new CryptographicException();
                EncryptionKeyValue = value;
                ModeValue = EncryptionMode.Key;
            }
        }
        public virtual byte[] HMACKey
        {
            get
            {
                if (HMACKeyValue == null) GenerateHMACKey();
                return (byte[])HMACKeyValue.Clone();
            }
            set
            {
                if (value.Length != KeySize) throw new CryptographicException();
                HMACKeyValue = value;
                ModeValue = EncryptionMode.Key;
            }
        }
        public virtual byte[] IV
        {
            get
            {
                if (IVValue == null) GenerateIV();
                return (byte[])IVValue.Clone();
            }
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
            get
            {
                if (EncryptionSaltValue == null) GenerateEncryptionSalt();
                return (byte[])EncryptionSaltValue.Clone();
            }
            set
            {
                if (value.Length != SaltSize) throw new CryptographicException();
                if (ModeValue == EncryptionMode.Password) DeriveKeys(encryptionSalt: value);
                EncryptionSaltValue = value;
            }
        }
        public virtual byte[] HMACSalt
        {
            get
            {
                if (HMACSaltValue == null) GenerateHMACSalt();
                return (byte[])HMACSaltValue.Clone();
            }
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
        protected void DeriveKeys(string password = null, byte[] encryptionSalt = null, byte[] hmacSalt = null)
        {
            if (password == null) password = Password;
            if (encryptionSalt == null) encryptionSalt = EncryptionSalt;
            if (hmacSalt == null) hmacSalt = HMACSalt;
            byte[] passwordBuffer = Encoding.Default.GetBytes(password);
            if (VersionValue <= FormatVersion.V2)
            {
                int passwordCharCount = password.Length;
                passwordBuffer = passwordBuffer.Take(passwordCharCount).ToArray();
            }
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(passwordBuffer, encryptionSalt, Iterations);
            Rfc2898DeriveBytes k2 = new Rfc2898DeriveBytes(passwordBuffer, hmacSalt, Iterations);
            EncryptionKeyValue = k1.GetBytes(KeySize);
            HMACKeyValue = k2.GetBytes(KeySize);
        }
        public virtual ICryptoTransform CreateEncryptor()
        {
            List<byte[]> headers = new List<byte[]>() {
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
                Array.Clear(EncryptionKeyValue, 0, EncryptionKeyValue.Length);
                EncryptionKeyValue = null;
            }
            if (HMACKeyValue != null)
            {
                Array.Clear(HMACKeyValue, 0, HMACKeyValue.Length);
                EncryptionKeyValue = null;
            }
            if (PasswordValue != string.Empty) PasswordValue = string.Empty;
            if (EncryptionSaltValue != null)
            {
                Array.Clear(EncryptionSaltValue, 0, EncryptionSaltValue.Length);
                EncryptionSaltValue = null;
            }
            if (HMACSaltValue != null)
            {
                Array.Clear(HMACSaltValue, 0, HMACSaltValue.Length);
                EncryptionKeyValue = null;
            }
            if (IVValue != null)
            {
                Array.Clear(IVValue, 0, IVValue.Length);
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
}