using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace RNCryptor.Tests
{
    [TestClass]
    public class Encryptor
    {
        [TestMethod]
        public void PasswordBasedEncryption()
        {
            foreach (PasswordVector vector in Vectors.Password)
            {
                Cryptor cryptor = new Cryptor()
                {
                    Version = vector.Version,
                    Password = vector.Password,
                    EncryptionSalt = vector.EncryptionSalt,
                    HMACSalt = vector.HMACSalt,
                    IV = vector.IV,
                };
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, cryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(vector.Plaintext, 0, vector.Plaintext.Length);
                    }
                    byte[] ciphertext = outputStream.ToArray();
                    Assert.IsTrue(ciphertext.SequenceEqual(vector.Ciphertext));
                }
            }
        }
    }
}