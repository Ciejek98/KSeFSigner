using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KSeFSigner
{
    public class CertificateLoader
    {
        /// <summary>
        /// Loads an X509Certificate2 object from certificate content and encrypted private key.
        /// </summary>
        /// <param name="certContent">PEM certificate content as string (-----BEGIN CERTIFICATE-----).</param>
        /// <param name="keyContent">Encrypted PEM private key content as string (-----BEGIN ENCRYPTED PRIVATE KEY-----).</param>
        /// <param name="keyPassword">Password to decrypt the private key.</param>
        /// <returns>X509Certificate2 object with private key attached.</returns>
        /// <exception cref="Exception">Thrown when password is incorrect or key file is corrupted.</exception>
        public static X509Certificate2 Load(string certContent, string keyContent, string keyPassword)
        {
            var cert = new X509Certificate2(Encoding.UTF8.GetBytes(certContent));

            string normalizedKey = keyContent.Replace("\r\n", "\n").Replace("\r", "\n").Trim();
            string password = keyPassword.Trim();

            try
            {
                var ecdsa = new ECDsaCng();
                ecdsa.ImportFromEncryptedPem(normalizedKey.AsSpan(), password.AsSpan());
                return cert.CopyWithPrivateKey(ecdsa);
            }
            catch (CryptographicException ex)
            {
                throw new Exception($"Incorrect password to private key or file corrupted. Original exception: {ex.Message}", ex);
            }
        }
        /// <summary>
        /// Loads an X509Certificate2 object from certificate content and encrypted private key.
        /// </summary>
        /// <param name="certContent">PEM certificate content as string (-----BEGIN CERTIFICATE-----).</param>
        /// <param name="keyContent">Encrypted PEM private key content as string (-----BEGIN ENCRYPTED PRIVATE KEY-----).</param>
        /// <param name="keyPassword">Password to decrypt the private key as SecureString.</param>
        /// <returns>X509Certificate2 object with private key attached.</returns>
        /// <exception cref="Exception">Thrown when password is incorrect or key file is corrupted.</exception>
        public static X509Certificate2 Load(string certContent, string keyContent, SecureString keyPassword)
        {
            string password = SecureStringToString(keyPassword);
            try
            {
                return Load(certContent, keyContent, password);
            }
            finally
            {
                // Wyczyść string z hasłem z pamięci
                password = null;
            }
        }

        private static string SecureStringToString(SecureString secureString)
        {
            if (secureString == null)
                throw new ArgumentNullException(nameof(secureString), "Password cannot be null.");

            IntPtr ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }
    }
}