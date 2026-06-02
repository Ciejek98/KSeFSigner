using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace KSeFSigner
{
    public class XAdESSigner
    {
        private const string EcdsaSha256AlgorithmUrl = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        private const string XadesNsUrl = "http://uri.etsi.org/01903/v1.3.2#";
        private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

        /// <summary>
        /// Signs an XML document in XAdES-BES format using provided X509Certificate2.
        /// </summary>
        /// <param name="xml">AuthTokenRequest XML content as string.</param>
        /// <param name="certificate">X509Certificate2 with ECDSA private key.</param>
        /// <returns>Signed XML document as string.</returns>
        /// <exception cref="Exception">Thrown when ECDSA algorithm registration fails or signature computation fails.</exception>
        public static string Sign(string xml, X509Certificate2 certificate)
        {
            XmlDocument xmlDocument = new() { PreserveWhitespace = true };
            xmlDocument.LoadXml(xml);
            Sign(xmlDocument, certificate);
            return xmlDocument.OuterXml;
        }

        /// <summary>
        /// Signs an XML document in XAdES-BES format using raw certificate and key strings.
        /// </summary>
        /// <param name="xml">AuthTokenRequest XML content as string.</param>
        /// <param name="certContent">PEM certificate content as string (-----BEGIN CERTIFICATE-----).</param>
        /// <param name="keyContent">Encrypted PEM private key content as string (-----BEGIN ENCRYPTED PRIVATE KEY-----).</param>
        /// <param name="keyPassword">Password to decrypt the private key.</param>
        /// <returns>Signed XML document as string.</returns>
        /// <exception cref="Exception">Thrown when certificate loading fails or signature computation fails.</exception>
        public static string Sign(string xml, string certContent, string keyContent, string keyPassword)
        {
            X509Certificate2 certificate = CertificateLoader.Load(certContent, keyContent, keyPassword);
            return Sign(xml, certificate);
        }
        /// <summary>
        /// Signs an XML document in XAdES-BES format using raw certificate and key strings.
        /// </summary>
        /// <param name="xml">AuthTokenRequest XML content as string.</param>
        /// <param name="certContent">PEM certificate content as string (-----BEGIN CERTIFICATE-----).</param>
        /// <param name="keyContent">Encrypted PEM private key content as string (-----BEGIN ENCRYPTED PRIVATE KEY-----).</param>
        /// <param name="keyPassword">Password to decrypt the private key as SecureString.</param>
        /// <returns>Signed XML document as string.</returns>
        /// <exception cref="Exception">Thrown when certificate loading fails or signature computation fails.</exception>
        public static string Sign(string xml, string certContent, string keyContent, SecureString keyPassword)
        {
            X509Certificate2 certificate = CertificateLoader.Load(certContent, keyContent, keyPassword);
            return Sign(xml, certificate);
        }

        /// <summary>
        /// Signs an XmlDocument in XAdES-BES format using provided X509Certificate2.
        /// Modifies the document in place by appending the signature element.
        /// </summary>
        /// <param name="xmlDocument">XmlDocument to sign. Must have a root element. PreserveWhitespace should be set to true.</param>
        /// <param name="certificate">X509Certificate2 with ECDSA private key.</param>
        /// <returns>The same XmlDocument with signature element appended.</returns>
        /// <exception cref="InvalidOperationException">Thrown when EC private key cannot be extracted from certificate.</exception>
        /// <exception cref="Exception">Thrown when ECDSA algorithm registration fails or signature computation fails.</exception>
        public static XmlDocument Sign(XmlDocument xmlDocument, X509Certificate2 certificate)
        {
            CryptoConfig.AddAlgorithm(
                typeof(EcdsaSignatureDescription),
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            );

            var verifyAlg = CryptoConfig.CreateFromName("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
            if (verifyAlg == null)
                throw new Exception("ECDSA algorithm registration failed.");

            string signatureId = "Signature";
            string signedPropertiesId = "SignedProperties";

            ECDsa ecdsaKey = certificate.GetECDsaPrivateKey();

            if (ecdsaKey == null)
                throw new InvalidOperationException("Unable to extract EC private key from certificate.");

            SignedXmlFixed signedXml = new(xmlDocument);
            signedXml.SigningKey = ecdsaKey;
            signedXml.SignedInfo.SignatureMethod = EcdsaSha256AlgorithmUrl;

            signedXml.Signature.Id = signatureId;

            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

            Reference rootReference = new(string.Empty);
            rootReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            rootReference.AddTransform(new XmlDsigExcC14NTransform());
            rootReference.DigestMethod = SignedXml.XmlDsigSHA256Url;
            signedXml.AddReference(rootReference);

            Reference xadesReference = new("#" + signedPropertiesId)
            {
                Type = SignedPropertiesType
            };
            xadesReference.AddTransform(new XmlDsigExcC14NTransform());
            xadesReference.DigestMethod = SignedXml.XmlDsigSHA256Url;
            signedXml.AddReference(xadesReference);

            string certDigest = Convert.ToBase64String(certificate.GetCertHash(HashAlgorithmName.SHA256));
            string issuerName = certificate.Issuer;
            string serialNumber = new BigInteger(certificate.GetSerialNumber()).ToString(CultureInfo.InvariantCulture);
            string signingTime = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O");

            XmlDocument qualifyingDoc = new();
            qualifyingDoc.LoadXml($@"<xades:QualifyingProperties Target=""#{signatureId}"" xmlns:xades=""{XadesNsUrl}"" xmlns=""{SignedXml.XmlDsigNamespaceUrl}"">
  <xades:SignedProperties Id=""{signedPropertiesId}"">
    <xades:SignedSignatureProperties>
      <xades:SigningTime>{signingTime}</xades:SigningTime>
      <xades:SigningCertificate>
        <xades:Cert>
          <xades:CertDigest>
            <DigestMethod Algorithm=""{SignedXml.XmlDsigSHA256Url}"" />
            <DigestValue>{certDigest}</DigestValue>
          </xades:CertDigest>
          <xades:IssuerSerial>
            <X509IssuerName>{issuerName}</X509IssuerName>
            <X509SerialNumber>{serialNumber}</X509SerialNumber>
          </xades:IssuerSerial>
        </xades:Cert>
      </xades:SigningCertificate>
    </xades:SignedSignatureProperties>
  </xades:SignedProperties>
</xades:QualifyingProperties>");

            DataObject dataObject = new() { Data = qualifyingDoc.ChildNodes };
            signedXml.AddDataObject(dataObject);

            try
            {
                signedXml.ComputeSignature();
            }
            catch (CryptographicException ex)
            {
                throw new Exception($"Failed to compute XML signature. Original exception: {ex.Message}", ex);
            }

            XmlElement xmlSignature = signedXml.GetXml();
            xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlSignature, true));

            return xmlDocument;
        }

        public class EcdsaSignatureDescription : SignatureDescription
        {
            public EcdsaSignatureDescription()
            {
                KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName;
                DigestAlgorithm = typeof(SHA256).AssemblyQualifiedName;
                FormatterAlgorithm = typeof(EcdsaSignatureFormatter).AssemblyQualifiedName;
                DeformatterAlgorithm = typeof(EcdsaSignatureDeformatter).AssemblyQualifiedName;
            }

            public override HashAlgorithm CreateDigest() => SHA256.Create();

            public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
                => new EcdsaSignatureDeformatter(key);

            public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
                => new EcdsaSignatureFormatter(key);
        }

        public class EcdsaSignatureFormatter : AsymmetricSignatureFormatter
        {
            private ECDsa _key;

            public EcdsaSignatureFormatter(AsymmetricAlgorithm key) { _key = (ECDsa)key; }
            public EcdsaSignatureFormatter() { }

            public override void SetKey(AsymmetricAlgorithm key) => _key = (ECDsa)key;
            public override void SetHashAlgorithm(string strName) { }
            public override byte[] CreateSignature(byte[] rgbHash) => _key.SignHash(rgbHash);
        }

        public class EcdsaSignatureDeformatter : AsymmetricSignatureDeformatter
        {
            private ECDsa _key;

            public EcdsaSignatureDeformatter(AsymmetricAlgorithm key) { _key = (ECDsa)key; }
            public EcdsaSignatureDeformatter() { }

            public override void SetKey(AsymmetricAlgorithm key) => _key = (ECDsa)key;
            public override void SetHashAlgorithm(string strName) { }
            public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature) => _key.VerifyHash(rgbHash, rgbSignature);
        }

        private class SignedXmlFixed : SignedXml
        {
            private readonly List<DataObject> _dataObjects = new();

            public SignedXmlFixed(XmlDocument document) : base(document) { }

            public override XmlElement GetIdElement(XmlDocument document, string idValue)
            {
                XmlElement element = base.GetIdElement(document, idValue);
                return element ?? _dataObjects
                    .SelectMany(x => x.Data.Cast<XmlNode>())
                    .Select(x => x.SelectSingleNode($"//*[@Id='{idValue}']") as XmlElement)
                    .FirstOrDefault(x => x != null);
            }

            public void AddDataObject(DataObject dataObject)
            {
                _dataObjects.Add(dataObject);
                AddObject(dataObject);
            }
        }
    }
}