# KSeFSigner

KSeFSigner is an unofficial .NET 8 workaround for signing XML documents (AuthTokenRequest) in XAdES-BES format for KSeF API 2.0 (Polish National e-Invoicing System). Addresses the ECDSA-SHA256 support gap in .NET 8.



FEATURES:

\* XAdESSigner.Sign(xml, certificate) - sign using X509Certificate2 object

\* XAdESSigner.Sign(xml, certContent, keyContent, keyPassword) - sign using raw strings

\* XAdESSigner.Sign(xml, certContent, keyContent, securePassword) - sign using SecureString password

\* CertificateLoader.Load(certContent, keyContent, keyPassword) - load X509Certificate2 from strings

\* CertificateLoader.Load(certContent, keyContent, securePassword) - load X509Certificate2 using SecureString password

\* Built-in ECDSA-SHA256 registration for SignedXml

\* SecureString support for password handling - password is zeroed from memory after use



REQUIREMENTS:

\* .NET 8 (net8.0-windows)

\* ECDSA P-256 certificate from KSeF Certification Center (CCK MF)

SecureString support for password handling - password is zeroed from memory after use



INPUT XML (replace {challenge} and {nip}):
```xml

<?xml version="1.0" encoding="utf-8"?>

<AuthTokenRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://ksef.mf.gov.pl/auth/token/2.0">

&#x20; <Challenge>{challenge}</Challenge>

&#x20; <ContextIdentifier>

&#x20;   <Nip>{nip}</Nip>

&#x20; </ContextIdentifier>

&#x20; <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>

</AuthTokenRequest>

```

