package ru.aiz.cryptoprolib.util;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.CAdES.tools.verifier.GostContentSignerProvider;
import ru.CryptoPro.CAdES.tools.verifier.GostDigestCalculatorProvider;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;
import ru.aiz.cryptoprolib.dto.SimpleSignatureDTO;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public class SignerUtil {
    public static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    public static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";

    public SimpleSignatureDTO signSimple(byte[] data, Certificate certificate, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(JCP.GOST_DIGEST_NAME);
        byte[] dataHash = md.digest(data);

        final Signature signatureS = Signature.getInstance(JCP.GOST_SIGN_2012_256_OID, JCP.PROVIDER_NAME);
        signatureS.initSign(privateKey);
        signatureS.update(dataHash);
        byte[] sign = signatureS.sign();

        return new SimpleSignatureDTO(JCP.GOST_DIGEST_NAME, dataHash,
                certificate.getEncoded(),
                JCP.GOST_SIGN_2012_256_OID, sign);
    }

    public byte[] signPKCS7(byte[] data, List<X509Certificate> chain, PrivateKey privateKey, boolean attached) throws CertificateEncodingException, CAdESException, CMSException, IOException, OperatorCreationException {
        Store certStore = new JcaCertStore(chain);
        final X509Certificate signerCert = chain.iterator().next();

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new GostContentSignerProvider(privateKey, JCP.PROVIDER_NAME);

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(new GostDigestCalculatorProvider(privateKey, JCP.PROVIDER_NAME))
                .build(contentSigner, signerCert);

        generator.addSignerInfoGenerator(signerInfoGenerator);
        generator.addCertificates(certStore);

        // Создаем совмещенную подпись PKCS7.

        CMSProcessable content = new CMSProcessableByteArray(data);
        CMSSignedData signedData = generator.generate((CMSTypedData) content, attached);

        return signedData.getEncoded();
    }

    public byte[] signCMSDetached(byte[] data, X509Certificate certificate, PrivateKey privateKey) throws Exception {
        String digestOid = AlgorithmUtility.keyAlgToDigestOid(privateKey.getAlgorithm());
        String keyOid = AlgorithmUtility.keyAlgToKeyAlgorithmOid(privateKey.getAlgorithm()); // алгоритм ключа подписи
        String signOid = AlgorithmUtility.keyAlgToSignatureOid(privateKey.getAlgorithm());

        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // digest
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;


        cms.encapContentInfo = new EncapsulatedContentInfo(
                new Asn1ObjectIdentifier(
                        new OID(STR_CMS_OID_DATA).value), null);


        cms.certificates = new CertificateSet(1);
        cms.certificates.elements = new CertificateChoices[1];

        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate certificate88 =
                new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();
        final Asn1BerDecodeBuffer decodeBuffer =
                new Asn1BerDecodeBuffer(certificate.getEncoded());
        certificate88.decode(decodeBuffer);

        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(certificate88);

        // Signature.getInstance
        final java.security.Signature signature = java.security.Signature.getInstance(signOid);
        byte[] sign;

        // signer infos
        cms.signerInfos = new SignerInfos(1);
        signature.initSign(privateKey);
        signature.update(data);
        sign = signature.sign();

        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = certificate.getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(certificate.getSerialNumber());
        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(digestOid).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(keyOid).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signature = new SignatureValue(sign);


        // encode
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }

}
