package ru.aiz.cryptoprolib;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import ru.CryptoPro.CAdES.tools.verifier.GostCMSSignatureAlgorithmNameGenerator;
import ru.CryptoPro.CAdES.tools.verifier.GostContentVerifierProvider;
import ru.CryptoPro.CAdES.tools.verifier.GostDigestCalculatorProvider;
import ru.CryptoPro.CAdES.tools.verifier.GostSignatureAlgorithmIdentifierFinder;
import ru.CryptoPro.JCP.JCP;
import ru.aiz.cryptoprolib.util.RWUtil;
import ru.aiz.cryptoprolib.util.SignerUtil;
import ru.aiz.cryptoprolib.util.VerifierUtil;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class VerifySignTest {
    static {
        Security.addProvider(new JCP());
        Security.addProvider(new BouncyCastleProvider());
    }

    private final RWUtil rwUtil = new RWUtil();
    private final SignerUtil signerUtil = new SignerUtil();
    private final VerifierUtil verifierUtil = new VerifierUtil();

    @Test
    public void checkLkzSign2() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        // Certificate[] certificates = keyStore.getCertificateChain("2c514c48c-8aa3-d5df-67ab-c4d4329587b");
        Key key = keyStore.getKey("2c514c48c-8aa3-d5df-67ab-c4d4329587b", "123123".toCharArray());

        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));
        byte[] cmsBytes = rwUtil.readCMSBase64(Files.readString(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf.lkz.sig").toURI())));

        CMSTypedStream dataStream = new CMSTypedStream(new ByteArrayInputStream(messageBytes));
        // Файловый поток читаемой подписи.
        InputStream fInSig = new ByteArrayInputStream(cmsBytes);

        DigestCalculatorProvider digestCalculatorProvider = new GostDigestCalculatorProvider(key, JCP.PROVIDER_NAME);

        CMSSignedDataParser parser = new CMSSignedDataParser(digestCalculatorProvider, dataStream, fInSig);

        // Список подписантов.
        SignerInformationStore signers = parser.getSignerInfos();

        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        jcaX509CertificateConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        // Список сертификатов для проверки подписи.
        Store store = parser.getCertificates();
        for (SignerInformation signer : signers.getSigners()) {
            for (Object storeMatch : store.getMatches(signer.getSID())) {
                // X509Certificate certificate = (X509Certificate) storeMatch;

                X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) storeMatch;
                X509Certificate certificate = jcaX509CertificateConverter.getCertificate(x509CertificateHolder);


                final SignerInformationVerifier signerVerifier = new SignerInformationVerifier(
                        new GostCMSSignatureAlgorithmNameGenerator(),
                        new GostSignatureAlgorithmIdentifierFinder(),
                        new GostContentVerifierProvider(certificate, JCP.PROVIDER_NAME),
                        new GostDigestCalculatorProvider(key, JCP.PROVIDER_NAME));

                // Проверяем подпись.
                // Можно проверить в CSP так:
                // csptest -cmssfsign -verify -in "C:\attached.signature" -my УЦ -cades_disable
                if (signer.verify(signerVerifier)) {
                    System.out.println("ЭЦП проверена открытым ключом сертификата: " + certificate.getSubjectDN());
                }
            }
        }

    }

    @Test
    public void checkLkzSign() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain("2c514c48c-8aa3-d5df-67ab-c4d4329587b");
        Key key = keyStore.getKey("2c514c48c-8aa3-d5df-67ab-c4d4329587b", "123123".toCharArray());

        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));
        byte[] cmsBytes = rwUtil.readCMSBase64(Files.readString(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf.lkz.sig").toURI())));

        CMSSignedData cmsSignedData = new CMSSignedData(cmsBytes);
        System.out.println(cmsSignedData);

        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        jcaX509CertificateConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);

        Store store = cmsSignedData.getCertificates();
        for (SignerInformation signer : cmsSignedData.getSignerInfos().getSigners()) {
            for (Object storeMatch : store.getMatches(signer.getSID())) {
                if (storeMatch instanceof X509CertificateHolder) {
                    X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) storeMatch;
                    X509Certificate certificate = jcaX509CertificateConverter.getCertificate(x509CertificateHolder);

                    //boolean signatureValid = x509CertificateHolder.isSignatureValid(new GostContentVerifierProvider(certificate, JCP.PROVIDER_NAME));
                    //System.out.println(signatureValid);

                    validate(cmsSignedData, certificate, (PrivateKey) key);
                }
            }

        }

    }

    private void validate(CMSSignedData cmsSignedData, X509Certificate signerCert, PrivateKey privateKey) throws CMSException {
        boolean verified = cmsSignedData.verifySignatures(new SignerInformationVerifierProvider() {

            @Override
            public SignerInformationVerifier get(SignerId sid) throws OperatorCreationException {

                try {

                    return new SignerInformationVerifier(
                            new GostCMSSignatureAlgorithmNameGenerator(),
                            new GostSignatureAlgorithmIdentifierFinder(),
                            new GostContentVerifierProvider(signerCert, JCP.PROVIDER_NAME),
                            new GostDigestCalculatorProvider(privateKey, JCP.PROVIDER_NAME));

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            }
        }, true);

        System.out.println("BC verified - " + verified);
    }

    @Test
    public void verifyExternal() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain("2c514c48c-8aa3-d5df-67ab-c4d4329587b");
        Key key = keyStore.getKey("2c514c48c-8aa3-d5df-67ab-c4d4329587b", "123123".toCharArray());

        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));
        byte[] cmsBytes = rwUtil.readCMSBase64(Files.readString(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf.lkz.sig").toURI())));

        verifierUtil.verify(cmsBytes, messageBytes, keyStore);
    }
}
