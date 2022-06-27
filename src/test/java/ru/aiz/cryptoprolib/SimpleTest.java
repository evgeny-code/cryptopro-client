package ru.aiz.cryptoprolib;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import ru.CryptoPro.CAdES.tools.verifier.GostCMSSignatureAlgorithmNameGenerator;
import ru.CryptoPro.CAdES.tools.verifier.GostSignatureAlgorithmIdentifierFinder;
import ru.CryptoPro.JCP.JCP;
import ru.aiz.cryptoprolib.dto.SimpleSignatureDTO;
import ru.aiz.cryptoprolib.util.RWUtil;
import ru.aiz.cryptoprolib.util.SignerUtil;
import ru.aiz.cryptoprolib.util.VerifierUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;

public class SimpleTest {
    public static final String ALIAS = "2c514c48c-8aa3-d5df-67ab-c4d4329587b";

    static {
        Security.addProvider(new JCP());
    }

    private final RWUtil rwUtil = new RWUtil();
    private final SignerUtil signerUtil = new SignerUtil();
    private final VerifierUtil verifierUtil = new VerifierUtil();

    @Test
    public void test() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
        Key key = keyStore.getKey(ALIAS, "123123".toCharArray());

        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));

        SimpleSignatureDTO simpleSignatureDTO = signerUtil.signSimple(messageBytes, certificates[0], (PrivateKey) key);
        System.out.println(simpleSignatureDTO);

        System.out.println("Verify result: " + verifierUtil.verifySimple(messageBytes, simpleSignatureDTO));
    }

    /** не работает)) */
    @Test
    void verify() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, "123123".toCharArray());
        X509Certificate c = (X509Certificate) certificates[0];

        //-------------------
        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));
        byte[] cmsBytes = rwUtil.readCMSBase64(Files.readString(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf.lkz.sig").toURI())));

        CMSSignedData signedData = new CMSSignedData(cmsBytes);
        System.out.println("");
        Iterator signerInfos = signedData.getSignerInfos().iterator();

        while (signerInfos.hasNext()) {
            SignerInformation signer = (SignerInformation) signerInfos.next();
            MessageDigest messageDigest = MessageDigest.getInstance(signer.getDigestAlgOID());
            byte[] digest = messageDigest.digest(messageBytes);

            System.out.println("digest calula = " + new String(digest));


            for (Object o : signedData.getCertificates().getMatches(signer.getSID())) {
                X509CertificateHolder certHolder = (X509CertificateHolder) o;
                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
                    System.out.println("verified");
                }

                System.out.println("digest in sig = " + new String(signer.getContentDigest()));
            }


            SignerInformationVerifier verifier = new SignerInformationVerifier(new GostCMSSignatureAlgorithmNameGenerator(),
                    new GostSignatureAlgorithmIdentifierFinder(),
                    new JcaContentVerifierProviderBuilder().build(c),
                    new JcaDigestCalculatorProviderBuilder().build());
            boolean verify = signer.verify(verifier);
            System.out.println(verify);
        }
    }
}
