package ru.aiz.cryptoprolib;

import org.junit.jupiter.api.Test;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;
import ru.aiz.cryptoprolib.util.RWUtil;
import ru.aiz.cryptoprolib.util.SignerUtil;
import ru.aiz.cryptoprolib.util.VerifierUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Pkcs7Test {
    public static final String ALIAS = "2c514c48c-8aa3-d5df-67ab-c4d4329587b";

    static {
        Security.addProvider(new JCP());
    }

    private SignerUtil signerUtil = new SignerUtil();
    private VerifierUtil verifierUtil = new VerifierUtil();
    private RWUtil rwUtil = new RWUtil();

    @Test
    public void execute() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
        PrivateKey key = (PrivateKey) keyStore.getKey(ALIAS, "123123".toCharArray());

        List<X509Certificate> chain = new ArrayList<>();
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate)
                chain.add((X509Certificate) certificate);
        }

        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));

        byte[] pkcs7 = signerUtil.signPKCS7(messageBytes, chain, key, true);
        System.out.println("pkcs7.length=" + pkcs7.length);

        assert true == verifierUtil.verifyCMSDetached(messageBytes, pkcs7);
    }


    @Test
    void detachedCMS() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        keyStore.load(null, null);

        Certificate[] certificates = keyStore.getCertificateChain(ALIAS);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, "123123".toCharArray());
        X509Certificate certificate = (X509Certificate) certificates[0];

        //-------------------
        byte[] messageBytes = Files.readAllBytes(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf").toURI()));
        byte[] cmsBytes = rwUtil.readCMSBase64(Files.readString(Path.of(ClassLoader.getSystemResource("Акт о финансировании.pdf.lkz.sig").toURI())));

        //-------------------
        byte[] cmsBytesNew = signerUtil.signCMSDetached(messageBytes, certificate, privateKey);
        Array.writeFile("/home/evgeny/Downloads/Акт о финансировании.pdf.123.p7s", cmsBytesNew);

        System.out.println("verify cmsBytes = " + verifierUtil.verifyCMSDetached(messageBytes, cmsBytes));
        System.out.println("verify cmsBytesNew = " + verifierUtil.verifyCMSDetached(messageBytes, cmsBytesNew));
    }
}
