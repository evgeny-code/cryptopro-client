package ru.aiz.cryptoprolib.util;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.aiz.cryptoprolib.dto.SimpleSignatureDTO;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;

public class VerifierUtil {

    public boolean verifySimple(byte[] data, SimpleSignatureDTO simpleSignatureDTO) throws NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException {
        MessageDigest md = MessageDigest.getInstance(simpleSignatureDTO.getDigestAlg());
        byte[] dataHash = md.digest(data);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(simpleSignatureDTO.getCertificate()));

        final Signature signatureV = Signature.getInstance(simpleSignatureDTO.getSignatureAlg());
        signatureV.initVerify(cert);
        signatureV.update(dataHash);

        return signatureV.verify(simpleSignatureDTO.getSignature());
    }

    public boolean verifyCMSDetached(byte[] data, byte[] cmsPKCS7) throws CAdESException {
        CAdESSignature cadesSignature = new CAdESSignature(cmsPKCS7, data, CAdESType.PKCS7);
        try {
            cadesSignature.verify(Collections.emptySet());
        } catch (CAdESException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public void verify(byte[] cmsBytes, byte[] messageBytes, KeyStore keyStore) {
        //todo

    }
}
