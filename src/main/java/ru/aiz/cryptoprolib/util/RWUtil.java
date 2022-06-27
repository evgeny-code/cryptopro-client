package ru.aiz.cryptoprolib.util;

import org.bouncycastle.util.encoders.Base64;

public class RWUtil {

    public byte[] readCMSBase64(String fileContent) {
        String base64Cms = fileContent
                .replaceAll("-----BEGIN CMS-----", "")
                .replaceAll("-----END CMS-----", "")
                .trim();

        return Base64.decode(base64Cms);
    }

    public byte[] readCertificateBase64(String fileContent) {
        String base64Cert = fileContent
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .trim();

        return Base64.decode(base64Cert);
    }
}
