package ru.aiz.cryptoprolib.dto;


import lombok.Data;

@Data
public class SimpleSignatureDTO {
    private final String digestAlg;
    private final byte[] hash;
    private final byte[] certificate;
    private final String signatureAlg;
    private final byte[] signature;
}
