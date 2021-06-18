package com.clients;

import java.io.Serializable;
import java.math.BigInteger;

public class RegisterKeyMsgBody implements Serializable {

    private final String signatureAlgorithm;
    private static final long serialVersionUID = 7529685098267757690L;
    private final String publicKeyAlgorithm;
    private final String hashAlgorithm;
    private final BigInteger encryptedZero;
    private final BigInteger pkNSquare;

    public RegisterKeyMsgBody(String signatureAlgorithm, String publicKeyAlgorithm, String hashAlgorithm, BigInteger encryptedZero, BigInteger pkNSquare) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.encryptedZero = encryptedZero;
        this.pkNSquare = pkNSquare;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }


    public BigInteger getEncryptedZero() {
        return encryptedZero;
    }

    public BigInteger getPkNSquare() {
        return pkNSquare;
    }
}
