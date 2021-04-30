package com.clients;

import java.io.Serializable;

public class RegisterUserMsgBody implements Serializable {

    private final byte[] publicKey;
    private final String signatureAlgorithm;
    private static final long serialVersionUID = 7529685098267757690L;
    private final String publicKeyAlgorithm;
    private final String hashAlgorithm;

    public RegisterUserMsgBody(byte[] publicKey, String signatureAlgorithm, String publicKeyAlgorithm, String hashAlgorithm) {
        this.publicKey = publicKey;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }


    public byte[] getPublicKey() {
        return publicKey;
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
}
