package com.proxy.controllers;

import java.io.Serializable;

public class RegisterKeyMsgBody implements Serializable {

    private final String signatureAlgorithm;
    private static final long serialVersionUID = 7529685098267757690L;
    private final String publicKeyAlgorithm;
    private final String hashAlgorithm;

    public RegisterKeyMsgBody(byte[] publicKey, String signatureAlgorithm, String publicKeyAlgorithm, String hashAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
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
