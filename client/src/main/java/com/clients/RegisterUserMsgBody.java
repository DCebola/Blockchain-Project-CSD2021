package com.clients;

import java.io.Serializable;

public class RegisterUserMsgBody implements Serializable {

    private byte[] publicKey;
    private String signatureAlgorithm;
    private static final long serialVersionUID = 7529685098267757690L;

    public RegisterUserMsgBody(byte[] publicKey, String signatureAlgorithm) {
        this.publicKey = publicKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }


    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
