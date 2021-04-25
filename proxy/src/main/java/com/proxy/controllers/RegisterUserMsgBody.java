package com.proxy.controllers;

import java.io.Serializable;
import java.security.PublicKey;

public class RegisterUserMsgBody implements Serializable {

    private static final long serialVersionUID = 6529685098264829690L;

    private final PublicKey  publicKey;
    private final String  algorithm;

    public RegisterUserMsgBody(PublicKey publicKey, String algorithm) {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
