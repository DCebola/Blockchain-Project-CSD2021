package com.proxy.controllers;

import java.io.Serializable;

public class Wallet implements Serializable {
    private static final long serialVersionUID = 152968238267857690L;

    private final String publicKey;
    private final String publicKeyAlgorithm;
    private final String signatureAlgorithm;
    private final String hashAlgorithm;

    public Wallet(String publicKey, String publicKeyAlgorithm, String signatureAlgorithm, String hashAlgorithm) {
        this.publicKey = publicKey;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }
    public Wallet(){
        this.publicKey = null;
        this.publicKeyAlgorithm = null;
        this.signatureAlgorithm = null;
        this.hashAlgorithm = null;
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public String getPublicKeyAlgorithm() {
        return this.publicKeyAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }
}
