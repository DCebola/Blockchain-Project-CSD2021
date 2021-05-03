package com.proxy.controllers;

public class SignedTransaction extends Transaction {

    private final String signature;
    private final String hash;
    private static final long serialVersionUID = 152968808267757799L;

    public SignedTransaction(String origin, String destination, double amount, String signature, String hash){
        super(origin, destination, amount);
        this.signature = signature;
        this.hash = hash;
    }

    public SignedTransaction(){
        super();
        this.signature = null;
        this.hash = null;
    }

    public String getSignature() {
        return signature;
    }

    public String getHash() {
        return hash;
    }
}
