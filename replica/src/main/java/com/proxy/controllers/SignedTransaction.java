package com.proxy.controllers;

public class SignedTransaction extends Transaction {

    private final String signature;

    public SignedTransaction(String origin, String destination, double amount, String signature){
        super(origin, destination, amount);
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }
}
