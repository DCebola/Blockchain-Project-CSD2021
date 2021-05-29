package com.proxy.controllers;

public class SignedTransaction extends Transaction {

    private final String signature;
    private static final long serialVersionUID = 152968808267757799L;
    private final String id;


    public SignedTransaction(String origin, String destination, double amount, String signature, String date, String id){
        super(origin, destination, amount, date);
        this.signature = signature;
        this.id = id;
    }

    public SignedTransaction(){
        super();
        this.signature = null;
        this.id = null;
    }

    public String getSignature() {
        return signature;
    }

    public String getId() {
        return id;
    }
}
