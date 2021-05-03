package com.clients;

public class SignedTransaction extends Transaction {

    private final String signature;
    private static final long serialVersionUID = 152968808267757799L;

    public SignedTransaction(String origin, String destination, double amount, String signature){
        super(origin, destination, amount);
        this.signature = signature;
    }

    public SignedTransaction(){
        super();
        this.signature = null;
    }

    public String getSignature() {
        return signature;
    }

}
