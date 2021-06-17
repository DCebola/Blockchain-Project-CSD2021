package com.models;

import com.untrusted.SmartContract;

public class SignedSmartContract extends SmartContract {

    private String signature;
    private String id;

    public SignedSmartContract(int outputNumber, String author, String date, String signature, String id) {
        super(outputNumber, author, date);
        this.signature = signature;
        this.id = id;
    }

    public SignedSmartContract() {
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
