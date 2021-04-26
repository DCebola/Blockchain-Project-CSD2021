package com.proxy.controllers;

import java.io.Serializable;

public class SignedTransaction implements Serializable {

    private String msgToBeSigned;
    private byte[] signedMessage;
    private Transaction transaction;
    private String whoSigned;

    public SignedTransaction(String msgToBeSigned, byte[] signedMessage, Transaction transaction, String whoSigned) {
        this.msgToBeSigned = msgToBeSigned;
        this.signedMessage = signedMessage;
        this.transaction = transaction;
        this.whoSigned = whoSigned;
    }

    public SignedTransaction() {
        signedMessage = null;
        msgToBeSigned = null;
        transaction = null;
        whoSigned = null;
    }

    public String getMsgToBeSigned() {
        return msgToBeSigned;
    }

    public byte[] getSignedMessage() {
        return signedMessage;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public String getWhoSigned() {
        return whoSigned;
    }

}
