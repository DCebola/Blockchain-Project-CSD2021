package com.proxy.controllers;


import java.io.Serializable;

import java.math.BigInteger;

public class Transaction implements Serializable {

    private static final long serialVersionUID = 6529685098267757690L;


    private final String origin;
    private final String destination;
    private final BigInteger amount;
    private final String date;
    private final BigInteger encryptedAmount;
    private final String whoEncrypted;
    private final String transactionPointer;

    public Transaction() {
        this.amount = null;
        this.origin = "";
        this.destination = "";
        this.date = "";
        this.encryptedAmount = null;
        this.whoEncrypted = null;
        this.transactionPointer = null;
    }

    public Transaction(String origin, String destination, BigInteger amount, String date, BigInteger encryptedAmount,String whoEncrypted, String transactionPointer) {
        this.origin = origin;
        this.destination = destination;
        this.amount = amount;
        this.date = date;
        this.encryptedAmount = encryptedAmount;
        this.whoEncrypted = whoEncrypted;
        this.transactionPointer = transactionPointer;
    }

    public String getOrigin() {
        return origin;
    }

    public String getDestination() {
        return destination;
    }

    public BigInteger getAmount() {
        return amount;
    }

    public String getDate() {
        return date;
    }

    public BigInteger getEncryptedAmount() {
        return encryptedAmount;
    }

    public String getWhoEncrypted() {
        return whoEncrypted;
    }

    public String getTransactionPointer() {
        return transactionPointer;
    }
}