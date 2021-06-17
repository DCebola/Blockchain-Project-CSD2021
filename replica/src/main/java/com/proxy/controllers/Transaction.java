package com.proxy.controllers;


import java.io.Serializable;

import java.math.BigInteger;

public class Transaction implements Serializable {

    private static final long serialVersionUID = 6529685098267757690L;


    private final String origin;
    private final String destination;
    private final BigInteger amount;
    private final String date;

    public Transaction() {
        this.amount = null;
        this.origin = "";
        this.destination = "";
        this.date = "";
    }

    public Transaction(String origin, String destination, BigInteger amount, String date) {
        this.origin = origin;
        this.destination = destination;
        this.amount = amount;
        this.date = date;
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
}
