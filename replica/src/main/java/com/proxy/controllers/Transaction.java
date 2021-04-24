package com.proxy.controllers;


import java.io.Serializable;

public class Transaction implements Serializable {

    private static final long serialVersionUID = 6529685098267757690L;

    private final String origin;
    private final String destination;
    private final double amount;

    public Transaction(String origin, String destination, double amount) {
        this.origin = origin;
        this.destination = destination;
        this.amount = amount;
    }

    public String getOrigin() {
        return origin;
    }

    public String getDestination() {
        return destination;
    }

    public double getAmount() {
        return amount;
    }
}
