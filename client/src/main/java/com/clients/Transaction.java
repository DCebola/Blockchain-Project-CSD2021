package com.clients;


import java.io.Serializable;
import java.security.PublicKey;

public class Transaction implements Serializable {

    private static final long serialVersionUID = 6529685098267757690L;


    private final String origin;
    private final String destination;
    private final double amount;

    public Transaction() {
        origin = "";
        destination = "";
        amount = -1;
    }

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
