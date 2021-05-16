package com.clients;


import java.io.Serializable;
import java.security.PublicKey;

public class Transaction implements Serializable {

    private static final long serialVersionUID = 6529685098267757690L;


    private final String origin;
    private final String destination;
    private final double amount;
    private final String date;

    public Transaction() {
        this.amount = -1;
        this.origin = "";
        this.destination = "";
        this.date = "";
    }

    public Transaction(String origin, String destination, double amount, String date) {
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

    public double getAmount() {
        return amount;
    }

    public String getDate() {
        return date;
    }
}
