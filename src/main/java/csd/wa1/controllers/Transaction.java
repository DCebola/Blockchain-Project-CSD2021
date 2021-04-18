package csd.wa1.controllers;

public class Transaction {

    private String origin;
    private String destination;
    private double amount;

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
