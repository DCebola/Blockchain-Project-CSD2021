package com.clients;


import java.io.Serializable;
import java.util.List;


public class ValidTransaction extends SignedTransaction {
    private static final long serialVersionUID = 152968899267757729L;

    private final String hash;
    private final List<Integer> replicas;
    private final String id;

    public ValidTransaction(String origin, String destination, double amount, String signature, String date, String hash, List<Integer> replicas, String id) {
        super(origin, destination, amount, date, signature);
        this.hash = hash;
        this.replicas = replicas;
        this.id = id;
    }

    public ValidTransaction() {
        super();
        this.id = null;
        this.hash = null;
        this.replicas = null;
    }

    public String getHash() {
        return hash;
    }

    public List<Integer> getReplicas() {
        return replicas;
    }

    public String getId() {
        return id;
    }
}
