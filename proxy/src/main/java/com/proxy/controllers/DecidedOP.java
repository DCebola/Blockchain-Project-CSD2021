package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;


public class DecidedOP<T> implements Serializable {

    private final SignedTransaction signedTransaction;
    private final String hash;
    private final List<Integer> replicas;
    private static final long serialVersionUID = 152968808267757690L;

    public DecidedOP(SignedTransaction signedTransaction, String hash, List<Integer> replicas) {
        this.signedTransaction = signedTransaction;
        this.hash = hash;
        this.replicas = replicas;
    }

    public DecidedOP() {
        this.replicas = null;
        this.signedTransaction = null;
        this.hash = null;
    }

    public SignedTransaction getSignedTransaction()  {
        return signedTransaction;
    }

    public String getHash() {
        return hash;
    }

    public List<Integer> getReplicas() {
        return replicas;
    }
}
