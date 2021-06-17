package com.clients;

import java.math.BigInteger;
import java.util.List;

public class ValidTransaction extends SignedTransaction {
    private static final long serialVersionUID = 152968899267757729L;

    private final String hash;
    private final List<Integer> replicas;

    public ValidTransaction(String origin, String destination, BigInteger amount, String signature, String date, String hash, List<Integer> replicas, String id, BigInteger encryptedAmount, String whoEncrypted, String transactionPointer) {
        super(origin, destination, amount, signature, date, id, encryptedAmount, whoEncrypted, transactionPointer);
        this.hash = hash;
        this.replicas = replicas;
    }

    public ValidTransaction() {
        super();
        this.hash = null;
        this.replicas = null;
    }

    public String getHash() {
        return hash;
    }

    public List<Integer> getReplicas() {
        return replicas;
    }

    @Override
    public String toString() {
        return String.format(
                "ID: %s , Origin: %s , Destination: %s , Amount: %s , Date: %s , Signature: %s , Replicas: %s , Hash: %s",
                this.getId(),
                this.getOrigin(),
                this.getDestination(),
                this.getAmount(),
                this.getDate(),
                this.getSignature(),
                this.getReplicas(),
                this.getHash());
    }
}