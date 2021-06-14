package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class BlockHeader implements Serializable {

    private static final long serialVersionUID = 6529655068467727690L;

    private final String previousHash;
    private String timeStamp;
    private int proof;
    private final String integrityHash;
    private final List<String> transactions;
    private String author;


    public BlockHeader(String author, String previousHash, List<String> transactions, String integrityHash, String timeStamp) {
        this.author = author;
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.integrityHash = integrityHash;
        this.timeStamp = timeStamp;
        this.proof = -1;
    }

    public BlockHeader(String author, String previousHash, List<String> transactions, String integrityHash, String timeStamp, int proof) {
        this.author = author;
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.integrityHash = integrityHash;
        this.timeStamp = timeStamp;
        this.proof = proof;
    }

    public BlockHeader() {
        this.author = null;
        this.previousHash = null;
        this.transactions = null;
        this.integrityHash = null;
        this.timeStamp = null;
        this.proof = -1;
    }

    public String getAuthor() {
        return author;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public int getProof() {
        return proof;
    }

    public String getIntegrityHash() {
        return integrityHash;
    }

    public List<String> getTransactions() {
        return transactions;
    }

    public void setProof(int proof) {
        this.proof = proof;
    }

    public void setAuthor(String author) {
        this.author = author;
    }
}