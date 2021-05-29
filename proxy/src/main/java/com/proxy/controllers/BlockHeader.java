package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class BlockHeader implements Serializable {

    private static final long serialVersionUID = 6529655068467727690L;

    private final String previousHash;
    private String timeStamp;
    private int work;
    private final String integrityHash;
    private final List<String> transactions;


    public BlockHeader(String previousHash, List<String> transactions, String integrityHash, String timeStamp) {
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.integrityHash = integrityHash;
        this.timeStamp = timeStamp;
        this.work = -1;
    }

    public BlockHeader(){
        this.previousHash = null;
        this.transactions = null;
        this.integrityHash = null;
        this.timeStamp = null;
        this.work = -1;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public int getWork() {
        return work;
    }

    public String getIntegrityHash() {
        return integrityHash;
    }

    public List<String> getTransactions() {
        return transactions;
    }
}