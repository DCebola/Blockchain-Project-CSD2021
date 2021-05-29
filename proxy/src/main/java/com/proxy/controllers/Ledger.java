package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class Ledger implements Serializable {

    private final List<Commit> transactions;
    private static final long serialVersionUID = 5529685098267757690L;

    public Ledger() {
        this.transactions = null;
    }

    public Ledger(List<Commit> transactions) {
        this.transactions = transactions;
    }

    public List<Commit> getTransactions() {
        return transactions;
    }

}
