package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class Ledger implements Serializable {

    private final List<SignedTransaction> transactions;
    private static final long serialVersionUID = 5529685098267757690L;

    public Ledger() {
        this.transactions = null;
    }

    public Ledger(List<SignedTransaction> transactions) {
        this.transactions = transactions;
    }

    public List<SignedTransaction> getTransactions() {
        return transactions;
    }

}
