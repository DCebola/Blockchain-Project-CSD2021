package com.clients;

import java.io.Serializable;
import java.util.List;


public class Ledger implements Serializable {

    private final List<Transaction> transactions;
    private static final long serialVersionUID = 5529685098267757690L;


    public Ledger() {
        this.transactions = null;
    }

    public Ledger(List<Transaction> transactions) {
        this.transactions = transactions;
    }

    public List<Transaction> getTransactions() {
        return transactions;
    }



}
