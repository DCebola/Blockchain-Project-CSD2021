package com.clients;

import java.io.Serializable;
import java.util.List;

public class Ledger implements Serializable {

    private final List<ValidTransaction> transactions;
    private static final long serialVersionUID = 5529685098267757690L;

    public Ledger() {
        this.transactions = null;
    }

    public Ledger(List<ValidTransaction> transactions) {
        this.transactions = transactions;
    }

    public List<ValidTransaction> getTransactions() {
        return transactions;
    }

}
