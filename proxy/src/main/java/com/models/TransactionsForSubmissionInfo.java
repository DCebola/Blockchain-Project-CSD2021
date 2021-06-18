package com.models;

import java.io.Serializable;
import java.util.List;

public class TransactionsForSubmissionInfo implements Serializable {

    private static final long serialVersionUID = 5529611111167757690L;
    private final List<InfoForDestination> transactionsInfo;

    public TransactionsForSubmissionInfo() {
        this.transactionsInfo = null;
    }

    public TransactionsForSubmissionInfo(List<InfoForDestination> transactionsInfo) {
        this.transactionsInfo = transactionsInfo;
    }


    public List<InfoForDestination> getTransactionsInfo() {
        return transactionsInfo;
    }
}
