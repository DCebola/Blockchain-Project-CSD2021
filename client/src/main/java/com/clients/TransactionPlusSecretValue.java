package com.clients;

import java.io.Serializable;

public class TransactionPlusSecretValue implements Serializable {

    private static final long serialVersionUID = 6529999098267757690L;
    private final Transaction transaction;
    private final String secretValue;

    public TransactionPlusSecretValue(Transaction transaction, String secretValue) {
        this.transaction = transaction;
        this.secretValue = secretValue;
    }

    public TransactionPlusSecretValue() {
        this.transaction = null;
        this.secretValue = null;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public String getSecretValue() {
        return secretValue;
    }
}
