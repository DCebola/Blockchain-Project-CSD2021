package com.clients;

import com.clients.SignedTransaction;

import java.io.Serializable;


public class ResultToRespond<T> implements Serializable {

    private final T response;
    private final SignedTransaction signedTransaction;
    private final String hash;
    private static final long serialVersionUID = 152968808267757690L;

    public ResultToRespond(SignedTransaction signedTransaction, String hash, T response) {
        this.response = response;
        this.signedTransaction = signedTransaction;
        this.hash = hash;
    }

    public ResultToRespond() {
        this.response = null;
        this.signedTransaction = null;
        this.hash = null;
    }

    public T getResponse() {
        return response;
    }

    public SignedTransaction getSignedTransaction()  {
        return signedTransaction;
    }

    public String getHash() {
        return hash;
    }
}
