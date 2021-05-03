package com.clients;

import com.clients.SignedTransaction;

import java.io.Serializable;
import java.util.List;


public class ResultToRespond<T> implements Serializable {

    private final T response;
    private final SignedTransaction signedTransaction;
    private final String hash;
    private final List<Integer> replicas;
    private static final long serialVersionUID = 152968808267757690L;

    public ResultToRespond(SignedTransaction signedTransaction, String hash, T response, List<Integer> replicas) {
        this.response = response;
        this.signedTransaction = signedTransaction;
        this.hash = hash;
        this.replicas = replicas;
    }

    public ResultToRespond() {
        this.replicas = null;
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

    public List<Integer> getReplicas() {
        return replicas;
    }
}
