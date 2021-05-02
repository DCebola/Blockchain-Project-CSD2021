package com.proxy.controllers;

import java.io.Serializable;

public class HashWithResponse<T> implements Serializable {

    private final T response;
    private final byte[] hash;
    private static final long serialVersionUID = 152968808267757690L;

    public HashWithResponse(byte[] hash, T response) {
        this.response = response;
        this.hash = hash;
    }

    public HashWithResponse() {
        this.response = null;
        this.hash = null;

    }

    public T getResponse() {
        return response;
    }

    public byte[] getHash() {
        return hash;
    }
}
