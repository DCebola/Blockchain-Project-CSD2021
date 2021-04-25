package com.proxy.controllers;

import java.io.Serializable;

public class SignedBody<T> implements Serializable {

    private final T content;
    private final String op;
    private final byte[] signature;
    private static final long serialVersionUID = 152968508267757690L;

    public SignedBody(T content, String op, byte[] signature) {
        this.content = content;
        this.op = op;
        this.signature = signature;
    }


    public T getContent() {
        return content;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getOp() {
        return op;
    }
}
