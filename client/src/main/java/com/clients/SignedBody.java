package com.clients;

import java.io.Serializable;

public class SignedBody<T> implements Serializable {

    private final T content;
    private final byte[] signature;
    private final String date;
    private static final long serialVersionUID = 152968508267757690L;

    public SignedBody(T content, byte[] signature, String date) {
        this.content = content;
        this.signature = signature;
        this.date = date;
    }

    public T getContent() {
        return content;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getDate() {
        return date;
    }


}
