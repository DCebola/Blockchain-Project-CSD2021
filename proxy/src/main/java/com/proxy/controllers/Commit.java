package com.proxy.controllers;

import java.io.Serializable;
import java.util.List;

public class Commit<T> implements Serializable {

    private static final long serialVersionUID = 152968808267757690L;

    private final T request;
    private final String hash;
    private final List<Integer> replicas;

    public Commit(T request, String hash, List<Integer> replicas) {
        this.request = request;
        this.hash = hash;
        this.replicas = replicas;
    }

    public Commit() {
        this.replicas = null;
        this.request = null;
        this.hash = null;
    }

    public T getRequest() {
        return request;
    }

    public String getHash() {
        return hash;
    }

    public List<Integer> getReplicas() {
        return replicas;
    }

}
