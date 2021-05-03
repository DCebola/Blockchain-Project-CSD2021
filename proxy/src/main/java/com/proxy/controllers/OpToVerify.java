package com.proxy.controllers;

import bftsmart.tom.core.messages.TOMMessage;

import java.io.Serializable;
import java.util.List;

public class OpToVerify implements Serializable {

    private final byte[] response;
    private final List<Integer> replicas;
    private static final long serialVersionUID = 152968808267757780L;


    public OpToVerify(byte[] response, List<Integer> replicas) {
        this.response = response;
        this.replicas = replicas;
    }

    public OpToVerify() {
        this.response = null;
        this.replicas = null;
    }

    public byte[] getResponse() {
        return response;
    }

    public List<Integer> getReplicas() {
        return replicas;
    }
}
