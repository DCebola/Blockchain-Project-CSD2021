package com.models;

import bftsmart.tom.core.messages.TOMMessage;

import java.io.Serializable;
import java.util.List;

public class QuorumResponse implements Serializable {

    private final byte[] response;
    private final List<Integer> replicas;
    private static final long serialVersionUID = 152968808267757780L;


    public QuorumResponse(byte[] response, List<Integer> replicas) {
        this.response = response;
        this.replicas = replicas;
    }

    public QuorumResponse() {
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
