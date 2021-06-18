package com.models;

import java.io.Serializable;

public class InfoForDestination implements Serializable {

    private static final long serialVersionUID = 152968899299999929L;

    private final String origin;
    private final String destination;
    private final String secretValue;
    private final String destinationPointer;

    public InfoForDestination(String origin, String destination, String secretValue, String destinationPointer){
        this.origin = origin;
        this.destination = destination;
        this.secretValue = secretValue;
        this.destinationPointer = destinationPointer;
    }

    public InfoForDestination() {
        this.origin = null;
        this.destination = null;
        this.secretValue = null;
        this.destinationPointer = null;
    }

    public String getOrigin() {
        return origin;
    }

    public String getDestination() {
        return destination;
    }

    public String getSecretValue() {
        return secretValue;
    }

    public String getDestinationPointer() {
        return destinationPointer;
    }
}
