package com.models;

import java.io.Serializable;
import java.util.List;

public class SmartContractArgs implements Serializable {

    private static final long serialVersionUID = 929682398167857690L;

    private final int amount;
    private final String origin;
    private final List<String> destinations;

    public SmartContractArgs(int amount, String origin, List<String> destinations) {
        this.amount = amount;
        this.origin = origin;
        this.destinations = destinations;
    }

    public List<String> getDestinations() {
        return destinations;
    }

    public int getAmount() {
        return amount;
    }

    public String getOrigin() {
        return origin;
    }
}
