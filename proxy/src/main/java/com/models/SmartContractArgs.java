package com.models;

import java.io.Serializable;
import java.util.List;

public class SmartContractArgs implements Serializable {

    private static final long serialVersionUID = 929682398167857690L;

    private final int amount;
    private final List<String> destinations;

    public SmartContractArgs(int amount, List<String> destinations) {
        this.amount = amount;
        this.destinations = destinations;
    }

    public List<String> getDestinations() {
        return destinations;
    }

    public int getAmount() {
        return amount;
    }
}
