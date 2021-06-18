package com.proxy.controllers;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class SmartContract implements Serializable {

    private static final long serialVersionUID = 562968899267729629L;


    private final int outputNumber;
    private final String author;
    private final String date;
    private final List<Transaction> output;
    private String currentOrigin;
    private int availableFunds;
    private List<String> currentDestinations;
    private String tempMemory;
    private String readTarget;


    private String signature;
    private int[] validatorIDs;
    private String hash;


    public SmartContract(int outputNumber, String author, String date) {
        this.outputNumber = outputNumber;
        this.author = author;
        this.date = date;
        this.output = new ArrayList<>(outputNumber);
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
        this.currentOrigin = null;
        this.availableFunds = -1;
        this.currentDestinations = null;
        this.readTarget = null;
    }

    public SmartContract() {
        this.outputNumber = -1;
        this.author = null;
        this.date = null;
        this.output = null;
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
        this.currentOrigin = null;
        this.availableFunds = -1;
        this.currentDestinations = null;
        this.readTarget = null;
    }

    public int getOutputNumber() {
        return outputNumber;
    }

    public String getAuthor() {
        return author;
    }

    public String getDate() {
        return date;
    }

    public SmartContractEvent init(String origin, int amount, List<String> destinations) {
        this.currentOrigin = origin;
        this.availableFunds = amount;
        this.currentDestinations = destinations;
        this.readTarget = null;
        return SmartContractEvent.BEGIN;
    }

    public SmartContractEvent run() {
        // Define contract behaviour here.
        return SmartContractEvent.STOP;
    }

    public String getReadTarget(){
        return readTarget;
    }

    public void read(String data){
        this.tempMemory = data;
    }

    public List<Transaction> getOutput() {
        return output;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public void setValidatorIDs(int[] validatorIDs) {
        this.validatorIDs = validatorIDs;
    }
}
