package com.proxy.controllers;

import com.google.gson.Gson;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class SmartContract implements Serializable {
    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";
    private static final long serialVersionUID = 562968899267729629L;


    private final int outputNumber;
    private final String author;
    private final String date;
    private final List<Transaction> output;
    private String currentOrigin;
    private BigInteger availableFunds;
    private List<String> currentDestinations;
    private List<String> tempMemory;
    private String readTarget;
    private boolean done;
    private DateTimeFormatter dateTimeFormatter;
    private final Gson gson;

    private String signature;
    private int[] validatorIDs;
    private String hash;


    public SmartContract(int outputNumber, String author, String date, Gson gson) {
        this.gson = gson;
        this.dateTimeFormatter = DateTimeFormatter.ofPattern(DATE_FORMATTER);
        this.outputNumber = outputNumber;
        this.author = author;
        this.date = date;
        this.output = new ArrayList<>(outputNumber);
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
        this.currentOrigin = null;
        this.availableFunds = null;
        this.currentDestinations = null;
        this.readTarget = null;
        this.done = false;
    }

    public SmartContract() {
        this.gson = null;
        this.dateTimeFormatter = null;
        this.outputNumber = -1;
        this.author = null;
        this.date = null;
        this.output = null;
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
        this.currentOrigin = null;
        this.availableFunds = null;
        this.currentDestinations = null;
        this.readTarget = null;
        this.done = false;

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

    public SmartContractEvent init(String origin, BigInteger amount, List<String> destinations) {
        this.currentOrigin = origin;
        this.availableFunds = amount;
        this.currentDestinations = destinations;
        this.readTarget = null;
        this.tempMemory = new LinkedList<>();
        this.done = false;
        return SmartContractEvent.BEGIN;
    }

    public SmartContractEvent run() {
        done = true;
        return SmartContractEvent.STOP;
    }

    public String getReadTarget() {
        return readTarget;
    }

    public void readTransaction(String data) {
        this.tempMemory.add(data);
    }

    public void readLedger(String data) {
        this.tempMemory.add(data);
    }

    public void readBalance(String data) {
        this.tempMemory.add(data);
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
