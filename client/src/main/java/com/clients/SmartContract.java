package com.clients;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

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
        if (done)
            return SmartContractEvent.STOP;
        else {
            int processDestinations = tempMemory.size();
            if (processDestinations < currentDestinations.size()) {
                readTarget = currentDestinations.get(processDestinations);
                return SmartContractEvent.READ_BALANCE;
            } else {
                assert gson != null;
                BigInteger balance1 = gson.fromJson(tempMemory.get(0), BigInteger.class);
                BigInteger balance2 = gson.fromJson(tempMemory.get(1), BigInteger.class);
                String currentDate = LocalDateTime.now().format(dateTimeFormatter);
                if (balance1.compareTo(balance2) > 0) {
                    BigInteger smallerFraction = availableFunds.divide(BigInteger.valueOf(4)).multiply(BigInteger.valueOf(3));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(0), smallerFraction, currentDate, null, null, null));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(1), availableFunds.subtract(smallerFraction), currentDate,null, null, null));
                } else if (balance1.compareTo(balance2) < 0) {
                    BigInteger smallerFraction = availableFunds.divide(BigInteger.valueOf(4));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(0), availableFunds.subtract(smallerFraction), currentDate,null, null, null));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(1), availableFunds, currentDate,null, null, null));
                } else {
                    BigInteger smallerFraction = availableFunds.divide(BigInteger.valueOf(2));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(0), availableFunds.subtract(smallerFraction), currentDate,null, null, null));
                    output.add(new Transaction(currentOrigin, currentDestinations.get(1), availableFunds.subtract(smallerFraction), currentDate,null, null, null));
                }
                done = true;
                return SmartContractEvent.STOP;
            }
        }
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
