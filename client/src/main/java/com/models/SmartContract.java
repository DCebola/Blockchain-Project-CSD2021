package com.models;

import com.enums.SmartContractEvent;
import com.google.gson.Gson;
import com.models.Transaction;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class SmartContract implements ISmartContract {
    private static final long serialVersionUID = 562968892267729629L;


    private final String author;
    private final String date;
    private List<Transaction> output;
    private String currentOrigin;
    private BigInteger availableFunds;
    private List<String> currentDestinations;
    private String readTarget;
    private boolean done;
    private List<Transaction> tempTransactions;
    private List<BigInteger> tempBalances;

    private String signature;
    private int[] validatorIDs;
    private String hash;


    public SmartContract(String author, String date) {
        this.author = author;
        this.date = date;
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
        this.currentOrigin = null;
        this.availableFunds = null;
        this.currentDestinations = null;
        this.readTarget = null;
        this.done = false;
        this.output = null;
        this.tempTransactions = null;
        this.tempBalances = null;
    }

    public SmartContract() {
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
        this.tempTransactions = null;
        this.tempBalances = null;

    }

    public String getAuthor() {
        return author;
    }

    public String getDate() {
        return date;
    }

    public SmartContractEvent init(String origin, BigInteger amount, List<String> destinations) {
        this.currentOrigin = origin;
        this.output = new LinkedList<>();
        this.availableFunds = amount;
        this.currentDestinations = destinations;
        this.readTarget = null;
        this.done = false;
        this.tempTransactions = new LinkedList<>();;
        this.tempBalances = new LinkedList<>();;
        return SmartContractEvent.BEGIN;
    }

    public SmartContractEvent run() {
        if (done)
            return SmartContractEvent.STOP;
        else {
            int processDestinations = tempBalances.size();
            if (processDestinations < currentDestinations.size()) {
                readTarget = currentDestinations.get(processDestinations);
                return SmartContractEvent.READ_BALANCE;
            } else {
                BigInteger balance1 = tempBalances.get(0);
                BigInteger balance2 = tempBalances.get(1);
                String currentDate = LocalDateTime.now().toString();
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

    public void readTransaction(Transaction transaction) {
        this.tempTransactions.add(transaction);
    }

    public void readBalance(BigInteger balance) {
        this.tempBalances.add(balance);
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
