package com.untrusted;

import com.models.Transaction;
import java.io.Serializable;
import java.util.*;
import java.math.*;

public class SmartContract implements Serializable {

    private static final long serialVersionUID = 562968899267729629L;


    private final int outputNumber;
    private final String author;
    private final String date;
    private final List<Transaction> output;
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
    }

    public SmartContract() {
        this.outputNumber = -1;
        this.author = null;
        this.date = null;
        this.output = null;
        this.signature = null;
        this.validatorIDs = null;
        this.hash = null;
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

    public List<Transaction> exec(String origin, int amount, List<String> destinations) {
        assert output != null;
        output.clear();
        // Do stuff
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
