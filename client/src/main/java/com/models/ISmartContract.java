package com.models;

import com.enums.SmartContractEvent;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

public interface ISmartContract extends Serializable {

    public String getAuthor();

    public String getDate();

    public SmartContractEvent init(String origin, BigInteger amount, List<String> destinations);

    public SmartContractEvent run();

    public String getReadTarget();

    public void readTransaction(Transaction transaction);

    public void readBalance(BigInteger balance) ;

    public List<Transaction> getOutput();

    public void setSignature(String signature);

    public void setHash(String hash);

    public void setValidatorIDs(int[] validatorIDs);
}

