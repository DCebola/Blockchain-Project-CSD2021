package com.proxy.controllers;

import bftsmart.tom.ServiceProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.*;
import java.util.List;

@RestController
public class LedgerController implements CommandLineRunner {

    private ServiceProxy serviceProxy;
    private Logger logger;


    /*@RequestMapping(value = "/{who}/obtainCoins",
            produces = "application/json",
            method=RequestMethod.POST)*/
    @PostMapping("/{who}/obtainCoins")
    public double obtainAmount(@PathVariable String who, @RequestBody double amount) {
        try {
            System.out.println("Hello");
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
            objOut.writeObject(who);
            objOut.writeDouble(amount);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            double coins = objIn.readDouble();
            logger.info("OK. {} obtained {} coins.", who, coins);
            return coins;


        } catch (IOException e) {
            logger.error("IO exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/transferMoney")
    @ResponseStatus(HttpStatus.OK)
    public void transferAmount(@RequestBody Transaction transaction) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.TRANSFER_MONEY);
            objOut.writeObject(transaction);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Proposed transaction: ({}, {}, {})", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else
                logger.info("OK. {} transferred {} coins to {}.", transaction.getOrigin(), transaction.getAmount(), transaction.getDestination());
        } catch (IOException e) {
            logger.error("IO exception in transferAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{who}/balance")
    public double currentAmount(@PathVariable String who) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.CURRENT_AMOUNT);
            objOut.writeObject(who);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Non existent user {}", who);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User does not exist.");
            } else {
                double balance = objIn.readDouble();
                logger.info("OK. User {} has the {} coins.", who, balance);
                return balance;
            }
        } catch (IOException e) {
            logger.error("IO exception in currentAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/ledger")
    public List<Transaction> ledgerOfGlobalTransactions() {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.GLOBAL_LEDGER);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            List<Transaction> global_ledger = (List<Transaction>) objIn.readObject();
            logger.info("OK. Global ledger with length {}.", global_ledger.size());
            return global_ledger;
        } catch (IOException e) {
            logger.error("IO exception in ledgerOfGlobalTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ClassNotFoundException e) {
            logger.error("Class not found in ledgerOfGlobalTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/{who}/ledger")
    public List<Transaction> ledgerOfClientTransactions(@PathVariable String who) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.CLIENT_LEDGER);
            objOut.writeObject(who);
            objOut.flush();
            byteOut.flush();
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());
            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Non existent user {}", who);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User does not exist.");
            } else {
                List<Transaction> user_ledger = (List<Transaction>) objIn.readObject();
                logger.info("OK. User {} ledger found with length {}.", who, user_ledger.size());
                return user_ledger;
            }
        } catch (IOException e) {
            logger.error("IO exception in ledgerOfClientTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ClassNotFoundException e) {
            logger.error("Class not found in ledgerOfClientTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{who}/minerate")
    public double minerateMoney(@PathVariable String who) {
        return 0.0f;
    }

    @PostMapping("/{who}/installSmartContract")
    @ResponseStatus(HttpStatus.OK)
    public void installSmartContract(@PathVariable String who, @RequestBody SmartContract smartContract) {
    }

    @PostMapping("/smartTransfer")
    @ResponseStatus(HttpStatus.OK)
    public void transferMoneyWithSmartContract(@RequestBody SmartTransferArgs args) {

    }

    @Override
    public void run(String... args) {
        this.logger = LoggerFactory.getLogger("LedgerClient");
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                logger.info("Launching client with uuid: {}", id);
                this.serviceProxy = new ServiceProxy(id);
            } else logger.error("Missing param: client ID");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}