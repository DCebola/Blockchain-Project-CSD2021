package com.proxy.controllers;

import bftsmart.tom.AsynchServiceProxy;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.util.TOMUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static bftsmart.tom.core.messages.TOMMessageType.ORDERED_REQUEST;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.*;

@RestController
public class LedgerController implements CommandLineRunner {

    private AsynchServiceProxy asynchServiceProxy;
    private Logger logger;


    @PostMapping("/login/{who}")
    public HashWithResponse<String> login(@PathVariable String who, @RequestBody SignedBody<String> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.LOGIN);
            objOut.writeObject(who);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            byte[] hash = (byte[]) objIn.readObject();
            boolean res = objIn.readBoolean();
            String nonce = (String) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(res).concat(nonce).getBytes());
            if(MessageDigest.isEqual(msgToBeVerified,hash)) {
                if (!res) {
                    logger.info("BAD REQUEST. User already exists {}", who);
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists.");
                } else {
                    logger.info("User {} logged in. Current nonce: {}", who, nonce);
                    return new HashWithResponse<>(hash,nonce);
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message was Tampered");
        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/register/{who}")
    public HashWithResponse<String> register(@PathVariable String who, @RequestBody RegisterUserMsgBody body) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.REGISTER_USER);
            objOut.writeObject(who);
            objOut.writeObject(body.getSignatureAlgorithm());
            objOut.writeObject(body.getPublicKey());
            objOut.writeObject(body.getPublicKeyAlgorithm());
            objOut.writeObject(body.getHashAlgorithm());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            byte[] hash = (byte[]) objIn.readObject();
            boolean res = objIn.readBoolean();
            String nonce = (String) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(res).concat(nonce).getBytes());
            if(MessageDigest.isEqual(msgToBeVerified,hash)) {
                if (!res) {
                    logger.info("BAD REQUEST. User already exists {}", who);
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists.");
                } else {
                    logger.info("OK. User {} registered successfully. Initial nonce {}", who, nonce);
                    return new HashWithResponse<>(hash,nonce);
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message was Tampered");
        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in registerUser. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{who}/obtainCoins")
    public HashWithResponse<Double> obtainAmount(@PathVariable String who, @RequestBody SignedBody<Double> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
            objOut.writeObject(who);
            objOut.writeDouble(signedBody.getContent());
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            byte[] hash = (byte[])objIn.readObject();
            boolean result = objIn.readBoolean();
            double coins = objIn.readDouble();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).concat(Double.toString(coins)).getBytes());
            if(MessageDigest.isEqual(hash,msgToBeVerified)) {
                if (!result) {
                    logger.info("BAD REQUEST. Non existent user {}", who);
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User does not exist.");
                } else {
                    logger.info("OK. {} obtained {} coins.", who, coins);
                    return new HashWithResponse<>(hash,coins);
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message tampered");

        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/transferMoney")
    @ResponseStatus(HttpStatus.OK)
    public void transferAmount(@RequestBody SignedBody<Transaction> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.TRANSFER_MONEY);
            Transaction transaction = signedBody.getContent();
            objOut.writeObject(transaction);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Proposed transaction: ({}, {}, {})", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else
                logger.info("OK. {} transferred {} coins to {}.", transaction.getOrigin(), transaction.getAmount(), transaction.getDestination());
        } catch (IOException | InterruptedException | ExecutionException e) {
            logger.error("Exception in transferAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{who}/balance")
    public double currentAmount(@PathVariable String who, @RequestBody SignedBody<String> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.CURRENT_AMOUNT);
            objOut.writeObject(who);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Non existent user {}", who);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User does not exist.");
            } else {
                double balance = objIn.readDouble();
                logger.info("OK. User {} has the {} coins.", who, balance);
                return balance;
            }
        } catch (IOException | InterruptedException | ExecutionException e) {
            logger.error("Exception in currentAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/ledger")
    public Ledger ledgerOfGlobalTransactions() {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.GLOBAL_LEDGER);
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            List<SignedTransaction> global_ledger = (List<SignedTransaction>) objIn.readObject();
            logger.info("OK. Global ledger with length {}.", global_ledger.size());
            return new Ledger(global_ledger);
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("Exception in ledgerOfGlobalTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/{who}/ledger")
    public Ledger ledgerOfClientTransactions(@PathVariable String who, @RequestBody SignedBody<String> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.CLIENT_LEDGER);
            objOut.writeObject(who);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            ObjectInput objIn = dispatchAsyncRequest(byteOut.toByteArray());
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST. Non existent user {}", who);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User does not exist.");
            } else {
                List<SignedTransaction> user_ledger = (List<SignedTransaction>) objIn.readObject();
                logger.info("OK. User {} ledger found with length {}.", who, user_ledger.size());
                return new Ledger(user_ledger);
            }
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("IO exception in ledgerOfClientTransactions. Cause: {}", e.getMessage());
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

    private ObjectInput dispatchAsyncRequest(byte[] op) throws IOException, ExecutionException, InterruptedException {
        CompletableFuture<byte[]> reply = new CompletableFuture<>();
        int quorumSize = getQuorumSize();
        asynchServiceProxy.invokeAsynchRequest(op, new ReplyListenerImp<>(reply, quorumSize), ORDERED_REQUEST);
        return new ObjectInputStream(new ByteArrayInputStream(reply.get()));
    }

    @Override
    public void run(String... args) {
        this.logger = LoggerFactory.getLogger("LedgerClient");
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                logger.info("Launching client with uuid: {}", id);
                this.asynchServiceProxy = new AsynchServiceProxy(id);
            } else logger.error("Usage: LedgerController <client ID>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int getQuorumSize() {
        return asynchServiceProxy.getViewManager().getCurrentViewN() - asynchServiceProxy.getViewManager().getCurrentViewF();
    }

    private byte[] generateHash(byte[] msg) throws NoSuchAlgorithmException {
        return TOMUtil.computeHash(msg);
    }

}
