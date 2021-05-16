package com.proxy.controllers;

import bftsmart.tom.AsynchServiceProxy;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.TOMUtil;
import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static bftsmart.tom.core.messages.TOMMessageType.ORDERED_REQUEST;
import static bftsmart.tom.core.messages.TOMMessageType.UNORDERED_REQUEST;

import java.io.*;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.*;

@RestController
public class LedgerController implements CommandLineRunner {

    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";

    private AsynchServiceProxy asynchServiceProxy;
    private Logger logger;
    private Base64 base64;
    private Gson gson;


    @PostMapping("/nonce/{who}")
    public String getNonce(@PathVariable String who, @RequestBody SignedBody<String> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.GET_NONCE);
            objOut.writeObject(who);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean res = objIn.readBoolean();
            String nonce = (String) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(res).concat(nonce).getBytes());
            if (MessageDigest.isEqual(msgToBeVerified, hash)) {
                if (!res) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists.");
                } else {
                    logger.info("User {} current nonce: {}", who, nonce);
                    return nonce;
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message was Tampered");
        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/register/{who}")
    public String register(@PathVariable String who, @RequestBody RegisterUserMsgBody body) {
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
            OpToVerify opToCommit = dispatchAsyncRequest(byteOut.toByteArray(), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToCommit.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean res = objIn.readBoolean();
            String nonce = (String) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(res).concat(nonce).getBytes());
            if (MessageDigest.isEqual(msgToBeVerified, hash)) {
                if (!res) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request");
                } else {
                    logger.info("OK. User {} registered successfully. Initial nonce {}", who, nonce);
                    return nonce;
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message was Tampered");
        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in registerUser. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{who}/obtainCoins")
    public DecidedOP<Double> obtainAmount(@PathVariable String who, @RequestBody SignedBody<Double> signedBody) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
            objOut.writeObject(who);
            objOut.writeDouble(signedBody.getContent());
            objOut.writeObject(signedBody.getDate());
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            List<Integer> replicas = opToVerify.getReplicas();
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            SignedTransaction signedTransaction = (SignedTransaction) objIn.readObject();
            boolean result = objIn.readBoolean();
            double coins = objIn.readDouble();
            String date = (String) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).concat(Double.toString(coins)).concat(date).getBytes());
            if (MessageDigest.isEqual(hash, msgToBeVerified)) {
                if (!result) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD request");
                } else {
                    DecidedOP<Double> resultToRespond = new DecidedOP<>(signedTransaction, new String(base64.encode(hash)), replicas);
                    byteOut = new ByteArrayOutputStream();
                    objOut = new ObjectOutputStream(byteOut);
                    objOut.writeObject(LedgerRequestType.COMMIT);
                    objOut.writeObject(resultToRespond);
                    objOut.flush();
                    byteOut.flush();
                    logger.info("OK. {} obtained {} coins.", who, coins);
                    asynchServiceProxy.invokeAsynchRequest(byteOut.toByteArray(), null, ORDERED_REQUEST);
                    return resultToRespond;
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
    public DecidedOP<Void> transferAmount(@RequestBody SignedBody<Transaction> signedBody) {

        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.TRANSFER_MONEY);
            Transaction transaction = signedBody.getContent();
            objOut.writeObject(transaction);
            objOut.writeObject(signedBody.getSignature());
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            List<Integer> replicas = opToVerify.getReplicas();
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            SignedTransaction signedTransaction = (SignedTransaction) objIn.readObject();
            boolean result = objIn.readBoolean();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).getBytes());
            if (MessageDigest.isEqual(msgToBeVerified, hash)) {
                if (!result) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
                } else {
                    DecidedOP<Void> resultToRespond = new DecidedOP<>(signedTransaction, new String(base64.encode(hash)), replicas);
                    byteOut = new ByteArrayOutputStream();
                    objOut = new ObjectOutputStream(byteOut);
                    objOut.writeObject(LedgerRequestType.COMMIT);
                    objOut.writeObject(resultToRespond);
                    objOut.flush();
                    byteOut.flush();
                    asynchServiceProxy.invokeAsynchRequest(byteOut.toByteArray(), null, ORDERED_REQUEST);
                    logger.info("OK. {} transferred {} coins to {}.", transaction.getOrigin(), transaction.getAmount(), transaction.getDestination());
                    return resultToRespond;
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message tampered");
        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in transferAmount. Cause: {}", e.getMessage());
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
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean result = objIn.readBoolean();
            double balance = objIn.readDouble();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).concat(Double.toString(balance)).getBytes());

            if (MessageDigest.isEqual(hash, msgToBeVerified)) {
                if (!result) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
                } else {
                    logger.info("OK. User {} has the {} coins.", who, balance);
                    return balance;
                }
            } else
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Message tampered");

        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in currentAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/ledger")
    public Ledger ledgerOfGlobalTransactions(@RequestBody DateInterval dates) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.GLOBAL_LEDGER);
            objOut.writeObject(dates);
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            List<DecidedOP> global_ledger = (List<DecidedOP>) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(global_ledger)).getBytes());
            if (MessageDigest.isEqual(hash, msgToBeVerified)) {
                logger.info("OK. Global ledger with length {}.", global_ledger.size());
                return new Ledger(global_ledger);
            } else {
                logger.error("Exception in ledgerOfGlobalTransactions. Cause: {}", "Message tampered");
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("Exception in ledgerOfGlobalTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/{who}/ledger")
    public Ledger ledgerOfClientTransactions(@PathVariable String who, @RequestBody DateInterval dateInterval) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.CLIENT_LEDGER);
            objOut.writeObject(who);
            objOut.writeObject(dateInterval);
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean result = objIn.readBoolean();
            List<DecidedOP> user_ledger = (List<DecidedOP>) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).concat(gson.toJson(user_ledger)).getBytes());
            if (MessageDigest.isEqual(hash, msgToBeVerified)) {
                if (!result) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request");
                } else {
                    logger.info("OK. User {} ledger found with length {}.", who, user_ledger.size());
                    return new Ledger(user_ledger);
                }
            } else {
                logger.error("Exception in ledgerOfClientTransactions. Cause: {}", "Message tampered");
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("IO exception in ledgerOfClientTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/verifyOp")
    public SignedTransaction verifyOp(@RequestBody String operation) {
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.VERIFY_OP);
            objOut.writeObject(operation);
            objOut.flush();
            byteOut.flush();
            OpToVerify opToVerify = dispatchAsyncRequest(byteOut.toByteArray(), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(opToVerify.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean result = objIn.readBoolean();
            SignedTransaction t = (SignedTransaction) objIn.readObject();
            byte[] msgToBeVerified = TOMUtil.computeHash(Boolean.toString(result).concat(gson.toJson(t)).getBytes());
            if (MessageDigest.isEqual(hash, msgToBeVerified)) {
                if (!result) {
                    logger.info("BAD REQUEST");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
                } else {
                    logger.info("Found operation associated to {}: {}", operation, gson.toJson(t));
                    return t;
                }
            } else {
                logger.error("Exception in verifyOp. Cause: {}", "Message tampered");
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("IO exception in verifyOp. Cause: {}", e.getMessage());
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

    private OpToVerify dispatchAsyncRequest(byte[] op, TOMMessageType messageType) throws IOException, ExecutionException, InterruptedException {
        CompletableFuture<OpToVerify> reply = new CompletableFuture<>();
        int quorumSize = getQuorumSize();
        asynchServiceProxy.invokeAsynchRequest(op, new ReplyListenerImp<>(reply, quorumSize), messageType);
        return reply.get();
    }

    @Override
    public void run(String... args) {
        this.logger = LoggerFactory.getLogger("LedgerClient");
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                logger.info("Launching client with uuid: {}", id);
                this.asynchServiceProxy = new AsynchServiceProxy(id);
                this.base64 = new Base64();
                this.gson = new Gson();
            } else logger.error("Usage: LedgerController <client ID>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int getQuorumSize() {
        return asynchServiceProxy.getViewManager().getCurrentViewN() - asynchServiceProxy.getViewManager().getCurrentViewF();
    }

}
