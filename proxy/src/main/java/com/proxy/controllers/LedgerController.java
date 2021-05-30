package com.proxy.controllers;

import bftsmart.tom.AsynchServiceProxy;
import bftsmart.tom.core.messages.TOMMessageType;
import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import static bftsmart.tom.core.messages.TOMMessageType.ORDERED_REQUEST;
import static bftsmart.tom.core.messages.TOMMessageType.UNORDERED_REQUEST;

import java.io.*;
import java.util.List;
import java.util.concurrent.*;

@RestController
public class LedgerController implements CommandLineRunner {

    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";

    private AsynchServiceProxy asynchServiceProxy;
    private Logger logger;
    private Base32 base32;
    private Gson gson;


    @PostMapping("/nonce/{who}")
    public String getNonce(@PathVariable String who, @RequestBody SignedBody<String> body) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createGetNonceRequest(who, body), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            objIn.readObject(); //Hash
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Key already registered.");
            } else {
                String nonce = (String) objIn.readObject();
                logger.info("Key {} current nonce: {}", who, nonce);
                return nonce;
            }
        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/register/{who}")
    public String register(@PathVariable String who, @RequestBody RegisterKeyMsgBody body) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createRegisterRequest(who, body), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request");
            } else {
                Wallet wallet = (Wallet) objIn.readObject();
                Commit<Wallet> commit = new Commit<>(wallet, base32.encodeAsString(hash), quorumResponse.getReplicas());
                quorumResponse = commit(commit, LedgerRequestType.COMMIT_WALLET);
                objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
                objIn.readInt();
                objIn.readObject(); //Hash
                if (!objIn.readBoolean()) {
                    logger.info("Found tampered request!");
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tampered request.");
                }
                logger.info("OK. Key {} registered successfully.", who);
                return (String) objIn.readObject(); //Nonce
            }
        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in register. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/{who}/obtainCoins")
    public ValidTransaction obtainAmount(@PathVariable String who, @RequestBody SignedBody<Double> signedBody) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createObtainCoinsRequest(who, signedBody), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD request");
            } else {
                ValidTransaction validTransaction = commitTransaction((SignedTransaction) objIn.readObject(), hash, quorumResponse);
                logger.info("OK. {} obtained {} coins.", who, validTransaction.getAmount());
                return validTransaction;
            }
        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainCoins. Cause: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/transferMoney")
    @ResponseStatus(HttpStatus.OK)
    public ValidTransaction transferAmount(@RequestBody SignedBody<Transaction> signedBody) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createTransferMoneyRequest(signedBody), ORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            } else {
                ValidTransaction validTransaction = commitTransaction((SignedTransaction) objIn.readObject(), hash, quorumResponse);
                logger.info("OK. {} transferred {} coins to {}.", validTransaction.getOrigin(), validTransaction.getAmount(), validTransaction.getDestination());
                return validTransaction;
            }
        } catch (IOException | InterruptedException | ExecutionException | ClassNotFoundException e) {
            logger.error("Exception in transferAmount. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/{who}/balance")
    public double currentAmount(@PathVariable String who) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createCurrentAmountRequest(who), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            objIn.readObject(); // Hash
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
            } else {
                double balance = objIn.readDouble();
                logger.info("OK. {} coins associated with key {}.", balance, who);
                return balance;
            }
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
            QuorumResponse quorumResponse = dispatchAsyncRequest(createGlobalLedgerRequest(dates), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            objIn.readObject(); // Hash
            List<Commit> global_ledger = (List<Commit>) objIn.readObject();
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
    public Ledger ledgerOfClientTransactions(@PathVariable String who, @RequestBody DateInterval dateInterval) {
        try {

            QuorumResponse quorumResponse = dispatchAsyncRequest(createClientLedgerRequest(who, dateInterval), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            objIn.readObject(); // Hash
            boolean result = objIn.readBoolean();
            List<Commit> client_ledger = (List<Commit>) objIn.readObject();
            if (!result) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request");
            } else {
                logger.info("OK. Found ledger with length {} associated to the key {}.", client_ledger.size(), who);
                return new Ledger(client_ledger);
            }
        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("IO exception in ledgerOfClientTransactions. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/verify/{id}")
    public ValidTransaction verify(@PathVariable String id) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createVerifyRequest(id), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean result = objIn.readBoolean();
            ValidTransaction t = (ValidTransaction) objIn.readObject();
            if (!result) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
            } else {
                logger.info("Transaction with id {} has been verified by replicas {}", id, t.getReplicas());
                return t;
            }

        } catch (IOException | ClassNotFoundException | InterruptedException | ExecutionException e) {
            logger.error("IO exception in verifyOp. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/lastBlock")
    public Block obtainLastMinedBlock() {
        return new Block();
    }

    @GetMapping("/pendingTransactions/{numPending}")
    public BlockHeader pickNotMineratedTransactions(@PathVariable int numPending) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createPickPendingTransactionsRequest(numPending), UNORDERED_REQUEST);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt();
            byte[] hash = (byte[]) objIn.readObject();
            boolean result = objIn.readBoolean();
            BlockHeader blockHeader = (BlockHeader) objIn.readObject();
            if (!result) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
            } else {
                logger.info("Obtained valid block header from a quorum of replicas");
                return blockHeader;
            }
        } catch (IOException | ExecutionException | InterruptedException | ClassNotFoundException e) {
            logger.error("Exception in obtainLastBlock. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{who}/mine")
    public String sendMinedBlock(@PathVariable String who, @RequestBody SignedBody<BlockHeader> signedBody) throws IOException, ExecutionException, InterruptedException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createSendMinedBlockRequest(signedBody, who), ORDERED_REQUEST);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt();
    }

    @PostMapping("/smartTransfer")
    @ResponseStatus(HttpStatus.OK)
    public void transferMoneyWithSmartContract(@RequestBody SignedBody<BlockHeader> signedBody) {

    }

    @PostMapping("/privacyTransfer")
    @ResponseStatus(HttpStatus.OK)
    public void transferMoneyWithPrivacy(@RequestBody SignedBody<BlockHeader> signedBody) {

    }

    @PostMapping("/{who}/installSmartContract")
    @ResponseStatus(HttpStatus.OK)
    public void installSmartContract(@PathVariable String who, @RequestBody SmartContract smartContract) {
    }


    @Override
    public void run(String... args) {
        this.logger = LoggerFactory.getLogger("LedgerClient");
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                logger.info("Launching client with uuid: {}", id);
                this.asynchServiceProxy = new AsynchServiceProxy(id);
                this.base32 = new Base32();
                this.gson = new Gson();
            } else logger.error("Usage: LedgerController <client ID>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int getQuorumSize() {
        return asynchServiceProxy.getViewManager().getCurrentViewN() - asynchServiceProxy.getViewManager().getCurrentViewF();
    }

    private QuorumResponse dispatchAsyncRequest(byte[] request, TOMMessageType messageType) throws IOException, ExecutionException, InterruptedException {
        CompletableFuture<QuorumResponse> reply = new CompletableFuture<>();
        int quorumSize = getQuorumSize();
        asynchServiceProxy.invokeAsynchRequest(request, new ReplyListenerImp<>(reply, quorumSize), messageType);
        return reply.get();
    }

    private QuorumResponse commit(Commit<?> op, LedgerRequestType requestType) throws IOException, ExecutionException, InterruptedException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(requestType);
        objOut.writeObject(op);
        objOut.flush();
        byteOut.flush();
        return dispatchAsyncRequest(byteOut.toByteArray(), ORDERED_REQUEST);
    }

    private ValidTransaction commitTransaction(SignedTransaction signedTransaction, byte[] hash, QuorumResponse quorumResponse) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        Commit<SignedTransaction> commit = new Commit<>(signedTransaction, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.COMMIT_TRANSACTION);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt();
        objIn.readObject(); //Hash
        if (!objIn.readBoolean()) {
            logger.info("Found tampered request!");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tampered request.");
        }
        return (ValidTransaction) objIn.readObject();
    }

    private byte[] createGetNonceRequest(String who, SignedBody<String> body) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.GET_NONCE);
        objOut.writeObject(who);
        objOut.writeObject(body.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createRegisterRequest(String key, RegisterKeyMsgBody body) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.REGISTER_KEY);
        objOut.writeObject(key);
        objOut.writeObject(body.getSignatureAlgorithm());
        objOut.writeObject(body.getPublicKeyAlgorithm());
        objOut.writeObject(body.getHashAlgorithm());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createObtainCoinsRequest(String who, SignedBody<Double> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
        objOut.writeObject(who);
        objOut.writeDouble(signedBody.getContent());
        objOut.writeObject(signedBody.getSignature());
        objOut.writeObject(signedBody.getDate());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createTransferMoneyRequest(SignedBody<Transaction> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.TRANSFER_MONEY);
        Transaction transaction = signedBody.getContent();
        objOut.writeObject(transaction);
        objOut.writeObject(signedBody.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createCurrentAmountRequest(String who) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.CURRENT_AMOUNT);
        objOut.writeObject(who);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createGlobalLedgerRequest(DateInterval dates) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.GLOBAL_LEDGER);
        objOut.writeObject(dates);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createClientLedgerRequest(String who, DateInterval dateInterval) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.CLIENT_LEDGER);
        objOut.writeObject(who);
        objOut.writeObject(dateInterval);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }


    private byte[] createVerifyRequest(String id) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.VERIFY);
        objOut.writeObject(id);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createPickPendingTransactionsRequest(int numPending) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.PICK_NOT_MINED_TRANSACTIONS);
        objOut.writeInt(numPending);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createSendMinedBlockRequest(SignedBody<BlockHeader> signedBody, String who) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.SEND_MINED_BLOCK);
        objOut.writeObject(who);
        System.out.println(gson.toJson(signedBody.getSignature()));
        BlockHeader blockHeader = signedBody.getContent();
        objOut.writeObject(blockHeader);
        objOut.writeObject(signedBody.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

}
