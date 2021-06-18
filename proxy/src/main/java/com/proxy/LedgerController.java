package com.proxy;

import bftsmart.tom.AsynchServiceProxy;
import bftsmart.tom.core.messages.TOMMessageType;
import com.enums.LedgerRequestType;
import com.enums.SmartContractEvent;
import com.google.gson.Gson;
import com.models.*;
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
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.*;

@RestController
public class LedgerController implements CommandLineRunner {

    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";
    private static final String SANDBOX_TYPE = "SANDBOX";
    private static final String REPLICA_TYPE = "REPLICA";

    private AsynchServiceProxy asynchServiceProxy;
    private Logger logger;
    private Base32 base32;
    private Gson gson;
    private int numReplicas;


    @PostMapping("/nonce/{who}")
    public String getNonce(@PathVariable String who, @RequestBody SignedBody<String> body) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createGetNonceRequest(who, body), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
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
            QuorumResponse quorumResponse = dispatchAsyncRequest(createRegisterRequest(who, body), ORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
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
    public ValidTransaction obtainAmount(@PathVariable String who, @RequestBody SignedBody<BigInteger> signedBody) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createObtainCoinsRequest(who, signedBody), ORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
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

    @PostMapping("/privacyTransfer")
    @ResponseStatus(HttpStatus.OK)
    public ValidTransaction transferMoneyWithPrivacy(@RequestBody SignedBody<TransactionPlusSecretValue> signedBody) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createTransferMoneyWithPrivacyRequest(signedBody), ORDERED_REQUEST, REPLICA_TYPE);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        byte[] hash = (byte[]) objIn.readObject();
        if (!objIn.readBoolean()) {
            logger.info("BAD REQUEST");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        } else {
            SignedTransaction signedTransaction = (SignedTransaction) objIn.readObject();
            String secretValue = (String) objIn.readObject();
            TransactionPlusSecretValue transactionPlusSecretValue = new TransactionPlusSecretValue(signedTransaction, secretValue);
            ValidTransaction validTransaction = commitPrivateTransaction(transactionPlusSecretValue, hash, quorumResponse);
            logger.info("OK. {} transferred {} coins to {}.", validTransaction.getOrigin(), validTransaction.getEncryptedAmount(), validTransaction.getDestination());
            return validTransaction;
        }
    }


    @PostMapping("/transferMoney")
    @ResponseStatus(HttpStatus.OK)
    public ValidTransaction transferAmount(@RequestBody SignedBody<Transaction> signedBody) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createTransferMoneyRequest(signedBody), ORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
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

    @GetMapping("/{who}/obtainNotSubmittedTransactions")
    public TransactionsForSubmissionInfo obtainNotSubmittedTransactions(@PathVariable String who) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createObtainNotSubmittedTransactionsRequest(who), UNORDERED_REQUEST, REPLICA_TYPE);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        objIn.readObject(); //hash
        if (!objIn.readBoolean()) {
            logger.info("BAD REQUEST");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
        } else
            return (TransactionsForSubmissionInfo) objIn.readObject();
    }


    @GetMapping("/{who}/balance")
    public String currentAmount(@PathVariable String who) {
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(createCurrentAmountRequest(who), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); // Hash
            if (!objIn.readBoolean()) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
            } else {
                String balance = (String) objIn.readObject();
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
            QuorumResponse quorumResponse = dispatchAsyncRequest(createGlobalLedgerRequest(dates), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); // Hash
            List<ValidTransaction> global_ledger = (List<ValidTransaction>) objIn.readObject();
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

            QuorumResponse quorumResponse = dispatchAsyncRequest(createClientLedgerRequest(who, dateInterval), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); // Hash
            boolean result = objIn.readBoolean();
            List<ValidTransaction> client_ledger = (List<ValidTransaction>) objIn.readObject();
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
            QuorumResponse quorumResponse = dispatchAsyncRequest(createVerifyRequest(id), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); //Hash
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
        try {
            QuorumResponse quorumResponse = dispatchAsyncRequest(obtainLastBlockRequest(), UNORDERED_REQUEST, REPLICA_TYPE);
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); //Hash
            boolean result = objIn.readBoolean();
            Block block = (Block) objIn.readObject();
            if (!result) {
                logger.info("BAD REQUEST");
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
            } else {
                logger.info("Obtained valid block from a quorum of replicas");
                return block;
            }
        } catch (InterruptedException | ExecutionException | IOException | ClassNotFoundException e) {
            logger.error("Exception in obtainLastBlock. Cause: {}", e.getMessage());
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/pendingTransactions/{numPending}")
    public BlockHeader pickNotMineratedTransactions(@PathVariable int numPending) {
        try {
            logger.info("hello");
            QuorumResponse quorumResponse = dispatchAsyncRequest(createPickPendingTransactionsRequest(numPending), UNORDERED_REQUEST, REPLICA_TYPE);
            logger.info("goodbye");
            ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
            objIn.readInt(); //ID
            objIn.readObject(); // Hash
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

    @PostMapping("/mine")
    public ValidTransaction sendMinedBlock(@RequestBody SignedBody<BlockHeaderAndReward> signedBody) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createSendMinedBlockRequest(signedBody), ORDERED_REQUEST, REPLICA_TYPE);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        byte[] hash = (byte[]) objIn.readObject();
        if (!objIn.readBoolean()) {
            logger.info("BAD REQUEST");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
        } else {
            BlockAndReward blockAndReward = (BlockAndReward) objIn.readObject();
            ValidTransaction reward = commitBlock(blockAndReward, hash, quorumResponse);
            logger.info("OK. Adding block to blockchain");
            return reward;
        }
    }

    @PostMapping("/smartTransfer/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Ledger transferMoneyWithSmartContract(@PathVariable String id, @RequestBody SignedBody<SmartContractArgs> signedBody) throws IOException, ClassNotFoundException, ExecutionException, InterruptedException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createTransferMoneyWithSmartContractRequest(id, signedBody), UNORDERED_REQUEST, REPLICA_TYPE);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        byte[] hash = (byte[]) objIn.readObject();
        if (!objIn.readBoolean()) {
            logger.info("BAD REQUEST");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
        } else {
            List<SignedTransaction> scOutput = (List<SignedTransaction>) objIn.readObject();
            Ledger validTransactions = commitSmartContractOutput(scOutput, hash, quorumResponse);
            logger.info("OK. Executed smart contract transaction. {}", validTransactions);
            return validTransactions;
        }
    }


    @PostMapping("/{who}/installSmartContract")
    @ResponseStatus(HttpStatus.OK)
    public String installSmartContract(@PathVariable String who, @RequestBody SignedBody<String> signedBody) throws IOException, ClassNotFoundException, ExecutionException, InterruptedException {
        QuorumResponse quorumResponse = dispatchAsyncRequest(createGetSystemSnapshotRequest(), UNORDERED_REQUEST, REPLICA_TYPE);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        objIn.readObject(); //Hash
        objIn.readBoolean(); //Decision
        Map<String, List<String>> wallets = (Map<String, List<String>>) objIn.readObject();
        logger.info("{}", wallets);
        List<Block> blockChain = (List<Block>) objIn.readObject();
        logger.info("{}", blockChain);

        quorumResponse = dispatchAsyncRequest(createValidateSmartContractRequest(who, signedBody, wallets, blockChain), ORDERED_REQUEST, SANDBOX_TYPE);
        objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        byte[] hash = (byte[]) objIn.readObject();
        if (!objIn.readBoolean()) {
            logger.info("BAD REQUEST");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "BAD REQUEST");
        } else {
            String encodedByteCode = (String) objIn.readObject();
            String id = commitSmartContract(encodedByteCode, hash, quorumResponse);
            logger.info("OK. Installing smart contract.");
            return id;
        }
    }


    @Override
    public void run(String... args) {
        this.logger = LoggerFactory.getLogger("LedgerClient");
        try {
            if (args.length == 1) {
                int id = Integer.parseInt(args[0]);
                logger.info("Launching client with uuid: {}", id);
                this.asynchServiceProxy = new AsynchServiceProxy(id);
                this.numReplicas = asynchServiceProxy.getViewManager().getCurrentViewProcesses().length / 2;
                this.base32 = new Base32();
                this.gson = new Gson();
                //TODO: Generate genesis block
            } else logger.error("Usage: LedgerController <client ID>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int getQuorumSize(int n) {
        return n - asynchServiceProxy.getViewManager().getCurrentViewF();
    }

    private QuorumResponse dispatchAsyncRequest(byte[] request, TOMMessageType messageType, String target) throws IOException, ExecutionException, InterruptedException {
        CompletableFuture<QuorumResponse> reply = new CompletableFuture<>();
        int[] targets;
        if (target.equals(REPLICA_TYPE))
            targets = getAvailableReplicas();
        else
            targets = getAvailableSandboxes();
        System.out.println(Arrays.toString(targets));
        System.out.println(getQuorumSize(targets.length));
        asynchServiceProxy.invokeAsynchRequest(request, targets, new ReplyListenerImp<>(reply, getQuorumSize(targets.length), targets), messageType);
        return reply.get();
    }

    private int[] getAvailableSandboxes() {
        List<Integer> sandboxes = new LinkedList<>();
        for (int id : asynchServiceProxy.getViewManager().getCurrentViewProcesses()) {
            if (id >= numReplicas)
                sandboxes.add(id);
        }
        System.out.println(Arrays.toString(sandboxes.toArray()));
        int[] found = new int[sandboxes.size()];
        for (int i = 0; i < sandboxes.size(); i++)
            found[i] = sandboxes.get(i);
        System.out.println(Arrays.toString(found));
        return found;
    }

    private int[] getAvailableReplicas() {
        List<Integer> replicas = new LinkedList<>();
        for (int id : asynchServiceProxy.getViewManager().getCurrentViewProcesses()) {
            if (id < numReplicas)
                replicas.add(id);
        }
        int[] found = new int[replicas.size()];
        for (int i = 0; i < replicas.size(); i++)
            found[i] = replicas.get(i);
        return found;
    }

    private QuorumResponse commit(Commit<?> op, LedgerRequestType requestType) throws IOException, ExecutionException, InterruptedException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(requestType);
        objOut.writeObject(op);
        objOut.flush();
        byteOut.flush();
        return dispatchAsyncRequest(byteOut.toByteArray(), ORDERED_REQUEST, REPLICA_TYPE);
    }


    private ValidTransaction commitTransaction(SignedTransaction signedTransaction, byte[] hash, QuorumResponse quorumResponse) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        Commit<SignedTransaction> commit = new Commit<>(signedTransaction, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.COMMIT_TRANSACTION);
        return getCommitResponse(quorumResponse);
    }

    private ValidTransaction commitPrivateTransaction(TransactionPlusSecretValue transactionPlusSecretValue, byte[] hash, QuorumResponse quorumResponse) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        Commit<TransactionPlusSecretValue> commit = new Commit<>(transactionPlusSecretValue, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.COMMIT_TRANSFER_WITH_PRIVACY);
        return getCommitResponse(quorumResponse);
    }

    private ValidTransaction commitBlock(BlockAndReward blockAndReward, byte[] hash, QuorumResponse quorumResponse) throws InterruptedException, ExecutionException, IOException, ClassNotFoundException {
        Commit<BlockAndReward> commit = new Commit<>(blockAndReward, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.COMMIT_BLOCK);
        return getCommitResponse(quorumResponse);
    }

    private String commitSmartContract(String encodedByteCode, byte[] hash, QuorumResponse quorumResponse) throws InterruptedException, ExecutionException, IOException, ClassNotFoundException {
        Commit<String> commit = new Commit<>(encodedByteCode, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.INSTALL_SMART_CONTRACT);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        objIn.readObject(); //Hash
        if (!objIn.readBoolean()) {
            logger.info("Found tampered request!");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tampered request.");
        }
        return (String) objIn.readObject();
    }


    private Ledger commitSmartContractOutput(List<SignedTransaction> scOutput, byte[] hash, QuorumResponse quorumResponse) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
        Commit<List<SignedTransaction>> commit = new Commit<>(scOutput, base32.encodeAsString(hash), quorumResponse.getReplicas());
        quorumResponse = commit(commit, LedgerRequestType.SMART_TRANSFER);
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
        objIn.readObject(); //Hash
        if (!objIn.readBoolean()) {
            logger.info("Found tampered request!");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tampered request.");
        }
        return (Ledger) objIn.readObject();
    }

    private ValidTransaction getCommitResponse(QuorumResponse quorumResponse) throws IOException, ClassNotFoundException {
        ObjectInput objIn = new ObjectInputStream(new ByteArrayInputStream(quorumResponse.getResponse()));
        objIn.readInt(); //ID
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
        objOut.writeObject(body.getEncryptedZero());
        objOut.writeObject(body.getPkNSquare());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createObtainCoinsRequest(String who, SignedBody<BigInteger> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
        objOut.writeObject(who);
        objOut.writeObject(signedBody.getContent());
        objOut.writeObject(signedBody.getSignature());
        objOut.writeObject(signedBody.getDate());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createTransferMoneyWithPrivacyRequest(SignedBody<TransactionPlusSecretValue> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objectOutput = new ObjectOutputStream(byteOut);
        objectOutput.writeObject(LedgerRequestType.TRANSFER_MONEY_WITH_PRIVACY);
        TransactionPlusSecretValue transactionPlusSecretValue = signedBody.getContent();
        Transaction transaction = transactionPlusSecretValue.getTransaction();
        String secretValue = transactionPlusSecretValue.getSecretValue();
        objectOutput.writeObject(transaction);
        objectOutput.writeObject(secretValue);
        objectOutput.writeObject(signedBody.getSignature());
        objectOutput.flush();
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

    private byte[] createObtainNotSubmittedTransactionsRequest(String who) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.OBTAIN_USER_NOT_SUBMITTED_TRANSACTIONS);
        objOut.writeObject(who);
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

    private byte[] obtainLastBlockRequest() throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.OBTAIN_LAST_BLOCK);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createSendMinedBlockRequest(SignedBody<BlockHeaderAndReward> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.SEND_MINED_BLOCK);
        BlockHeaderAndReward blockHeaderAndReward = signedBody.getContent();
        logger.info("{}", gson.toJson(signedBody.getContent()));
        objOut.writeObject(blockHeaderAndReward);
        objOut.writeObject(signedBody.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }


    private byte[] createGetSystemSnapshotRequest() throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.GET_SYSTEM_SNAPSHOT);
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }


    private byte[] createValidateSmartContractRequest(String who, SignedBody<String> signedBody, Map<String, List<String>> wallets, List<Block> blockchain) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.VALIDATE_SMART_CONTRACT);
        objOut.writeObject(wallets);
        objOut.writeObject(blockchain);
        objOut.writeObject(who);
        objOut.writeObject(signedBody.getDate());
        objOut.writeObject(signedBody.getContent());
        objOut.writeObject(signedBody.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();
    }

    private byte[] createTransferMoneyWithSmartContractRequest(String id, SignedBody<SmartContractArgs> signedBody) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutput objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(LedgerRequestType.SMART_TRANSFER);
        logger.info("{}", gson.toJson(signedBody.getContent()));
        SmartContractArgs scArgs = signedBody.getContent();
        objOut.writeObject(id);
        objOut.writeObject(scArgs.getOrigin());
        objOut.writeObject(scArgs.getAmount());
        objOut.writeObject(scArgs.getDestinations());
        objOut.writeObject(signedBody.getSignature());
        objOut.flush();
        byteOut.flush();
        return byteOut.toByteArray();

    }

}
