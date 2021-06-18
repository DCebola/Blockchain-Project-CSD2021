import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import bftsmart.tom.util.TOMUtil;
import com.enums.LedgerRequestType;
import com.enums.SmartContractEvent;
import com.google.gson.Gson;
import com.models.*;
import com.models.SmartContractTemplate;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

public class BFTSmartSandbox extends DefaultSingleRecoverable {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String ERROR_MSG = "ERROR";
    private static final String IGNORE_MSG = "IGNORE_MSG";

    private static final int KEY_ALGORITHM = 0;
    private static final int SIGNATURE_ALGORITHM = 1;
    private static final int HASH_ALGORITHM = 2;
    private static final int WALLET_NONCE = 3;
    private static final int TRANSACTION_ID_SIZE = 20;
    private static final String NORMAL_TRANSACTION_ID_PREFIX = "0xT";

    private static final String DUMMY_DESTINATION_1 = "DUMMY_DESTINATION_1";
    private static final String DUMMY_DESTINATION_2 = "DUMMY_DESTINATION_2";
    private static final String DUMMY_ORIGIN = "DUMMY_ORIGIN";
    private static final BigInteger DUMMY_AMOUNT = BigInteger.valueOf(100);


    private final Logger logger;
    private final Gson gson;
    private final Base32 base32;
    private final int id;
    private Map<String, List<String>> wallets;
    private List<Block> blockChain;
    private final int timeout;
    private final String smartContractClassName;

    public BFTSmartSandbox(int id) throws IOException {
        this.id = id;
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.gson = new Gson();
        this.base32 = new Base32();
        Properties properties = new Properties();
        properties.load(new FileInputStream("config/sandbox.config"));
        smartContractClassName = properties.getProperty("smartContractClassName");
        timeout = Integer.parseInt(properties.getProperty("timeout"));
        new ServiceReplica(id, this, this);

    }

    public static void main(String[] args) throws IOException {
        if (args.length == 1) {
            Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
            new BFTSmartSandbox(Integer.parseInt(args[0]));
        } else
            System.out.println("Usage: BFTSmartSandbox <server id>");
    }


    /****************************************++**** Ordered requests **************************************************/

    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            if ((objIn.readObject()).equals(LedgerRequestType.INSTALL_SMART_CONTRACT)) {
                this.wallets = (Map<String, List<String>>) objIn.readObject();
                this.blockChain = (List<Block>) objIn.readObject();
                testContract(objIn, objOut);
            } else {
                logger.info("Ignored operation.");
                writeReplicaDecision(objOut, IGNORE_MSG.getBytes(), false);
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException | ExecutionException | InterruptedException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }


    private void testContract(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, ExecutionException, InterruptedException {
        logger.debug("New TEST_CONTRACT operation.");
        String pubKey = (String) objIn.readObject();
        String date = (String) objIn.readObject();
        byte[] byteCode = base32.decode((String) objIn.readObject());
        byte[] sigBytes = (byte[]) objIn.readObject();
        List<String> wallet = wallets.get(pubKey);
        String msg = LedgerRequestType.INSTALL_SMART_CONTRACT.name().concat(gson.toJson(byteCode)).concat(wallet.get(WALLET_NONCE));
        if (wallet != null) {
            if (verifySignature(pubKey, msg, sigBytes)) {
                SmartContractLoader scLoader = new SmartContractLoader(byteCode, smartContractClassName);
                if (scLoader.loadSmartContract()) {
                    ISmartContract smartContract;
                    try {
                        smartContract = scLoader.getNewSmartContractInstance(pubKey, date, gson);
                        List<String> destinations = new ArrayList<>(2);
                        if (wallets.keySet().size() < 2) {
                            destinations.add(DUMMY_DESTINATION_1);
                            destinations.add(DUMMY_DESTINATION_2);
                        } else {
                            int i = 0;
                            for (String walletKey : wallets.keySet()) {
                                ++i;
                                destinations.add(walletKey);
                                if (i == 2)
                                    break;
                            }
                        }
                        safeExecuteContract(objOut, smartContract, pubKey, sigBytes, destinations);
                    } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
                        logger.info("Invalid smart contract. Error on instantiation.");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        writeReplicaDecision(objOut, hash, false);
                    }
                }
            } else {
                logger.info("Invalid signature");
                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                writeReplicaDecision(objOut, hash, false);
            }
        } else {
            logger.info("Key {} does not exist", pubKey);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
            writeReplicaDecision(objOut, hash, false);
        }
    }

    private void safeExecuteContract(ObjectOutput objOut, ISmartContract smartContract, String pubKey, byte[] sigBytes, List<String> destinations) throws ExecutionException, InterruptedException, IOException {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
        Future<List<Transaction>> future = executor.submit(new sandboxThread(smartContract, DUMMY_ORIGIN, DUMMY_AMOUNT, destinations));
        final boolean[] timedOut = {false};
        executor.schedule(() -> {
            if (future.cancel(true)) {
                timedOut[0] = true;
            }
        }, timeout, TimeUnit.MILLISECONDS);
        if (!timedOut[0]) {
            if (smartContract.getAuthor().equals(pubKey)) {
                if (checkContractOutput(future.get(), smartContract.getOutputNumber(), destinations)) {
                    logger.info("Valid smart contract.");
                    smartContract.setSignature(base32.encodeAsString(sigBytes));
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(smartContract)).getBytes());
                    writeReplicaDecision(objOut, hash, true);
                    objOut.writeObject(smartContract);
                } else {
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                    writeReplicaDecision(objOut, hash, false);
                }
            } else {
                logger.info("Mismatched author.");
                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                writeReplicaDecision(objOut, hash, false);
            }
        } else {
            logger.info("Timeout.");
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
            writeReplicaDecision(objOut, hash, false);
        }
    }

    private boolean checkContractOutput(List<Transaction> output, int expectedSize, List<String> destinations) {
        if (output.size() != expectedSize) {
            logger.info("Wrong output size.");
            return false;
        }
        BigInteger producedAmount = BigInteger.ZERO;
        Transaction t = output.get(0);
        if (!t.getOrigin().equals(DUMMY_ORIGIN) || !t.getDestination().equals(destinations.get(0))) {
            logger.info("Wrong transaction.");
            return false;
        }
        producedAmount = producedAmount.add(t.getAmount());
        t = output.get(1);
        if (!t.getOrigin().equals(DUMMY_ORIGIN) || !t.getDestination().equals(destinations.get(1))) {
            logger.info("Wrong transaction.");
            return false;
        }
        producedAmount = producedAmount.add(t.getAmount());
        if (!producedAmount.equals(DUMMY_AMOUNT)) {
            logger.info("Manipulation of amount.");
            return false;
        }
        return true;
    }

    /******************************************** Unordered requests **************************************************/

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            logger.info("Ignored operation.");
            writeReplicaDecision(objOut, IGNORE_MSG.getBytes(), false);
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    /************************************************ Auxiliary methods ***********************************************/

    private boolean verifySignature(String publicKey, String msg, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        List<String> walletData = wallets.get(publicKey);
        Signature sign = Signature.getInstance(walletData.get(SIGNATURE_ALGORITHM));
        sign.initVerify(KeyFactory.getInstance(walletData.get(KEY_ALGORITHM)).generatePublic(new X509EncodedKeySpec(base32.decode(publicKey))));
        sign.update(generateHash(msg.getBytes(), walletData.get(HASH_ALGORITHM)));
        return sign.verify(signature);
    }

    private byte[] generateHash(byte[] msg, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(msg);
        return hash.digest();
    }


    private BigInteger getPublicBalance(String walletKey) {
        BigInteger balance = BigInteger.ZERO;
        if (!wallets.containsKey(walletKey)) {
            return BigInteger.valueOf(-1);
        }
        for (Block block : blockChain) {
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction t : validTransactions) {
                if (t.getWhoEncrypted() == null) {
                    if (t.getOrigin().equals(walletKey))
                        balance = balance.subtract(t.getAmount());
                    else if (t.getDestination().equals(walletKey))
                        balance = balance.add(t.getAmount());
                }
            }
        }
        return balance;
    }

    private List<ValidTransaction> getLedger(String walletKey) {
        List<ValidTransaction> ledger = new LinkedList<>();
        for (Block block : blockChain) {
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction transaction : validTransactions) {
                if (transaction.getOrigin().equals(walletKey) || transaction.getDestination().equals(walletKey))
                    ledger.add(transaction);
            }
        }
        return ledger;
    }

    private ValidTransaction findTransaction(String id) {
        for (Block block : blockChain) {
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction transaction : validTransactions) {
                if (transaction.getId().equals(id))
                    return transaction;
            }
        }
        return null;
    }

    /************************************************ Auxiliary Response methods **************************************/

    private void writeReplicaDecision(ObjectOutput objOut, byte[] hash, boolean decision) throws IOException {
        objOut.writeInt(id);
        objOut.writeObject(hash);
        objOut.writeBoolean(decision);
    }

    /************************************************* Snapshot methods ***********************************************/

    @Override
    public void installSnapshot(byte[] bytes) {
    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }

    /************************************************* Execution thread ***********************************************/

    private class sandboxThread implements Callable<List<Transaction>> {
        private final ISmartContract sc;
        private final String origin;
        private final BigInteger amount;
        private final List<String> destinations;

        public sandboxThread(ISmartContract sc, String origin, BigInteger amount, List<String> destinations) {
            this.sc = sc;
            this.origin = origin;
            this.amount = amount;
            this.destinations = destinations;
        }

        @Override
        public List<Transaction> call() {
            SmartContractEvent nextEvent = sc.init(origin, amount, destinations);
            while (nextEvent != SmartContractEvent.STOP) {
                nextEvent = sc.run();
                switch (nextEvent) {
                    case READ_TRANSACTION:
                        sc.readTransaction(gson.toJson(findTransaction(sc.getReadTarget())));
                        break;
                    case READ_CLIENT_LEDGER:
                        sc.readBalance(gson.toJson(getLedger(sc.getReadTarget())));
                        break;
                    case READ_BALANCE:
                        sc.readLedger(gson.toJson(getPublicBalance(sc.getReadTarget())));
                        break;
                }
            }
            return sc.getOutput();
        }
    }
}