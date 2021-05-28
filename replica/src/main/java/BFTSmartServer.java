import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import bftsmart.tom.util.TOMUtil;
import com.google.gson.Gson;
import com.proxy.controllers.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;


import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.sql.Timestamp;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class BFTSmartServer extends DefaultSingleRecoverable {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";

    private static final String INITIAL_NONCE = "0";
    private static final String NO_NONCE = "-1";

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private static final String GLOBAL_LEDGER = "GLOBAL-LEDGER";
    private static final String USER_ACCOUNT = "-ACCOUNT";
    private static final String USER_LEDGER = "-LEDGER";

    private static final int KEY_ALGORITHM = 0;
    private static final int SIGNATURE_ALGORITHM = 1;
    private static final int HASH_ALGORITHM = 2;
    private static final int WALLET_NONCE = 3;

    private final Logger logger;
    private final Jedis jedis;
    private final Gson gson;
    private final Base64 base64;
    private final int id;


    public BFTSmartServer(int id) throws IOException {
        this.id = id;
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.base64 = new Base64(true);
        this.gson = new Gson();
        Properties jedis_properties = new Properties();
        //TODO: tls with redis
        //TODO: Refactoring of methods
        jedis_properties.load(new FileInputStream("config/redis.config"));
        String redisPort = jedis_properties.getProperty("redis_port");
        String redis_ip = "172.18.30.".concat(Integer.toString(id));
        jedis = new Jedis("redis://".concat(redis_ip).concat(":").concat(redisPort));
        new ServiceReplica(id, this, this);

    }

    public static void main(String[] args) throws IOException {
        if (args.length == 1) {
            Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
            new BFTSmartServer(Integer.parseInt(args[0]));
        } else
            System.out.println("Usage: BFTSmartServer <server id>");
    }

    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case REGISTER_KEY: {
                    logger.debug("New REGISTER_KEY operation.");
                    String publicKey = (String) objIn.readObject();
                    String signatureAlgorithm = (String) objIn.readObject();
                    String publicKeyAlgorithm = (String) objIn.readObject();
                    String hashAlgorithm = (String) objIn.readObject();
                    byte[] hashResult;
                    if (jedis.exists(publicKey)) {
                        logger.info("Key {} already registered", publicKey);
                        hashResult = TOMUtil.computeHash(
                                Boolean.toString(false)
                                        .concat(publicKey)
                                        .concat(signatureAlgorithm)
                                        .concat(publicKeyAlgorithm)
                                        .concat(hashAlgorithm)
                                        .getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    } else {
                        hashResult = TOMUtil.computeHash(
                                Boolean.toString(true)
                                        .concat(publicKey)
                                        .concat(signatureAlgorithm)
                                        .concat(publicKeyAlgorithm)
                                        .concat(hashAlgorithm)
                                        .getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(true);
                        objOut.writeObject(new Wallet(publicKey, publicKeyAlgorithm, signatureAlgorithm, hashAlgorithm));
                    }
                }
                break;
                case OBTAIN_COINS: {
                    logger.debug("New OBTAIN_COINS operation.");
                    String publicKey = (String) objIn.readObject();

                    if (!jedis.exists(publicKey)) {
                        logger.info("Key {} does not exist", publicKey);
                        objOut.writeBoolean(false);
                    } else {
                        double amount = objIn.readDouble();
                        String date = (String) objIn.readObject();
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                        String msg = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount).concat(nonce).concat(date));
                        byte[] hash;
                        if (verifySignature(publicKey, msg, msgSignature) && amount > 0) {
                            nonce = Integer.toString(Integer.parseInt(nonce) + 1);
                            jedis.lset(publicKey, WALLET_NONCE, nonce);
                            logger.info("Signature verified successfully");
                            hash = TOMUtil.computeHash(Boolean.toString(true).concat(Double.toString(amount)).concat(date).getBytes());
                            SignedTransaction signedTransaction = new SignedTransaction(SYSTEM, publicKey, amount, base64.encodeAsString(msgSignature), date);
                            objOut.writeInt(id);
                            objOut.writeObject(hash);
                            objOut.writeBoolean(true);
                            objOut.writeObject(signedTransaction);
                            objOut.writeDouble(amount);
                            objOut.writeObject(date);
                        } else {
                            hash = TOMUtil.computeHash(Boolean.toString(false).concat(Double.toString(-1)).getBytes());
                            objOut.writeInt(id);
                            objOut.writeObject(hash);
                            objOut.writeBoolean(false);
                            objOut.writeObject(null);
                            objOut.writeDouble(-1);
                            objOut.writeObject(null);
                        }
                    }
                }
                break;
                case TRANSFER_MONEY: {
                    logger.debug("New TRANSFER_MONEY operation.");
                    Transaction transaction = (Transaction) objIn.readObject();
                    String origin = transaction.getOrigin();
                    String destination = transaction.getDestination();
                    double amount = transaction.getAmount();
                    String date = transaction.getDate();
                    byte[] hash;
                    if (!jedis.exists(origin) || !jedis.exists(destination)
                            || origin.equals(destination)) {
                        logger.info("Bad transaction ({}, {}, {})", origin, destination, amount);
                        hash = TOMUtil.computeHash(Boolean.toString(false).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                        logger.info("Invalid Signature");
                    } else {
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String nonce = jedis.lindex(origin, WALLET_NONCE);
                        String msg = gson.toJson(LedgerRequestType.TRANSFER_MONEY.name()).concat(gson.toJson(transaction).concat(nonce).concat(date));
                        if (amount > 0 && verifySignature(origin, msg, msgSignature)) {
                            logger.info("Signature verified successfully.");
                            if (getBalance(origin) >= amount) {
                                nonce = Integer.toString(Integer.parseInt(nonce) + 1);
                                jedis.lset(origin, WALLET_NONCE, nonce);
                                hash = TOMUtil.computeHash(Boolean.toString(true).getBytes());
                                SignedTransaction signedTransaction = new SignedTransaction(origin, destination, amount, base64.encodeAsString(msgSignature), date);
                                logger.info("Proposed transaction ({}, {}, {}).", origin, destination, amount);
                                objOut.writeInt(id);
                                objOut.writeObject(hash);
                                objOut.writeBoolean(true);
                                objOut.writeObject(signedTransaction);

                            } else {
                                hash = TOMUtil.computeHash(Boolean.toString(false).getBytes());
                                objOut.writeInt(id);
                                objOut.writeObject(hash);
                                objOut.writeBoolean(false);
                                objOut.writeObject(null);
                                logger.info("Invalid Signature");
                            }
                        } else {
                            hash = TOMUtil.computeHash(Boolean.toString(true).getBytes());
                            objOut.writeInt(id);
                            objOut.writeObject(hash);
                            objOut.writeBoolean(false);
                            objOut.writeObject(null);
                            logger.info("Invalid Signature");
                        }
                    }
                    break;
                }
                case COMMIT_TRANSACTION: {
                    Commit commit = (Commit) objIn.readObject();
                    SignedTransaction t = (SignedTransaction) commit.getRequest();
                    String origin = t.getOrigin();
                    String destination = t.getDestination();
                    double amount = t.getAmount();
                    ValidTransaction transaction = new ValidTransaction(
                            origin,
                            destination,
                            amount,
                            t.getSignature(),
                            t.getDate(),
                            commit.getHash(),
                            commit.getReplicas(),
                            base64.encodeAsString(TOMUtil.computeHash(base64.decode(t.getSignature()))));

                    jedis.rpush(GLOBAL_LEDGER, gson.toJson(transaction));
                    logger.info("Transaction ({}, {}, {}) added to global ledger.", origin, destination, amount);
                }
                break;
                case COMMIT_WALLET: {
                    Commit commit = (Commit) objIn.readObject();
                    Wallet wallet = (Wallet) commit.getRequest();
                    String publicKey = wallet.getPublicKey();
                    String publicKeyAlgorithm = wallet.getPublicKeyAlgorithm();
                    String signatureAlgorithm = wallet.getSignatureAlgorithm();
                    String hashAlgorithm = wallet.getHashAlgorithm();
                    jedis.rpush(publicKey, publicKeyAlgorithm);
                    jedis.rpush(publicKey, signatureAlgorithm);
                    jedis.rpush(publicKey, hashAlgorithm);
                    jedis.rpush(publicKey, INITIAL_NONCE);
                    logger.debug("Registered key {} with hash algorithm {}, signature {} and nonce {}", publicKey, publicKeyAlgorithm, signatureAlgorithm, INITIAL_NONCE);
                    logger.info("Registered key {}", publicKey);
                }
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case GET_NONCE: {
                    logger.debug("New REQUEST_NONCE operation");
                    String publicKey = (String) objIn.readObject();
                    String message = gson.toJson(LedgerRequestType.GET_NONCE.name().concat(publicKey));
                    byte[] msgSignature = (byte[]) objIn.readObject();
                    if (verifySignature(publicKey, message, msgSignature)) {
                        logger.info("Signature verified");
                        String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                        byte[] hashResult = TOMUtil.computeHash(Boolean.toString(true).concat(nonce).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(true);
                        objOut.writeObject(nonce);
                    } else {
                        logger.info("Signature not verified");
                        byte[] hashResult = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NONCE).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(false);
                        objOut.writeObject(NO_NONCE);
                    }

                }
                break;
                case CURRENT_AMOUNT: {
                    logger.debug("New CURRENT_AMOUNT operation.");
                    String publicKey = (String) objIn.readObject();
                    if (!jedis.exists(publicKey)) {
                        logger.info("Key {} not registered.", publicKey);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(Double.toString(-1)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeDouble(-1);
                    } else {
                        double balance = getBalance(publicKey);
                        logger.info("{} coins associated with key {}.", publicKey, balance);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(Double.toString(balance)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeDouble(balance);
                    }
                    break;
                }
                case GLOBAL_LEDGER: {
                    DateInterval dateInterval = (DateInterval) objIn.readObject();
                    logger.debug("New GLOBAL_LEDGER operation.");
                    objOut.writeInt(id);
                    List<ValidTransaction> signedTransactions = getLedger(dateInterval);
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(signedTransactions)).getBytes());
                    objOut.writeObject(hash);
                    objOut.writeObject(signedTransactions);
                    break;
                }
                case CLIENT_LEDGER: {
                    logger.debug("New CLIENT_LEDGER operation.");
                    String publicKey = (String) objIn.readObject();
                    DateInterval dateInterval = (DateInterval) objIn.readObject();
                    if (!jedis.exists(publicKey)) {
                        logger.info("Key {} not registered.", publicKey);
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    } else {
                        List<ValidTransaction> client_ledger = getLedger(publicKey, dateInterval);
                        logger.info("Found ledger with length {} associated with key {}.", client_ledger.size(), client_ledger);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(client_ledger)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(client_ledger);
                    }
                    break;
                }
                case VERIFY_OP: {
                    //TODO: Use ID for verification
                    logger.debug("New VERIFY_OP operation.");
                    String op = (String) objIn.readObject();
                    List<String> ops = jedis.lrange(GLOBAL_LEDGER, 0, -1);
                    SignedTransaction signedTransaction = null;
                    for (String opS : ops) {
                        if (op.equals(opS)) {
                            logger.info("Transaction found");
                            signedTransaction = (SignedTransaction) gson.fromJson(opS, Commit.class).getRequest();
                            objOut.writeInt(id);
                            byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(signedTransaction)).getBytes());
                            objOut.writeObject(hash);
                            objOut.writeBoolean(true);
                            objOut.writeObject(signedTransaction);
                            break;
                        }
                    }
                    if (signedTransaction == null) {
                        logger.info("Transaction not found!!!");
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    }
                }
                break;
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private boolean verifySignature(String publicKey, String msg, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        List<String> walletData = jedis.lrange(publicKey, 0, -1);
        Signature sign = Signature.getInstance(walletData.get(SIGNATURE_ALGORITHM));
        sign.initVerify(KeyFactory.getInstance(walletData.get(KEY_ALGORITHM)).
                generatePublic(new X509EncodedKeySpec(base64.decode(publicKey))));
        sign.update(generateHash(msg.getBytes(), walletData.get(HASH_ALGORITHM)));
        return sign.verify(signature);
    }

    private byte[] generateHash(byte[] msg, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(msg);
        return hash.digest();
    }

    private List<ValidTransaction> getLedger(DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserialized_ledger = new LinkedList<>();
        List<String> serialized_ledger = jedis.lrange(GLOBAL_LEDGER, 0, -1);

        for (String t : serialized_ledger) {
            ValidTransaction transaction = gson.fromJson(t, ValidTransaction.class);
            long transactionTimeStamp = Timestamp.valueOf(transaction.getDate()).getTime();

            if (transactionTimeStamp >= startDate && transactionTimeStamp <= endDate) {
                deserialized_ledger.add(transaction);
            }
        }
        return deserialized_ledger;
    }

    private List<ValidTransaction> getLedger(String publicKey, DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserialized_ledger = new LinkedList<>();
        List<String> serialized_ledger = jedis.lrange(GLOBAL_LEDGER, 0, -1);

        for (String t : serialized_ledger) {
            ValidTransaction transaction = gson.fromJson(t, ValidTransaction.class);
            if (transaction.getOrigin().equals(publicKey)) {
                long transactionTimeStamp = Timestamp.valueOf(transaction.getDate()).getTime();
                if (transactionTimeStamp >= startDate && transactionTimeStamp <= endDate) {
                    deserialized_ledger.add(transaction);
                }
            }
        }
        return deserialized_ledger;
    }


    private double getBalance(String publicKey) {
        double balance = 0;
        if (!jedis.exists(publicKey))
            return -1;
        List<String> ledger = jedis.lrange(GLOBAL_LEDGER, 0, -1);
        for (String json_t : ledger) {
            SignedTransaction t = (SignedTransaction) gson.fromJson(json_t, Commit.class).getRequest();
            if (t.getOrigin().equals(publicKey))
                balance -= t.getAmount();
            else if (t.getDestination().equals(publicKey))
                balance += t.getAmount();
        }
        return balance;
    }

    @Override
    public void installSnapshot(byte[] bytes) {

    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
