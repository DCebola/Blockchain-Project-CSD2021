import bftsmart.reconfiguration.util.TOMConfiguration;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.core.TOMSender;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import bftsmart.tom.util.TOMUtil;
import com.google.gson.Gson;
import com.proxy.controllers.LedgerRequestType;
import com.proxy.controllers.SignedTransaction;
import com.proxy.controllers.Transaction;
import com.proxy.controllers.Utils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;


import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class BFTSmartServer extends DefaultSingleRecoverable {

    private static final String INITIAL_NONCE = "0";
    private static final String NO_NOUNCE = "-1";

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private static final String GLOBAL_LEDGER = "GLOBAL-LEDGER";
    private static final String USER_ACCOUNT = "-ACCOUNT";
    private static final String USER_LEDGER = "-LEDGER";

    private static final int USER_KEY = 0;
    private static final int USER_SIGNATURE_ALGORITHM = 1;
    private static final int USER_KEY_ALGORITHM = 2;
    private static final int USER_HASH_ALGORITHM = 3;

    private final Logger logger;
    private final Jedis jedis;
    private final Gson gson;
    private final Base64 base64;


    public BFTSmartServer(int id) throws IOException {
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.base64 = new Base64();
        this.gson = new Gson();
        Properties jedis_properties = new Properties();
        jedis_properties.load(new FileInputStream("config/jedis.config"));
        String redisPort = jedis_properties.getProperty("jedis_port").split(",")[id];
        jedis = new Jedis("redis://127.0.0.1:".concat(redisPort));
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
                case LOGIN: {
                    logger.debug("New LOGIN operation");
                    String message = gson.toJson(LedgerRequestType.LOGIN.name());
                    String user = (String) objIn.readObject();
                    byte[] msgSignature = (byte[]) objIn.readObject();
                    if (!jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        if(verifySignature(user,message,msgSignature)) {
                            logger.info("Signature verified");
                            String nonce = jedis.lrange(user.concat(USER_ACCOUNT), 4, -1).get(0);
                            byte[] hashResult = TOMUtil.computeHash(Boolean.toString(true).concat(nonce).getBytes());
                            objOut.writeObject(hashResult);
                            objOut.writeBoolean(true);
                            objOut.writeObject(nonce);
                        } else {
                            logger.info("Signature not verified");
                            byte[] hashResult = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NOUNCE).getBytes());
                            objOut.writeObject(hashResult);
                            objOut.writeBoolean(false);
                        }
                    }
                }
                break;
                case REGISTER_USER: {
                    logger.debug("New REGISTER_USER operation.");
                    String user = (String) objIn.readObject();
                    String signatureAlgorithm = (String) objIn.readObject();
                    byte[] publicKey = (byte[]) objIn.readObject();
                    String publicKeyAlgorithm = (String) objIn.readObject();
                    String hashAlgorithm = (String) objIn.readObject();
                    byte[] hashResult;
                    if (jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} already exists", user);
                        hashResult = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NOUNCE).getBytes());
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(false);
                        objOut.writeObject(NO_NOUNCE);
                    } else {
                        hashResult = TOMUtil.computeHash(Boolean.toString(true).concat(INITIAL_NONCE).getBytes());
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(true);
                        objOut.writeObject(INITIAL_NONCE);
                        jedis.rpush(user.concat(USER_ACCOUNT), new String(base64.encode(publicKey)));
                        jedis.rpush(user.concat(USER_ACCOUNT), signatureAlgorithm);
                        jedis.rpush(user.concat(USER_ACCOUNT), publicKeyAlgorithm);
                        jedis.rpush(user.concat(USER_ACCOUNT), hashAlgorithm);
                        jedis.rpush(user.concat(USER_ACCOUNT), INITIAL_NONCE);

                        logger.debug("User {}, with {} key, {} signature and length {} and nonce {}", user, publicKeyAlgorithm, signatureAlgorithm, publicKey.length * 8 * 4, INITIAL_NONCE);
                        logger.info("Registered user {}", user);
                    }
                    break;
                }
                case OBTAIN_COINS: {
                    logger.debug("New OBTAIN_COINS operation.");
                    String user = (String) objIn.readObject();

                    if (!jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        double amount = objIn.readDouble();
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String nonce = jedis.lrange(user.concat(USER_ACCOUNT), 4, -1).get(0);
                        String msg = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount).concat(nonce));
                        byte[] hash;
                        if (verifySignature(user, msg, msgSignature)) {
                            nonce = Integer.toString(Integer.parseInt(nonce)+1);
                            jedis.lset(user.concat(USER_ACCOUNT),4,nonce);

                            logger.info("Signature verified successfully");
                            SignedTransaction signedTransaction = new SignedTransaction(SYSTEM, user, amount, new String(base64.encode(msgSignature)));
                            hash = TOMUtil.computeHash(Boolean.toString(true).concat(Double.toString(amount)).getBytes());
                            objOut.writeObject(hash);
                            objOut.writeBoolean(true);
                            logger.info("New transaction ({}, {}, {}).", SYSTEM, user, amount);
                            jedis.rpush(GLOBAL_LEDGER, gson.toJson(signedTransaction));
                            logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", SYSTEM, user, amount);
                            registerUserTransaction(user, signedTransaction);
                            objOut.writeDouble(amount);
                        } else {
                            hash = TOMUtil.computeHash(Boolean.toString(false).concat(Double.toString(-1)).getBytes());
                            objOut.writeObject(hash);
                            objOut.writeBoolean(false);
                            objOut.writeDouble(-1);
                            logger.info("Invalid Signature");
                        }
                    }
                    break;
                }
                case TRANSFER_MONEY: {
                    logger.debug("New TRANSFER_MONEY operation.");
                    Transaction transaction = (Transaction) objIn.readObject();
                    String origin = transaction.getOrigin();
                    String destination = transaction.getDestination();
                    double amount = transaction.getAmount();
                    if (!jedis.exists(origin.concat(USER_ACCOUNT)) || !jedis.exists(destination.concat(USER_ACCOUNT))) {
                        logger.info("Bad transaction ({}, {}, {})", origin, destination, amount);
                        objOut.writeBoolean(false);
                    } else {
                        //TODO: Verify balance
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String nonce = jedis.lrange(origin.concat(USER_ACCOUNT), 4, -1).get(0);
                        String msg = gson.toJson(LedgerRequestType.TRANSFER_MONEY.name()).concat(gson.toJson(transaction).concat(nonce));
                        byte[] hash;

                        if (verifySignature(origin, msg, msgSignature)) {
                            nonce = Integer.toString(Integer.parseInt(nonce)+1);
                            jedis.lset(origin.concat(USER_ACCOUNT),4,nonce);
                            hash = TOMUtil.computeHash(Boolean.toString(true).getBytes());
                            logger.info("Signature verified successfully");
                            logger.info("Proposed transaction ({}, {}, {}).", origin, destination, amount);
                            SignedTransaction signedTransaction = new SignedTransaction(origin, destination, amount, new String(base64.encode(msgSignature)));
                            registerUserTransaction(transaction.getOrigin(), signedTransaction);
                            registerUserTransaction(transaction.getDestination(), signedTransaction);
                            jedis.rpush(GLOBAL_LEDGER, gson.toJson(signedTransaction));
                            logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", origin, destination, amount);
                            objOut.writeObject(hash);
                            objOut.writeBoolean(true);
                        } else {
                            hash = TOMUtil.computeHash(Boolean.toString(true).getBytes());
                            objOut.writeObject(hash);
                            objOut.writeBoolean(false);
                            logger.info("Invalid Signature");
                        }
                    }
                    break;
                }
                case CURRENT_AMOUNT: {
                    logger.debug("New CURRENT_AMOUNT operation.");
                    String user = (String) objIn.readObject();
                    if (!jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String msg = gson.toJson(LedgerRequestType.CURRENT_AMOUNT.name());
                        if (verifySignature(user, msg, msgSignature)) {
                            double balance = getBalance(user);
                            logger.info("User {} has {} coins.", user, balance);
                            objOut.writeBoolean(true);
                            objOut.writeDouble(balance);
                        } else {
                            objOut.writeBoolean(false);
                            logger.info("Invalid Signature");
                        }
                    }
                    break;
                }
                case GLOBAL_LEDGER:
                    logger.debug("New GLOBAL_LEDGER operation.");
                    objOut.writeObject(getLedger(GLOBAL_LEDGER));
                    break;
                case CLIENT_LEDGER: {
                    logger.debug("New CLIENT_LEDGER operation.");
                    String user = (String) objIn.readObject();
                    if (!jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String msg = gson.toJson(LedgerRequestType.CLIENT_LEDGER.name());
                        if (verifySignature(user, msg, msgSignature)) {
                            List<SignedTransaction> user_ledger = getLedger(user.concat(USER_LEDGER));
                            logger.info("User {} ledger found with length {}.", user, user_ledger);
                            objOut.writeBoolean(true);
                            objOut.writeObject(user_ledger);
                        } else {
                            objOut.writeBoolean(false);
                            logger.info("Invalid Signature");
                        }
                    }
                    break;
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

    private boolean verifySignature(String user, String msg, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        List<String> userData = jedis.lrange(user.concat(USER_ACCOUNT), 0, -1);
        PublicKey publicKey = KeyFactory.getInstance(userData.get(USER_KEY_ALGORITHM)).
                generatePublic(new X509EncodedKeySpec(base64.decode(userData.get(USER_KEY))));
        Signature sign = Signature.getInstance(userData.get(USER_SIGNATURE_ALGORITHM));
        sign.initVerify(publicKey);
        sign.update(generateHash(msg.getBytes(), userData.get(USER_HASH_ALGORITHM)));
        return sign.verify(signature);
    }

    private byte[] generateHash(byte[] msg, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(msg);
        return hash.digest();
    }

    private List<SignedTransaction> getLedger(String key) {
        List<SignedTransaction> deserialized_ledger = new LinkedList<>();
        List<String> serialized_ledger = jedis.lrange(key, 0, -1);
        serialized_ledger.forEach((transaction) -> deserialized_ledger.add(gson.fromJson(transaction, SignedTransaction.class)));
        return deserialized_ledger;
    }

    private double getBalance(String user) {
        double balance = 0;
        if (!jedis.exists(user.concat(USER_ACCOUNT)))
            return -1;
        List<String> ledger = jedis.lrange(user.concat(USER_LEDGER), 0, -1);
        for (String json_t : ledger) {
            SignedTransaction t = gson.fromJson(json_t, SignedTransaction.class);
            if (t.getOrigin().equals(user))
                balance -= t.getAmount();
            else if (t.getDestination().equals(user))
                balance += t.getAmount();
        }
        return balance;
    }

    private void registerUserTransaction(String user, SignedTransaction signedTransaction) {
        jedis.rpush(user.concat(USER_LEDGER), gson.toJson(signedTransaction));
        logger.debug("Transaction of user {} added to personal ledger.", user);
    }

    @Override
    public byte[] appExecuteUnordered(byte[] bytes, MessageContext messageContext) {
        return new byte[0];
    }


    @Override
    public void installSnapshot(byte[] bytes) {

    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
