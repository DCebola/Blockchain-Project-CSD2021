import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import bftsmart.tom.util.TOMUtil;
import com.google.gson.Gson;
import com.proxy.controllers.*;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;


import java.io.*;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class BFTSmartServer extends DefaultSingleRecoverable {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String INITIAL_NONCE = "0";
    private static final String NO_NONCE = "-1";

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private static final String GLOBAL_LEDGER = "GLOBAL-LEDGER";
    private static final String USER_ACCOUNT = "-ACCOUNT";
    private static final String USER_LEDGER = "-LEDGER";
    private static final String BLOCK_CHAIN = "BLOCK-CHAIN";
    private static final String PROOF_OF_WORK_CHALLENGE = "0000000000000000";

    private static final int KEY_ALGORITHM = 0;
    private static final int SIGNATURE_ALGORITHM = 1;
    private static final int HASH_ALGORITHM = 2;
    private static final int WALLET_NONCE = 3;
    private static final int TRANSACTION_ID_SIZE = 20;

    private final Logger logger;
    private Jedis jedis;
    private final Gson gson;
    private final Base32 base32;
    private final int id;
    private final SecureRandom rand;
    private final JedisPool jedisPool;


    public BFTSmartServer(int id) throws IOException, NoSuchAlgorithmException {
        this.id = id;
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.base32 = new Base32();
        this.rand = new SecureRandom();
        this.gson = new Gson();
        int work = -100283092;
        BlockHeader blockHeader = new BlockHeader(null, null, null, base32.encodeAsString(TOMUtil.computeHash(gson.toJson(null).getBytes())), null, work);


        Block genesisBlock = new Block(blockHeader, null);
        Properties jedis_properties = new Properties();

        //TODO: tls with redis
        jedis_properties.load(new FileInputStream("config/redis.config"));
        String redisPort = jedis_properties.getProperty("redis_port");
        String redis_ip = "172.18.30.".concat(Integer.toString(id));
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMaxTotal(128);
        jedisPoolConfig.setMaxIdle(128);
        jedisPoolConfig.setMinIdle(16);
        this.jedisPool = new JedisPool(jedisPoolConfig,redis_ip,Integer.parseInt(redisPort));
        jedis = jedisPool.getResource();
        //jedis = new Jedis("redis://".concat(redis_ip).concat(":").concat(redisPort));
        jedis.rpush(BLOCK_CHAIN, gson.toJson(genesisBlock));
        jedis.close();
        new ServiceReplica(id, this, this);

    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
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
                    jedis = jedisPool.getResource();
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
                    jedis = jedisPool.getResource();
                    if (!jedis.exists(publicKey)) {
                        jedis.close();
                        logger.info("Key {} does not exist", publicKey);
                        objOut.writeBoolean(false);
                    } else {
                        double amount = objIn.readDouble();
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String date = (String) objIn.readObject();
                        jedis = jedisPool.getResource();
                        String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                        jedis.close();
                        String msg = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount).concat(nonce).concat(date));
                        byte[] hash;
                        if (verifySignature(publicKey, msg, msgSignature) && amount > 0) {
                            nonce = Integer.toString(Integer.parseInt(nonce) + 1);
                            jedis = jedisPool.getResource();
                            jedis.lset(publicKey, WALLET_NONCE, nonce);
                            jedis.close();
                            logger.info("Signature verified successfully");
                            hash = TOMUtil.computeHash(Boolean.toString(true).concat(msg).getBytes());
                            byte[] idBytes = new byte[TRANSACTION_ID_SIZE];
                            rand.nextBytes(idBytes);
                            SignedTransaction signedTransaction = new SignedTransaction(
                                    SYSTEM,
                                    publicKey,
                                    amount,
                                    base32.encodeAsString(msgSignature),
                                    date,
                                    "0xT" + base32.encodeAsString(idBytes)
                            );
                            logger.info("T {}", gson.toJson(signedTransaction));
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
                        String date = transaction.getDate();
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        String nonce = jedis.lindex(origin, WALLET_NONCE);
                        String msg = gson.toJson(LedgerRequestType.TRANSFER_MONEY.name()).concat(gson.toJson(transaction).concat(nonce).concat(date));
                        if (amount > 0 && verifySignature(origin, msg, msgSignature)) {
                            logger.info("Signature verified successfully.");
                            if (getBalance(origin) >= amount) {
                                nonce = Integer.toString(Integer.parseInt(nonce) + 1);
                                jedis.lset(origin, WALLET_NONCE, nonce);
                                hash = TOMUtil.computeHash(Boolean.toString(true).concat(msg).getBytes());
                                byte[] idBytes = new byte[TRANSACTION_ID_SIZE];
                                rand.nextBytes(idBytes);
                                SignedTransaction signedTransaction = new SignedTransaction(
                                        origin,
                                        destination,
                                        amount,
                                        base32.encodeAsString(msgSignature),
                                        date,
                                        "0xT" + base32.encodeAsString(idBytes)
                                );
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
                    logger.debug("New COMMIT_TRANSACTION operation.");
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
                            t.getId());
                    logger.info("T {}", t);
                    jedis.rpush(GLOBAL_LEDGER, gson.toJson(transaction));
                    objOut.writeInt(id);
                    objOut.writeObject(TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(transaction)).getBytes()));
                    objOut.writeBoolean(true);
                    objOut.writeObject(transaction);
                    logger.info("Transaction ({}, {}, {}) added to global ledger.", origin, destination, amount);
                }
                break;
                case COMMIT_WALLET: {
                    logger.debug("New COMMIT_WALLET operation.");
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
                    objOut.writeInt(id);
                    objOut.writeObject(TOMUtil.computeHash(
                            Boolean.toString(true)
                                    .concat(publicKey)
                                    .concat(signatureAlgorithm)
                                    .concat(publicKeyAlgorithm)
                                    .concat(hashAlgorithm)
                                    .getBytes()));
                    objOut.writeBoolean(true);
                    objOut.writeObject(INITIAL_NONCE);
                    logger.debug("Registered key {} with hash algorithm {}, signature algorithm {} and nonce {}", publicKey, hashAlgorithm, signatureAlgorithm, INITIAL_NONCE);
                    logger.info("Registered key {}", publicKey);
                }
                break;
                case SEND_MINED_BLOCK: {
                    logger.debug("New SEND_MINED_BLOCK operation.");
                    BlockHeaderAndReward blockHeaderAndReward = (BlockHeaderAndReward) objIn.readObject();
                    BlockHeader blockHeader = blockHeaderAndReward.getBlockHeader();
                    Transaction transaction = blockHeaderAndReward.getTransaction();
                    String pubKey = blockHeader.getWhoSigned();
                    byte[] sigBytes = (byte[]) objIn.readObject();
                    String nonce = jedis.lindex(pubKey, WALLET_NONCE);
                    String msg = gson.toJson(LedgerRequestType.SEND_MINED_BLOCK.name()).concat(gson.toJson(blockHeaderAndReward).concat(nonce));
                    if (verifySignature(pubKey, msg, sigBytes) && transaction.getDestination().equals(pubKey) && transaction.getOrigin().equals("SYSTEM") && transaction.getAmount() == 20) {
                        logger.info("Signature verified successfully.");
                        byte[] block = gson.toJson(blockHeader).getBytes();
                        byte[] hashedBlock = generateHash(block, "SHA-256");
                        if (validProofOfWork(hashedBlock)) {
                            logger.info("Valid proof of work");
                            List<ValidTransaction> transactionsToBeVerified = getLedger(blockHeader.getTransactions().size() - 1);
                            assert transactionsToBeVerified != null;
                            if (verifyBlockContent(blockHeader, transactionsToBeVerified)) {
                                logger.info("Block completely verified!!");
                                Block finalBlock = new Block(blockHeader, transactionsToBeVerified);
                                byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(finalBlock)).concat(pubKey).getBytes());
                                objOut.writeInt(id);
                                objOut.writeObject(hash);
                                objOut.writeBoolean(true);
                                byte[] idBytes = new byte[TRANSACTION_ID_SIZE];
                                rand.nextBytes(idBytes);
                                SignedTransaction signedTransaction = new SignedTransaction(
                                        transaction.getOrigin(),
                                        transaction.getDestination(),
                                        transaction.getAmount(),
                                        base32.encodeAsString(sigBytes),
                                        transaction.getDate(),
                                        "0xTB" + base32.encodeAsString(idBytes)
                                );
                                BlockAndReward blockAndReward = new BlockAndReward(finalBlock, signedTransaction);
                                objOut.writeObject(blockAndReward);
                            } else {
                                logger.info("Block content invalid!!");
                                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                                objOut.writeInt(id);
                                objOut.writeObject(hash);
                                objOut.writeBoolean(false);
                                objOut.writeObject(null);
                            }
                        } else {
                            logger.info("Invalid proof of work!!");
                            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                            objOut.writeInt(id);
                            objOut.writeObject(hash);
                            objOut.writeBoolean(false);
                            objOut.writeObject(null);
                        }
                    } else {
                        logger.info("Signature not verified");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    }
                }
                break;
                case COMMIT_BLOCK: {
                    logger.info("Commit block");
                    Commit commit = (Commit) objIn.readObject();
                    BlockAndReward blockAndReward = (BlockAndReward) commit.getRequest();
                    SignedTransaction t = (SignedTransaction) blockAndReward.getTransaction();
                    String publicKey = blockAndReward.getBlock().getBlockHeader().getWhoSigned();
                    String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                    Block block = blockAndReward.getBlock();
                    nonce = Integer.toString(Integer.parseInt(nonce) + 1);

                    List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
                    Block lastBlock = gson.fromJson(l.get(0), Block.class);
                    BlockHeader lastBlockBlockHeader = lastBlock.getBlockHeader();
                    byte[] blockHeaderBytes = gson.toJson(lastBlockBlockHeader).getBytes();
                    byte[] hashedBlock = generateHash(blockHeaderBytes, "SHA-256");

                    if(validProofOfWork(hashedBlock) && block.getBlockHeader().getPreviousHash().equals(base32.encodeAsString(hashedBlock))) {
                        jedis.lpop(GLOBAL_LEDGER, block.getSignedTransactions().size());
                        addBlock(publicKey,nonce,block,t,commit,objOut,blockAndReward);
                    } else {
                        l = jedis.lrange(BLOCK_CHAIN, -2, -2);
                        if(l.size() > 0) {
                            BlockHeader secondLastBlockHeader = gson.fromJson(l.get(0),Block.class).getBlockHeader();
                            blockHeaderBytes = gson.toJson(secondLastBlockHeader).getBytes();
                            hashedBlock = generateHash(blockHeaderBytes, "SHA-256");
                            if(validProofOfWork(hashedBlock) && block.getBlockHeader().getPreviousHash().equals(base32.encodeAsString(hashedBlock))) {
                                if(lastBlock.getSignedTransactions().size() > block.getSignedTransactions().size()) {
                                    logger.info("The old block was better");
                                    notifyWithNotAddedBlock(objOut);
                                } else if(lastBlock.getSignedTransactions().size() == block.getSignedTransactions().size()) {
                                    if(newBlockHasBetterProof(block,lastBlock)) {
                                        cancelReward(lastBlock.getBlockHeader().getWhoSigned());
                                        jedis.rpop(BLOCK_CHAIN,1);
                                        addBlock(publicKey,nonce,block,t,commit,objOut,blockAndReward);
                                    } else {
                                        logger.info("The older block had a better proof");
                                        notifyWithNotAddedBlock(objOut);
                                    }
                                } else {
                                    jedis.rpop(BLOCK_CHAIN,1);
                                    jedis.rpop(GLOBAL_LEDGER,block.getSignedTransactions().size()-lastBlock.getSignedTransactions().size());
                                    cancelReward(lastBlock.getBlockHeader().getWhoSigned());
                                    addBlock(publicKey,nonce,block,t,commit,objOut,blockAndReward);
                                }
                            } else {
                                logger.info("This block is too old to be registered!!");
                                notifyWithNotAddedBlock(objOut);
                            }
                        } else {
                            logger.info("Too small of a chain to be able to replace blocks!!");
                            notifyWithNotAddedBlock(objOut);
                        }
                    }
                }
                break;
                case GET_NONCE: {
                    logger.debug("New REQUEST_NONCE operation");
                    String publicKey = (String) objIn.readObject();
                    if (jedis.exists(publicKey)) {
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
                    } else {
                        logger.info("Key not registered.");
                        byte[] hashResult = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NONCE).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hashResult);
                        objOut.writeBoolean(false);
                        objOut.writeObject(NO_NONCE);
                    }
                    break;
                }
                case CURRENT_AMOUNT: {
                    logger.debug("New CURRENT_AMOUNT operation.");
                    String publicKey = (String) objIn.readObject();
                    System.out.println(publicKey);
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
                    List<ValidTransaction> globalLedger = getLedger(dateInterval);
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(globalLedger)).getBytes());
                    objOut.writeObject(hash);
                    objOut.writeObject(globalLedger);
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
                        List<ValidTransaction> clientLedger = getLedger(publicKey, dateInterval);
                        logger.info("Found ledger with length {} associated with key {}.", clientLedger.size(), clientLedger);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(clientLedger)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(clientLedger);
                    }
                    break;
                }
                case VERIFY: {
                    logger.debug("New VERIFY operation.");
                    String transactionId = (String) objIn.readObject();
                    ValidTransaction transaction = findTransaction(transactionId);
                    if (transaction != null) {
                        logger.info("Transaction verified");
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(transaction)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(transaction);
                    } else {
                        logger.info("Transaction not found.");
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    }
                    break;
                }
                case PICK_NOT_MINED_TRANSACTIONS: {
                    int numTransactions = objIn.readInt();
                    List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
                    Block lastBlock = gson.fromJson(l.get(0), Block.class);
                    BlockHeader lastBlockBlockHeader = lastBlock.getBlockHeader();
                    byte[] blockHeaderBytes = gson.toJson(lastBlockBlockHeader).getBytes();
                    byte[] hashedBlock = generateHash(blockHeaderBytes, "SHA-256");

                    List<ValidTransaction> notMinedTransactions = getLedger(numTransactions - 1);
                    if (notMinedTransactions != null && validProofOfWork(hashedBlock)) {
                        logger.info("Building block header");
                        BlockHeader blockHeader = buildBlockHeader(notMinedTransactions, base32.encodeAsString(hashedBlock));
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(blockHeader)).concat(gson.toJson(lastBlock)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(blockHeader);
                        objOut.writeObject(lastBlock);
                    } else {
                        logger.info("Not building block header");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).concat(gson.toJson(null)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                        objOut.writeObject(null);
                    }
                    break;
                }
                case OBTAIN_LAST_BLOCK: {
                    logger.info("Obtaining last block");
                    List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
                    logger.info("Sending the last block");
                    Block block = gson.fromJson(l.get(0), Block.class);
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(block)).getBytes());
                    objOut.writeInt(id);
                    objOut.writeObject(hash);
                    objOut.writeBoolean(true);
                    objOut.writeObject(block);

                    break;
                }
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException | EncoderException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private void cancelReward(String whoSigned) {
        List<String> transactions = jedis.lrange(GLOBAL_LEDGER,0,-1);
        for(int i = 0; i < transactions.size(); i++) {
            ValidTransaction validTransaction = gson.fromJson(transactions.get(i),ValidTransaction.class);
            if(validTransaction.getDestination().equals(whoSigned)) {
                jedis.lrem(GLOBAL_LEDGER, 1, transactions.get(i));
                break;
            }
        }
    }

    private void notifyWithNotAddedBlock(ObjectOutput objOut) throws IOException {
        objOut.writeInt(id);
        objOut.writeObject(TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes()));
        objOut.writeBoolean(false);
        objOut.writeObject(null);
    }

    private void addBlock(String publicKey, String nonce, Block block, SignedTransaction t, Commit commit, ObjectOutput objOut, BlockAndReward blockAndReward) throws IOException {
        jedis.lset(publicKey, WALLET_NONCE, nonce);
        jedis.rpush(BLOCK_CHAIN, gson.toJson(block));
        ValidTransaction transaction = new ValidTransaction(
                t.getOrigin(),
                t.getDestination(),
                t.getAmount(),
                t.getSignature(),
                t.getDate(),
                commit.getHash(),
                commit.getReplicas(),
                t.getId());
        jedis.rpush(GLOBAL_LEDGER, gson.toJson(transaction));
        objOut.writeInt(id);
        objOut.writeObject(TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(blockAndReward)).getBytes()));
        objOut.writeBoolean(true);
        objOut.writeObject(blockAndReward);
        logger.info("Block added to global ledger");

    }

    private boolean newBlockHasBetterProof(Block block, Block lastBlock) throws NoSuchAlgorithmException {
        BlockHeader blockHeader = block.getBlockHeader();
        byte[] blockHeaderBytes = gson.toJson(blockHeader).getBytes();
        byte[] hashedBlock = generateHash(blockHeaderBytes, "SHA-256");

        BlockHeader lastBlockHeader = lastBlock.getBlockHeader();
        byte[] lastBlockHeaderBytes = gson.toJson(lastBlockHeader).getBytes();
        byte[] hashedLastBlock = generateHash(lastBlockHeaderBytes, "SHA-256");

        for (int i = 2; i < hashedBlock.length; i++) {
            byte blockByte = hashedBlock[i];
            byte lastBlockByte = hashedLastBlock[i];
            if (blockByte > lastBlockByte)
                return false;
            if (blockByte < lastBlockByte)
                return true;
        }
        return false;
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
                    jedis = jedisPool.getResource();
                    if (jedis.exists(publicKey)) {
                        jedis.close();
                        String message = gson.toJson(LedgerRequestType.GET_NONCE.name().concat(publicKey));
                        byte[] msgSignature = (byte[]) objIn.readObject();
                        if (verifySignature(publicKey, message, msgSignature)) {
                            logger.info("Signature verified");
                            jedis = jedisPool.getResource();
                            String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                            jedis.close();
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
                    } else {
                        logger.info("Key not registered.");
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
                    System.out.println(publicKey);
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
                    List<ValidTransaction> globalLedger = getLedger(dateInterval);
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(globalLedger)).getBytes());
                    objOut.writeObject(hash);
                    objOut.writeObject(globalLedger);
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
                        List<ValidTransaction> clientLedger = getLedger(publicKey, dateInterval);
                        logger.info("Found ledger with length {} associated with key {}.", clientLedger.size(), clientLedger);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(clientLedger)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(clientLedger);
                    }
                    break;
                }
                case VERIFY: {
                    logger.debug("New VERIFY operation.");
                    String transactionId = (String) objIn.readObject();
                    ValidTransaction transaction = findTransaction(transactionId);
                    if (transaction != null) {
                        logger.info("Transaction verified");
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(transaction)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(transaction);
                    } else {
                        logger.info("Transaction not found.");
                        objOut.writeInt(id);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                    }
                    break;
                }
                case PICK_NOT_MINED_TRANSACTIONS: {
                    int numTransactions = objIn.readInt();
                    List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
                    Block lastBlock = gson.fromJson(l.get(0), Block.class);
                    BlockHeader lastBlockBlockHeader = lastBlock.getBlockHeader();
                    byte[] blockHeaderBytes = gson.toJson(lastBlockBlockHeader).getBytes();
                    byte[] hashedBlock = generateHash(blockHeaderBytes, "SHA-256");

                    List<ValidTransaction> notMinedTransactions = getLedger(numTransactions - 1);
                    if (notMinedTransactions != null && validProofOfWork(hashedBlock)) {
                        logger.info("Building block header");
                        BlockHeader blockHeader = buildBlockHeader(notMinedTransactions, base32.encodeAsString(hashedBlock));
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(blockHeader)).concat(gson.toJson(lastBlock)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(true);
                        objOut.writeObject(blockHeader);
                        objOut.writeObject(lastBlock);
                    } else {
                        logger.info("Not building block header");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).concat(gson.toJson(null)).getBytes());
                        objOut.writeInt(id);
                        objOut.writeObject(hash);
                        objOut.writeBoolean(false);
                        objOut.writeObject(null);
                        objOut.writeObject(null);
                    }
                    break;
                }
                case OBTAIN_LAST_BLOCK: {
                    logger.info("Obtaining last block");
                    List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
                    logger.info("Sending the last block");
                    Block block = gson.fromJson(l.get(0), Block.class);
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(block)).getBytes());
                    objOut.writeInt(id);
                    objOut.writeObject(hash);
                    objOut.writeBoolean(true);
                    objOut.writeObject(block);

                    break;
                }
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException | EncoderException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private BlockHeader buildBlockHeader(List<ValidTransaction> notMinedTransactions, String previousHash) throws EncoderException {
        String integrityHash = buildCumulativeHash(notMinedTransactions);
        String timeStamp = LocalDateTime.now().format(formatter);
        int work = -1;
        List<String> blockTransactions = new LinkedList<>();
        for (int i = 0; i < notMinedTransactions.size(); i++) {
            blockTransactions.add(notMinedTransactions.get(i).getId());
        }
        //String previousHash = gson.fromJson(jedis.lrange(BLOCK_CHAIN,-1,-1).get(0),Block.class).getBlockHeader().;
        return new BlockHeader(null, previousHash, blockTransactions, integrityHash, timeStamp);
    }

    private String buildCumulativeHash(List<ValidTransaction> notMinedTransactions) throws EncoderException {
        String finalHash = "";
        for (int i = 0; i < notMinedTransactions.size(); i++) {
            if (i == 0)
                finalHash = finalHash.concat(notMinedTransactions.get(i).getHash());
            else
                finalHash = gson.toJson(TOMUtil.computeHash(finalHash.concat(notMinedTransactions.get(i).getHash()).getBytes()));
        }

        return base32.encodeAsString(finalHash.getBytes());
    }

    private boolean verifySignature(String publicKey, String msg, byte[] signature) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        jedis = jedisPool.getResource();
        List<String> walletData = jedis.lrange(publicKey, 0, -1);
        jedis.close();
        Signature sign = Signature.getInstance(walletData.get(SIGNATURE_ALGORITHM));
        sign.initVerify(KeyFactory.getInstance(walletData.get(KEY_ALGORITHM)).
                generatePublic(new X509EncodedKeySpec(base32.decode(publicKey))));
        sign.update(generateHash(msg.getBytes(), walletData.get(HASH_ALGORITHM)));
        return sign.verify(signature);
    }

    private boolean verifyBlockContent(BlockHeader blockHeader, List<ValidTransaction> transactionsToBeVerified) {
        List<String> transactionsInBlock = blockHeader.getTransactions();
        String finalHash = "";
        assert transactionsToBeVerified != null;
        if (transactionsInBlock.size() == transactionsToBeVerified.size()) {
            for (int i = 0; i < transactionsToBeVerified.size(); i++) {
                ValidTransaction transaction = transactionsToBeVerified.get(i);
                if (transaction.getId().equals(transactionsInBlock.get(i))) {
                    if (i == 0)
                        finalHash = finalHash.concat(transaction.getHash());
                    else
                        finalHash = gson.toJson(TOMUtil.computeHash(finalHash.concat(transaction.getHash()).getBytes()));
                } else {
                    return false;
                }
            }
            finalHash = base32.encodeAsString(finalHash.getBytes());
            return finalHash.equals(blockHeader.getIntegrityHash());
        }
        return false;
    }

    private byte[] generateHash(byte[] msg, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(msg);
        return hash.digest();
    }

    private boolean validProofOfWork(byte[] block) {
        String leftMostByte = Integer.toBinaryString(block[0] & 255 | 256).substring(1);
        String secondLeftMostByte = Integer.toBinaryString(block[1] & 255 | 256).substring(1);
        String mostSignificantBytes = leftMostByte.concat(secondLeftMostByte);
        return mostSignificantBytes.equals(PROOF_OF_WORK_CHALLENGE);
    }

    private ValidTransaction findTransaction(String id) {
        List<String> blocks = jedis.lrange(BLOCK_CHAIN,1,-1);
        for(String b: blocks) {
            Block block = gson.fromJson(b,Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for(ValidTransaction transaction: validTransactions) {
                if (transaction.getId().equals(id))
                    return transaction;
            }
        }
        return null;
    }


    private List<ValidTransaction> getLedger(int numTransactions) {
        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        List<String> serializedLedger = null;
        long globalLedgerSize = jedis.llen(GLOBAL_LEDGER);
        if (numTransactions >= 0 && globalLedgerSize > 0) {
            if (numTransactions <= globalLedgerSize)
                serializedLedger = jedis.lrange(GLOBAL_LEDGER, 0, numTransactions);
            else
                serializedLedger = jedis.lrange(GLOBAL_LEDGER, 0, -1);
            serializedLedger.forEach(t -> deserializedLedger.add(gson.fromJson(t, ValidTransaction.class)));
            return deserializedLedger;
        }
        return null;
    }

    private List<ValidTransaction> getLedger() {
        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        List<String> serializedLedger = jedis.lrange(GLOBAL_LEDGER, 0, -1);
        serializedLedger.forEach(t -> deserializedLedger.add(gson.fromJson(t, ValidTransaction.class)));
        return deserializedLedger;
    }


    private List<ValidTransaction> getLedger(DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        //List<String> serializedLedger = jedis.lrange(GLOBAL_LEDGER, 0, -1);
        List<String> blocks = jedis.lrange(BLOCK_CHAIN, 1, -1);
        for(String b: blocks) {
            Block block = gson.fromJson(b,Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction transaction : validTransactions) {
                long transactionTimeStamp = Timestamp.valueOf(transaction.getDate()).getTime();
                if (transactionTimeStamp >= startDate && transactionTimeStamp <= endDate) {
                    deserializedLedger.add(transaction);
                }
            }
        }
        return deserializedLedger;
    }

    private List<ValidTransaction> getLedger(String publicKey, DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserializedLedger = new LinkedList<>();

        List<String> blocks = jedis.lrange(BLOCK_CHAIN,1,-1);
        for(String b: blocks) {
            Block block = gson.fromJson(b,Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for(ValidTransaction transaction: validTransactions) {
                if (transaction.getOrigin().equals(publicKey) || transaction.getDestination().equals(publicKey)) {
                    long transactionTimeStamp = Timestamp.valueOf(transaction.getDate()).getTime();
                    if (transactionTimeStamp >= startDate && transactionTimeStamp <= endDate) {
                        deserializedLedger.add(transaction);
                    }
                }
            }
        }
        return deserializedLedger;
    }


    private double getBalance(String publicKey) {
        double balance = 0;
        if (!jedis.exists(publicKey))
            return -1;

        List<String> blockChain = jedis.lrange(BLOCK_CHAIN, 1, -1);
        for (String b : blockChain) {
            Block block = gson.fromJson(b, Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction t : validTransactions) {
                if (t.getOrigin().equals(publicKey))
                    balance -= t.getAmount();
                else if (t.getDestination().equals(publicKey))
                    balance += t.getAmount();
            }
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
