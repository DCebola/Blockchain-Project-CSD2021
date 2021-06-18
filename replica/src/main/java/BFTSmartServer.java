import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import bftsmart.tom.util.TOMUtil;
import com.google.gson.Gson;
import com.proxy.controllers.*;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;


import java.io.*;
import java.math.BigInteger;
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
    private static final String PENDING_TRANSACTIONS = "PENDING-TRANSACTIONS";
    private static final String PENDING_REWARD = "PENDING-REWARDS";
    private static final String BLOCK_CHAIN = "BLOCK-CHAIN";


    private static final int KEY_ALGORITHM = 0;
    private static final int SIGNATURE_ALGORITHM = 1;
    private static final int HASH_ALGORITHM = 2;
    private static final int WALLET_NONCE = 3;
    private static final int TRANSACTION_ID_SIZE = 20;

    private static final String NORMAL_TRANSACTION_ID_PREFIX = "0xT";
    private static final String REWARD_TRANSACTION_ID_PREFIX = "0xTB";

    private final Logger logger;
    private Jedis jedis;
    private final Gson gson;
    private final Base32 base32;
    private final int id;
    private final SecureRandom rand;
    private final JedisPool jedisPool;
    private final String challenge;
    private final String hash_algorithm;
    private final int mining_reward;

    public BFTSmartServer(int id) throws IOException {
        this.id = id;
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.base32 = new Base32();
        this.rand = new SecureRandom();
        this.gson = new Gson();

        Properties properties = new Properties();
        properties.load(new FileInputStream("config/replica.config"));

        this.challenge = properties.getProperty("challenge");
        this.hash_algorithm = properties.getProperty("hash_algorithm");
        this.mining_reward = Integer.parseInt(properties.getProperty("mining_reward"));

        int work = -100283092;
        BlockHeader blockHeader = new BlockHeader(
                SYSTEM,
                null,
                null,
                base32.encodeAsString(TOMUtil.computeHash(SYSTEM.getBytes())),
                null,
                work);
        Block genesisBlock = new Block(blockHeader, null);

        String redisPort = properties.getProperty("redis_port");
        String redis_ip = "172.18.30.".concat(Integer.toString(id));
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMaxTotal(Integer.parseInt(properties.getProperty("max_total")));
        jedisPoolConfig.setMaxIdle(Integer.parseInt(properties.getProperty("max_idle")));
        jedisPoolConfig.setMinIdle(Integer.parseInt(properties.getProperty("min_idle")));
        this.jedisPool = new JedisPool(jedisPoolConfig, redis_ip, Integer.parseInt(redisPort)); //TODO: ENABLE TLS

        jedis = jedisPool.getResource();
        //jedis = new Jedis("redis://".concat(redis_ip).concat(":").concat(redisPort));
        jedis.rpush(BLOCK_CHAIN, gson.toJson(genesisBlock));
        jedis.close();
        new ServiceReplica(id, this, this);

    }

    public static void main(String[] args) throws IOException {
        if (args.length == 1) {
            Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
            new BFTSmartServer(Integer.parseInt(args[0]));
        } else
            System.out.println("Usage: BFTSmartServer <server id>");
    }

    /****************************************++**** Ordered requests **************************************************/

    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case REGISTER_KEY:
                    registerKeyRequest(objIn, objOut);
                    break;
                case OBTAIN_COINS:
                    obtainCoinsRequest(objIn, objOut);
                    break;
                case TRANSFER_MONEY:
                    transferMoneyRequest(objIn, objOut);
                    break;
                case SEND_MINED_BLOCK:
                    sendMinedBlockRequest(objIn, objOut);
                    break;
                case COMMIT_WALLET:
                    commitWalletRequest(objIn, objOut);
                    break;
                case COMMIT_TRANSACTION:
                    commitTransactionRequest(objIn, objOut);
                    break;
                case COMMIT_BLOCK:
                    commitBlockRequest(objIn, objOut);
                    break;
                case TRANSFER_MONEY_WITH_PRIVACY:
                    transferMoneyWithPrivacyRequest(objIn, objOut);
                    break;
                case COMMIT_TRANSFER_WITH_PRIVACY:
                    commitTransferMoneyWithPrivacy(objIn, objOut);
                    break;
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private void registerKeyRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New REGISTER_KEY operation.");
        String publicKey = (String) objIn.readObject();
        String signatureAlgorithm = (String) objIn.readObject();
        String publicKeyAlgorithm = (String) objIn.readObject();
        String hashAlgorithm = (String) objIn.readObject();
        BigInteger encryptedZero = (BigInteger) objIn.readObject();
        BigInteger pkNSquare = (BigInteger) objIn.readObject();

        byte[] hash;
        jedis = jedisPool.getResource();
        if (jedis.exists(publicKey)) {
            jedisPool.close();
            logger.info("Key {} already registered", publicKey);
            hash = TOMUtil.computeHash(
                    Boolean.toString(false)
                            .concat(publicKey)
                            .concat(signatureAlgorithm)
                            .concat(publicKeyAlgorithm)
                            .concat(hashAlgorithm)
                            .concat(encryptedZero.toString())
                            .concat(pkNSquare.toString())
                            .getBytes());
            writeRegisterKeyResponse(objOut, hash, false, null);
        } else {
            jedis.close();
            hash = TOMUtil.computeHash(
                    Boolean.toString(true)
                            .concat(publicKey)
                            .concat(signatureAlgorithm)
                            .concat(publicKeyAlgorithm)
                            .concat(hashAlgorithm)
                            .concat(encryptedZero.toString())
                            .concat(pkNSquare.toString())
                            .getBytes());
            writeRegisterKeyResponse(objOut, hash, true, new Wallet(publicKey, publicKeyAlgorithm, signatureAlgorithm, hashAlgorithm, encryptedZero, pkNSquare));
        }
    }


    private void obtainCoinsRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        logger.debug("New OBTAIN_COINS operation.");
        String publicKey = (String) objIn.readObject();
        jedis = jedisPool.getResource();
        if (!jedis.exists(publicKey)) {
            jedis.close();
            logger.info("Key {} does not exist", publicKey);
            objOut.writeBoolean(false);
        } else {
            jedis.close();
            BigInteger amount = (BigInteger) objIn.readObject();
            byte[] msgSignature = (byte[]) objIn.readObject();
            String date = (String) objIn.readObject();
            jedis = jedisPool.getResource();
            String nonce = jedis.lindex(publicKey, WALLET_NONCE);
            jedis.close();
            String msg = LedgerRequestType.OBTAIN_COINS.name().concat(gson.toJson(amount)).concat(nonce).concat(date);
            System.out.println("-----------");
            System.out.println(msg);
            System.out.println("-----------");

            byte[] hash;
            if (verifySignature(publicKey, msg, msgSignature) && amount.intValue() > 0) {
                logger.info("Signature verified successfully");
                hash = TOMUtil.computeHash(Boolean.toString(true).concat(msg).getBytes());
                SignedTransaction signedTransaction = createSignedTransaction(
                        SYSTEM,
                        publicKey,
                        amount,
                        base32.encodeAsString(msgSignature),
                        date,
                        NORMAL_TRANSACTION_ID_PREFIX,
                        null,
                        null,
                        null
                );
                writeObtainAmountResponse(objOut, hash, true, signedTransaction, amount, date);
            } else {
                hash = TOMUtil.computeHash(Boolean.toString(false).concat(new BigInteger("-1").toString()).getBytes());
                writeObtainAmountResponse(objOut, hash, false, null, new BigInteger("-1"), null);
            }
        }
    }

    private SignedTransaction createSignedTransaction(String origin, String destination, BigInteger amount, String signature, String date, String prefix, BigInteger encryptedAmount, String whoEncrypted, String transactionPointer) {
        byte[] idBytes = new byte[TRANSACTION_ID_SIZE];
        rand.nextBytes(idBytes);
        SignedTransaction signedTransaction = new SignedTransaction(
                origin,
                destination,
                amount,
                signature,
                date,
                prefix + base32.encodeAsString(idBytes),
                encryptedAmount,
                whoEncrypted,
                transactionPointer
        );
        logger.info("T {}", gson.toJson(signedTransaction));
        return signedTransaction;
    }

    private void transferMoneyWithPrivacyRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        logger.debug("New TRANSFER_MONEY_WITH_PRIVACY operation");
        Transaction t = (Transaction) objIn.readObject();
        String secretValue = (String) objIn.readObject();
        String origin = t.getOrigin();
        String destination = t.getDestination();
        BigInteger encryptedAmount = t.getEncryptedAmount();

        jedis = jedisPool.getResource();
        byte[] hash;
        if (!jedis.exists(origin) || !jedis.exists(destination) || origin.equals(destination)) {
            jedis.close();
            logger.info("Bad transaction ({}, {}, {})", origin, destination, encryptedAmount);
        } else {
            String date = t.getDate();
            jedis.close();
            byte[] msgSignature = (byte[]) objIn.readObject();
            jedis = jedisPool.getResource();
            String nonce = jedis.lindex(origin, WALLET_NONCE);
            jedis.close();
            String msg = LedgerRequestType.TRANSFER_MONEY_WITH_PRIVACY.name().concat(gson.toJson(t).concat(secretValue).concat(nonce).concat(date));
            if (verifySignature(origin, msg, msgSignature)) {
                logger.info("Signature verified successfully");
                /*if (getBalance(origin).intValue() >= amount.intValue()) {}*/
                hash = TOMUtil.computeHash(Boolean.toString(true).concat(msg).getBytes());
                SignedTransaction signedTransaction = createSignedTransaction(
                        origin,
                        destination,
                        t.getAmount(),
                        base32.encodeAsString(msgSignature),
                        date,
                        NORMAL_TRANSACTION_ID_PREFIX,
                        encryptedAmount,
                        t.getWhoEncrypted(),
                        t.getTransactionPointer()
                );
                logger.info("Proposed transaction ({}, {}, {}).", origin, destination, encryptedAmount);
                writeTransferMoneyWithPrivacyResponse(objOut, hash, true, signedTransaction, secretValue);
            } else {
                hash = TOMUtil.computeHash(Boolean.toString(false).getBytes());
                writeTransferMoneyResponse(objOut, hash, false, null);
                logger.info("Signature not verified!");
            }
        }
    }


    private void transferMoneyRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        logger.debug("New TRANSFER_MONEY operation.");
        Transaction transaction = (Transaction) objIn.readObject();
        String origin = transaction.getOrigin();
        String destination = transaction.getDestination();
        BigInteger amount = transaction.getAmount();
        byte[] hash;
        jedis = jedisPool.getResource();
        if (!jedis.exists(origin) || !jedis.exists(destination) || origin.equals(destination)) {
            jedis.close();
            logger.info("Bad transaction ({}, {}, {})", origin, destination, amount);
            hash = TOMUtil.computeHash(Boolean.toString(false).getBytes());
            writeTransferMoneyResponse(objOut, hash, false, null);
            logger.info("Invalid Signature");
        } else {
            jedis.close();
            String date = transaction.getDate();
            byte[] msgSignature = (byte[]) objIn.readObject();
            jedis = jedisPool.getResource();
            String nonce = jedis.lindex(origin, WALLET_NONCE);
            jedis.close();
            String msg = LedgerRequestType.TRANSFER_MONEY.name().concat(gson.toJson(transaction)).concat(nonce).concat(date);
            if (amount.intValue() > 0 && verifySignature(origin, msg, msgSignature)) {
                logger.info("Signature verified successfully.");
                if (getBalance(origin).intValue() >= amount.intValue()) {
                    hash = TOMUtil.computeHash(Boolean.toString(true).concat(msg).getBytes());
                    SignedTransaction signedTransaction = createSignedTransaction(
                            origin,
                            destination,
                            amount,
                            base32.encodeAsString(msgSignature),
                            date,
                            NORMAL_TRANSACTION_ID_PREFIX,
                            null,
                            null,
                            null
                    );
                    logger.info("Proposed transaction ({}, {}, {}).", origin, destination, amount);
                    writeTransferMoneyResponse(objOut, hash, true, signedTransaction);
                } else {
                    hash = TOMUtil.computeHash(Boolean.toString(false).getBytes());
                    writeTransferMoneyResponse(objOut, hash, false, null);
                    logger.info("Not enough balance.");
                }
            } else {
                hash = TOMUtil.computeHash(Boolean.toString(true).getBytes());
                writeTransferMoneyResponse(objOut, hash, false, null);
                logger.info("Invalid Signature");
            }
        }
    }


    private void sendMinedBlockRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        logger.debug("New SEND_MINED_BLOCK operation.");
        BlockHeaderAndReward blockHeaderAndReward = (BlockHeaderAndReward) objIn.readObject();
        BlockHeader blockHeader = blockHeaderAndReward.getBlockHeader();
        Transaction reward = blockHeaderAndReward.getTransaction();
        logger.info("{}", reward);
        String publicKey = blockHeader.getAuthor();
        byte[] sigBytes = (byte[]) objIn.readObject();
        jedis = jedisPool.getResource();
        if (!jedis.exists(publicKey)) {
            jedis.close();
            logger.debug("Key {} does not exist", publicKey);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
            writeSendMinedResponse(objOut, hash, false, null);
        } else {
            jedis.close();
            jedis = jedisPool.getResource();
            String nonce = jedis.lindex(publicKey, WALLET_NONCE);
            jedis.close();
            String msg = LedgerRequestType.SEND_MINED_BLOCK.name().concat(gson.toJson(blockHeaderAndReward)).concat(nonce);
            System.out.println("-------------------------");
            System.out.println(msg);
            System.out.println("-------------------------");
            if (verifySignature(publicKey, msg, sigBytes)
                    && reward.getDestination().equals(publicKey)
                    && reward.getOrigin().equals(SYSTEM)
                    && reward.getAmount().intValue() == mining_reward) {
                logger.info("Signature verified successfully.");
                byte[] block = gson.toJson(blockHeader).getBytes();
                byte[] hashedBlock = generateHash(block, hash_algorithm);

                if (checkProofOfWork(hashedBlock)) {
                    logger.info("Valid proof of work");
                    List<ValidTransaction> transactionsToVerify = getPendingTransactions(blockHeader.getTransactions().size() - 1);
                    assert transactionsToVerify != null;
                    if (verifyBlockContent(blockHeader, transactionsToVerify)) {
                        logger.info("Block completely verified.");
                        Block finalBlock = new Block(blockHeader, transactionsToVerify);
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(finalBlock)).concat(publicKey).getBytes());
                        SignedTransaction signedReward = createSignedTransaction(
                                reward.getOrigin(),
                                reward.getDestination(),
                                reward.getAmount(),
                                base32.encodeAsString(sigBytes),
                                reward.getDate(),
                                REWARD_TRANSACTION_ID_PREFIX,
                                null,
                                null,
                                null
                        );
                        BlockAndReward blockAndReward = new BlockAndReward(finalBlock, signedReward);
                        logger.info("{}", gson.toJson(blockAndReward));
                        writeSendMinedResponse(objOut, hash, true, blockAndReward);
                    } else {
                        logger.info("Block content invalid.");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        writeSendMinedResponse(objOut, hash, false, null);
                    }
                } else {
                    logger.info("Invalid proof of work.");
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                    writeSendMinedResponse(objOut, hash, false, null);
                }
            } else {
                logger.info("Signature not verified");
                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                writeSendMinedResponse(objOut, hash, false, null);
            }
        }
    }

    private boolean checkProofOfWork(byte[] block) {
        return Utils.getMostSignificantBytes((challenge.length() / Byte.SIZE), block).equals(challenge);
    }

    private boolean verifyBlockContent(BlockHeader blockHeader, List<ValidTransaction> transactionsToVerify) {
        List<String> transactionsInBlock = blockHeader.getTransactions();
        String finalHash = "";
        assert transactionsToVerify != null;
        if (transactionsInBlock.size() == transactionsToVerify.size()) {
            for (int i = 0; i < transactionsToVerify.size(); i++) {
                ValidTransaction transaction = transactionsToVerify.get(i);
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
        } else
            return false;
    }


    private void commitWalletRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New COMMIT_WALLET operation.");
        Commit commit = (Commit) objIn.readObject();
        Wallet wallet = (Wallet) commit.getRequest();
        String publicKey = wallet.getPublicKey();
        String publicKeyAlgorithm = wallet.getPublicKeyAlgorithm();
        String signatureAlgorithm = wallet.getSignatureAlgorithm();
        String hashAlgorithm = wallet.getHashAlgorithm();
        BigInteger encryptedZero = wallet.getEncryptedZero();
        BigInteger pkNSquare = wallet.getPkNSquare();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, publicKeyAlgorithm);
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, signatureAlgorithm);
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, hashAlgorithm);
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, INITIAL_NONCE);
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, encryptedZero.toString());
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(publicKey, pkNSquare.toString());
        jedis.close();

        byte[] hash = TOMUtil.computeHash(
                Boolean.toString(true)
                        .concat(publicKey)
                        .concat(signatureAlgorithm)
                        .concat(publicKeyAlgorithm)
                        .concat(hashAlgorithm)
                        .getBytes());
        writeCommitWalletResponse(objOut, hash, true);
        logger.debug("Registered key {} with hash algorithm {}, signature algorithm {} and nonce {} and homomorphic square of key {}", publicKey, hashAlgorithm, signatureAlgorithm, INITIAL_NONCE, pkNSquare.toString());
        logger.info("Registered key {}", publicKey);
    }

    private void commitTransferMoneyWithPrivacy(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New COMMIT_TRANSACTION_WITH_PRIVACY operation");
        Commit commit = (Commit) objIn.readObject();
        TransactionPlusSecretValue transactionPlusSecretValue = (TransactionPlusSecretValue) commit.getRequest();
        SignedTransaction t = (SignedTransaction) transactionPlusSecretValue.getTransaction();
        String secretValue = transactionPlusSecretValue.getSecretValue();

        jedis = jedisPool.getResource();

        String nonce = jedis.lindex(t.getOrigin(), WALLET_NONCE);
        jedis.close();
        nonce = Integer.toString(Integer.parseInt(nonce) + 1);
        jedis = jedisPool.getResource();
        jedis.lset(t.getDestination(), WALLET_NONCE, nonce);
        jedis.close();
        jedis = jedisPool.getResource();

        ValidTransaction validTransaction = new ValidTransaction(
                t.getOrigin(),
                t.getDestination(),
                t.getAmount(),
                t.getSignature(),
                t.getDate(),
                commit.getHash(),
                commit.getReplicas(),
                t.getId(),
                t.getEncryptedAmount(),
                t.getWhoEncrypted(),
                t.getTransactionPointer());

        InfoForDestination infoForDestination = new InfoForDestination(t.getOrigin(),t.getDestination(),secretValue,validTransaction.getId());

        logger.info("T {}", t);
        jedis = jedisPool.getResource();
        jedis.rpush(PENDING_TRANSACTIONS, gson.toJson(validTransaction));
        jedis.close();

        jedis = jedisPool.getResource();
        jedis.rpush(t.getDestination(), gson.toJson(infoForDestination));
        jedis.close();

        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(validTransaction)).getBytes());
        writeCommitTransactionResponse(objOut, hash, true, validTransaction);
        logger.info("Transaction ({}, {}, {}) added to global ledger.", t.getOrigin(), t.getDestination(), t.getEncryptedAmount());
    }


    private void commitTransactionRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New COMMIT_TRANSACTION operation.");
        Commit commit = (Commit) objIn.readObject();
        SignedTransaction t = (SignedTransaction) commit.getRequest();
        String origin = t.getOrigin();
        String destination = t.getDestination();
        BigInteger amount = t.getAmount();

        jedis = jedisPool.getResource();
        String nonce = "";
        if (origin.equals(SYSTEM)) {
            nonce = jedis.lindex(destination, WALLET_NONCE);
            jedis.close();
            nonce = Integer.toString(Integer.parseInt(nonce) + 1);
            jedis = jedisPool.getResource();
            jedis.lset(destination, WALLET_NONCE, nonce);
        } else {
            nonce = jedis.lindex(origin, WALLET_NONCE);
            jedis.close();
            nonce = Integer.toString(Integer.parseInt(nonce) + 1);
            jedis = jedisPool.getResource();
            jedis.lset(origin, WALLET_NONCE, nonce);
        }
        jedis.close();
        ValidTransaction validTransaction = new ValidTransaction(
                origin,
                destination,
                amount,
                t.getSignature(),
                t.getDate(),
                commit.getHash(),
                commit.getReplicas(),
                t.getId(),
                null,
                null,
                null);
        logger.info("T {}", t);
        jedis = jedisPool.getResource();
        jedis.rpush(PENDING_TRANSACTIONS, gson.toJson(validTransaction));
        jedis.close();
        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(validTransaction)).getBytes());
        writeCommitTransactionResponse(objOut, hash, true, validTransaction);
        logger.info("Transaction ({}, {}, {}) added to global ledger.", origin, destination, amount);
    }


    private void commitBlockRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        logger.debug("New COMMIT_BLOCK operation.");
        Commit commit = (Commit) objIn.readObject();
        BlockAndReward blockAndReward = (BlockAndReward) commit.getRequest();
        SignedTransaction reward = blockAndReward.getTransaction();
        String publicKey = blockAndReward.getBlock().getBlockHeader().getAuthor();
        jedis = jedisPool.getResource();
        String nonce = jedis.lindex(publicKey, WALLET_NONCE);
        jedis.close();
        Block block = blockAndReward.getBlock();
        logger.info("{}", gson.toJson(block));

        nonce = Integer.toString(Integer.parseInt(nonce) + 1);
        jedis = jedisPool.getResource();
        List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
        jedis.close();
        Block lastBlock = gson.fromJson(l.get(0), Block.class);
        BlockHeader lastBlockBlockHeader = lastBlock.getBlockHeader();
        byte[] lastBlockHeaderBytes = gson.toJson(lastBlockBlockHeader).getBytes();
        byte[] lastBlockHash = generateHash(lastBlockHeaderBytes, hash_algorithm);
        if (block.getBlockHeader().getPreviousHash().equals(base32.encodeAsString(lastBlockHash))) {
            jedis = jedisPool.getResource();
            List<String> removedTransactions = jedis.lpop(PENDING_TRANSACTIONS, block.getSignedTransactions().size());
            jedis.close();
            logger.info("{}", gson.toJson(removedTransactions));
            cleanPendingRewards(removedTransactions);
            addBlock(publicKey, nonce, block, reward, commit, objOut);
        } else {
            jedis = jedisPool.getResource();
            l = jedis.lrange(BLOCK_CHAIN, -2, -2);
            jedis.close();
            if (l.size() > 0) {
                BlockHeader secondLastBlockHeader = gson.fromJson(l.get(0), Block.class).getBlockHeader();
                lastBlockHeaderBytes = gson.toJson(secondLastBlockHeader).getBytes();
                lastBlockHash = generateHash(lastBlockHeaderBytes, hash_algorithm);
                if (block.getBlockHeader().getPreviousHash().equals(base32.encodeAsString(lastBlockHash))) {
                    if (lastBlock.getSignedTransactions().size() > block.getSignedTransactions().size()) {
                        logger.info("Old block has more transactions.");
                        byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                        writeCommitBlockResponse(objOut, hash, false, null);
                    } else if (lastBlock.getSignedTransactions().size() == block.getSignedTransactions().size()) {
                        if (compareProofsOfWork(block, lastBlock)) {
                            cancelReward(lastBlock.getBlockHeader().getPreviousHash());
                            jedis = jedisPool.getResource();
                            jedis.rpop(BLOCK_CHAIN, 1);
                            jedis.close();
                            addBlock(publicKey, nonce, block, reward, commit, objOut);
                        } else {
                            logger.info("Older block has better proof of work.");
                            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                            writeCommitBlockResponse(objOut, hash, false, null);
                        }
                    } else {
                        jedis = jedisPool.getResource();
                        jedis.rpop(BLOCK_CHAIN, 1);
                        jedis.close();
                        jedis = jedisPool.getResource();
                        List<String> removedTransactions = jedis.rpop(PENDING_TRANSACTIONS, block.getSignedTransactions().size() - lastBlock.getSignedTransactions().size());
                        jedis.close();
                        cleanPendingRewards(removedTransactions);
                        cancelReward(lastBlock.getBlockHeader().getPreviousHash());
                        addBlock(publicKey, nonce, block, reward, commit, objOut);
                    }
                } else {
                    logger.info("Block is too old to be registered.");
                    byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                    writeCommitBlockResponse(objOut, hash, false, null);
                }
            } else {
                logger.info("Can not replace genesis block.");
                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
                writeCommitBlockResponse(objOut, hash, false, null);
            }
        }
    }

    private void cleanPendingRewards(List<String> removedTransactions) {
        if (removedTransactions != null) {
            List<String> ids = new LinkedList<>();
            removedTransactions.forEach(t -> ids.add(gson.fromJson(t, ValidTransaction.class).getId()));
            jedis = jedisPool.getResource();
            List<String> pendingRewards = jedis.lrange(PENDING_REWARD, 0, -1);
            jedis.close();
            int count = 0;
            ListIterator<String> reverseIt = pendingRewards.listIterator();
            PendingReward reward;
            while (reverseIt.hasPrevious()) {
                reward = gson.fromJson(reverseIt.previous(), PendingReward.class);
                assert (reward != null);
                if (ids.contains(reward.getRewardId()))
                    break;
                count += 1;
            }
            jedis.rpop(PENDING_REWARD, pendingRewards.size() - count);
        }
    }

    private void cancelReward(String previousBlockHash) {
        jedis = jedisPool.getResource();
        List<String> pendingRewards = jedis.lrange(PENDING_REWARD, 0, -1);
        jedis.close();
        String rewardId = "";
        for (String pendingReward : pendingRewards) {
            PendingReward reward = gson.fromJson(pendingReward, PendingReward.class);
            if (reward.getPreviousBlockHash().equals(previousBlockHash)) {
                jedis = jedisPool.getResource();
                jedis.lrem(PENDING_TRANSACTIONS, 1, pendingReward);
                jedis.close();
                rewardId = reward.getRewardId();
                break;
            }
        }
        if (!rewardId.equals("")) {
            jedis = jedisPool.getResource();
            List<String> transactions = jedis.lrange(PENDING_TRANSACTIONS, 0, -1);
            jedis.close();
            for (String transaction : transactions) {
                ValidTransaction validTransaction = gson.fromJson(transaction, ValidTransaction.class);
                if (validTransaction.getId().equals(rewardId)) {
                    jedis = jedisPool.getResource();
                    jedis.lrem(PENDING_TRANSACTIONS, 1, transaction);
                    jedis.close();
                    break;
                }
            }
        }
    }

    private void addBlock(String publicKey, String nonce, Block block, SignedTransaction t, Commit commit, ObjectOutput objOut) throws IOException {
        jedis = jedisPool.getResource();
        jedis.lset(publicKey, WALLET_NONCE, nonce);
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(BLOCK_CHAIN, gson.toJson(block));
        jedis.close();
        ValidTransaction validReward = new ValidTransaction(
                t.getOrigin(),
                t.getDestination(),
                t.getAmount(),
                t.getSignature(),
                t.getDate(),
                commit.getHash(),
                commit.getReplicas(),
                t.getId(),
                null,
                null,
                null);
        jedis = jedisPool.getResource();
        jedis.rpush(PENDING_REWARD, gson.toJson(new PendingReward(block.getBlockHeader().getPreviousHash(), validReward.getId())));
        jedis.close();
        jedis = jedisPool.getResource();
        jedis.rpush(PENDING_TRANSACTIONS, gson.toJson(validReward));
        jedis.close();
        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(block)).concat(gson.toJson(validReward)).getBytes());
        writeCommitBlockResponse(objOut, hash, true, validReward);
        logger.info("Block added to global ledger");
    }

    private boolean compareProofsOfWork(Block block, Block lastBlock) throws NoSuchAlgorithmException {
        BlockHeader blockHeader = block.getBlockHeader();
        byte[] blockHeaderBytes = gson.toJson(blockHeader).getBytes();
        byte[] hashedBlock = generateHash(blockHeaderBytes, hash_algorithm);

        BlockHeader lastBlockHeader = lastBlock.getBlockHeader();
        byte[] lastBlockHeaderBytes = gson.toJson(lastBlockHeader).getBytes();
        byte[] hashedLastBlock = generateHash(lastBlockHeaderBytes, hash_algorithm);

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

    /******************************************** Unordered requests **************************************************/

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case GET_NONCE:
                    getNonceRequest(objIn, objOut);
                    break;
                case CURRENT_AMOUNT:
                    currentAmountRequest(objIn, objOut);
                    break;
                case GLOBAL_LEDGER:
                    globalLedgerRequest(objIn, objOut);
                    break;
                case CLIENT_LEDGER:
                    clientLedgerRequest(objIn, objOut);
                    break;
                case VERIFY:
                    verifyRequest(objIn, objOut);
                    break;
                case PICK_NOT_MINED_TRANSACTIONS:
                    pickNotMinedTransactionsRequest(objIn, objOut);
                    break;
                case OBTAIN_LAST_BLOCK:
                    obtainLastBlockRequest(objOut);
                    break;
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException | EncoderException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }


    private void getNonceRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        logger.debug("New REQUEST_NONCE operation");
        String publicKey = (String) objIn.readObject();
        jedis = jedisPool.getResource();
        if (jedis.exists(publicKey)) {
            jedis.close();
            String message = LedgerRequestType.GET_NONCE.name().concat(publicKey);
            byte[] msgSignature = (byte[]) objIn.readObject();
            if (verifySignature(publicKey, message, msgSignature)) {
                logger.info("Signature verified");
                jedis = jedisPool.getResource();
                String nonce = jedis.lindex(publicKey, WALLET_NONCE);
                jedis.close();
                byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(nonce).getBytes());
                writeGetNonceResponse(objOut, hash, true, nonce);
            } else {
                logger.info("Signature not verified");
                byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NONCE).getBytes());
                writeGetNonceResponse(objOut, hash, false, NO_NONCE);
            }
        } else {
            jedis.close();
            logger.info("Key not registered.");
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(NO_NONCE).getBytes());
            writeGetNonceResponse(objOut, hash, false, NO_NONCE);
        }
    }


    private void currentAmountRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New CURRENT_AMOUNT operation.");
        String publicKey = (String) objIn.readObject();
        jedis = jedisPool.getResource();
        if (!jedis.exists(publicKey)) {
            jedis.close();
            logger.info("Key {} not registered.", publicKey);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(new BigInteger("-1").toString()).getBytes());
            writeCurrentAmountResponse(objOut, hash, false, new BigInteger("-1"));
        } else {
            jedis.close();
            BigInteger balance = getBalance(publicKey);
            logger.info("{} coins associated with key {}.", balance, publicKey);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(balance.toString()).getBytes());
            writeCurrentAmountResponse(objOut, hash, true, balance);
        }
    }


    private void globalLedgerRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        DateInterval dateInterval = (DateInterval) objIn.readObject();
        logger.debug("New GLOBAL_LEDGER operation.");
        List<ValidTransaction> globalLedger = getPendingTransactions(dateInterval);
        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(globalLedger)).getBytes());
        objOut.writeInt(id);
        objOut.writeObject(hash);
        objOut.writeObject(globalLedger);
    }


    private void clientLedgerRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New CLIENT_LEDGER operation.");
        String publicKey = (String) objIn.readObject();
        DateInterval dateInterval = (DateInterval) objIn.readObject();
        jedis = jedisPool.getResource();
        if (!jedis.exists(publicKey)) {
            jedis.close();
            logger.info("Key {} not registered.", publicKey);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
            writeClientLedgerResponse(objOut, hash, false, null);
        } else {
            jedis.close();
            List<ValidTransaction> clientLedger = getPendingTransactions(publicKey, dateInterval);
            logger.info("Found ledger with length {} associated with key {}.", clientLedger.size(), clientLedger);
            byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(clientLedger)).getBytes());
            writeClientLedgerResponse(objOut, hash, true, clientLedger);
        }
    }


    private void verifyRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, ClassNotFoundException {
        logger.debug("New VERIFY operation.");
        String transactionId = (String) objIn.readObject();
        ValidTransaction transaction = findTransaction(transactionId);
        if (transaction != null) {
            logger.info("Transaction verified");
            byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(transaction)).getBytes());
            writeVerifyResponse(objOut, hash, true, transaction);
        } else {
            logger.info("Transaction not found.");
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).getBytes());
            writeVerifyResponse(objOut, hash, false, null);
        }
    }


    private void pickNotMinedTransactionsRequest(ObjectInput objIn, ObjectOutput objOut) throws IOException, NoSuchAlgorithmException, EncoderException {
        logger.debug("New PICK_NOT_MINED_TRANSACTIONS operation");
        int numTransactions = objIn.readInt();
        List<ValidTransaction> notMinedTransactions = getPendingTransactions(numTransactions - 1);
        if (notMinedTransactions != null) {
            logger.info("Building block header");
            jedis = jedisPool.getResource();
            List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
            jedis.close();
            byte[] lastBlockHeaderBytes = gson.toJson(gson.fromJson(l.get(0), Block.class).getBlockHeader()).getBytes();
            byte[] lastBlockHash = generateHash(lastBlockHeaderBytes, hash_algorithm);
            BlockHeader blockHeader = createBlockHeader(notMinedTransactions, base32.encodeAsString(lastBlockHash));
            byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(blockHeader)).getBytes());
            writePickNotMinedTransactionsResponse(objOut, hash, true, blockHeader);
        } else {
            logger.info("Not building block header");
            byte[] hash = TOMUtil.computeHash(Boolean.toString(false).concat(gson.toJson(null)).concat(gson.toJson(null)).getBytes());
            writePickNotMinedTransactionsResponse(objOut, hash, true, null);
        }
    }


    private BlockHeader createBlockHeader(List<ValidTransaction> notMinedTransactions, String previousHash) {
        String integrityHash = buildCumulativeHash(notMinedTransactions);
        String timeStamp = LocalDateTime.now().format(formatter);
        List<String> blockTransactions = new LinkedList<>();
        for (ValidTransaction notMinedTransaction : notMinedTransactions)
            blockTransactions.add(notMinedTransaction.getId());
        return new BlockHeader(null, previousHash, blockTransactions, integrityHash, timeStamp);
    }

    private String buildCumulativeHash(List<ValidTransaction> notMinedTransactions) {
        String finalHash = "";
        for (int i = 0; i < notMinedTransactions.size(); i++) {
            if (i == 0)
                finalHash = finalHash.concat(notMinedTransactions.get(i).getHash());
            else
                finalHash = gson.toJson(TOMUtil.computeHash(finalHash.concat(notMinedTransactions.get(i).getHash()).getBytes()));
        }
        return base32.encodeAsString(finalHash.getBytes());
    }


    private void obtainLastBlockRequest(ObjectOutput objOut) throws IOException {
        logger.info("Obtaining last block");
        jedis = jedisPool.getResource();
        List<String> l = jedis.lrange(BLOCK_CHAIN, -1, -1);
        jedis.close();
        logger.info("Sending the last block");
        Block block = gson.fromJson(l.get(0), Block.class);
        byte[] hash = TOMUtil.computeHash(Boolean.toString(true).concat(gson.toJson(block)).getBytes());
        writeReplicaDecision(objOut, hash, true);
        objOut.writeObject(block);
    }


    /************************************************ Auxiliary methods ***********************************************/

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

    private byte[] generateHash(byte[] msg, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(algorithm);
        hash.update(msg);
        return hash.digest();
    }

    private ValidTransaction findTransaction(String id) {
        jedis = jedisPool.getResource();
        List<String> blocks = jedis.lrange(BLOCK_CHAIN, 1, -1);
        jedis.close();
        for (String b : blocks) {
            Block block = gson.fromJson(b, Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction transaction : validTransactions) {
                if (transaction.getId().equals(id))
                    return transaction;
            }
        }
        return null;
    }

    private List<ValidTransaction> getPendingTransactions(int numTransactions) {
        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        List<String> serializedLedger;
        jedis = jedisPool.getResource();
        long globalLedgerSize = jedis.llen(PENDING_TRANSACTIONS);
        jedis.close();
        if (numTransactions >= 0 && globalLedgerSize > 0) {
            if (numTransactions <= globalLedgerSize) {
                jedis = jedisPool.getResource();
                serializedLedger = jedis.lrange(PENDING_TRANSACTIONS, 0, numTransactions);
                jedis.close();
            } else {
                jedis = jedisPool.getResource();
                serializedLedger = jedis.lrange(PENDING_TRANSACTIONS, 0, -1);
                jedis.close();
            }
            serializedLedger.forEach(t -> deserializedLedger.add(gson.fromJson(t, ValidTransaction.class)));
            return deserializedLedger;
        }
        return null;
    }

    private List<ValidTransaction> getPendingTransactions(DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        jedis = jedisPool.getResource();
        List<String> blocks = jedis.lrange(BLOCK_CHAIN, 1, -1);
        jedis.close();
        for (String b : blocks) {
            Block block = gson.fromJson(b, Block.class);
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

    private List<ValidTransaction> getPendingTransactions(String publicKey, DateInterval dateInterval) {
        long startDate = Timestamp.valueOf(dateInterval.getStartDate()).getTime();
        long endDate = Timestamp.valueOf(dateInterval.getEndDate()).getTime();

        List<ValidTransaction> deserializedLedger = new LinkedList<>();
        jedis = jedisPool.getResource();
        List<String> blocks = jedis.lrange(BLOCK_CHAIN, 1, -1);
        jedis.close();
        for (String b : blocks) {
            Block block = gson.fromJson(b, Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction transaction : validTransactions) {
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

    private BigInteger getBalance(String publicKey) {
        BigInteger balance = new BigInteger("0");
        jedis = jedisPool.getResource();
        if (!jedis.exists(publicKey)) {
            jedis.close();
            return new BigInteger("-1");
        }
        jedis.close();

        jedis = jedisPool.getResource();
        List<String> blockChain = jedis.lrange(BLOCK_CHAIN, 1, -1);
        jedis.close();
        for (String b : blockChain) {
            Block block = gson.fromJson(b, Block.class);
            List<ValidTransaction> validTransactions = block.getSignedTransactions();
            for (ValidTransaction t : validTransactions) {
                if (t.getOrigin().equals(publicKey))
                    balance = balance.subtract(t.getAmount());
                else if (t.getDestination().equals(publicKey))
                    balance = balance.add(t.getAmount());
            }
        }
        return balance;
    }


    /************************************************ Auxiliary Response methods **************************************/

    private void writeReplicaDecision(ObjectOutput objOut, byte[] hash, boolean decision) throws IOException {
        objOut.writeInt(id);
        objOut.writeObject(hash);
        objOut.writeBoolean(decision);
    }

    /*** Ordered requests' responses **/

    private void writeRegisterKeyResponse(ObjectOutput objOut, byte[] hash, boolean decision, Wallet wallet) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(wallet);
    }

    private void writeObtainAmountResponse(ObjectOutput objOut, byte[] hash, boolean decision, SignedTransaction signedTransaction, BigInteger amount, String date) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(signedTransaction);
        objOut.writeObject(amount);
        objOut.writeObject(date);
    }

    private void writeTransferMoneyResponse(ObjectOutput objOut, byte[] hash, boolean decision, SignedTransaction signedTransaction) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(signedTransaction);
    }

    private void writeTransferMoneyWithPrivacyResponse(ObjectOutput objOut, byte[] hash, boolean decision, SignedTransaction signedTransaction, String secretValue) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(signedTransaction);
        objOut.writeObject(secretValue);
    }

    private void writeSendMinedResponse(ObjectOutput objOut, byte[] hash, boolean decision, BlockAndReward blockAndReward) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(blockAndReward);
    }

    private void writeCommitWalletResponse(ObjectOutput objOut, byte[] hash, boolean decision) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(INITIAL_NONCE);
    }

    private void writeCommitTransactionResponse(ObjectOutput objOut, byte[] hash, boolean decision, ValidTransaction validTransaction) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(validTransaction);
    }

    private void writeCommitBlockResponse(ObjectOutput objOut, byte[] hash, boolean decision, ValidTransaction validReward) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(validReward);
    }

    /*** Unordered requests' responses **/

    private void writeGetNonceResponse(ObjectOutput objOut, byte[] hash, boolean decision, String nonce) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(nonce);
    }

    private void writeCurrentAmountResponse(ObjectOutput objOut, byte[] hash, boolean decision, BigInteger balance) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(balance);
    }

    private void writeClientLedgerResponse(ObjectOutput objOut, byte[] hash, boolean decision, List<ValidTransaction> clientLedger) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(clientLedger);
    }

    private void writeVerifyResponse(ObjectOutput objOut, byte[] hash, boolean decision, ValidTransaction transaction) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(transaction);
    }

    private void writePickNotMinedTransactionsResponse(ObjectOutput objOut, byte[] hash, boolean decision, BlockHeader blockHeader) throws IOException {
        writeReplicaDecision(objOut, hash, decision);
        objOut.writeObject(blockHeader);

    }


    /************************************************* Snapshot methods ***********************************************/

    @Override
    public void installSnapshot(byte[] bytes) {

    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
