import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

import com.google.gson.Gson;
import com.proxy.controllers.LedgerRequestType;
import com.proxy.controllers.Transaction;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;


import java.io.*;
import java.security.Security;

import java.util.*;

public class BFTSmartServer extends DefaultSingleRecoverable {

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private static final String GLOBAL_LEDGER = "GLOBAL-LEDGER";
    private static final String USER_ACCOUNT = "-ACCOUNT";
    private static final String USER_LEDGER = "-LEDGER";
    private final Logger logger;
    private final Jedis jedis;
    private final Gson gson;


    public BFTSmartServer(int id) throws IOException {
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.gson = new Gson();
        Properties jedis_properties = new Properties();
        jedis_properties.load(new FileInputStream("config/jedis.config"));
        String redisPort = jedis_properties.getProperty("jedis_port").split(",")[id];
        jedis = new Jedis("redis://127.0.0.1:".concat(redisPort));
        jedis.set("test_user".concat(USER_ACCOUNT), "test_key");
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
                case OBTAIN_COINS: {
                    logger.debug("New OBTAIN_COINS operation.");
                    String user = (String) objIn.readObject();
                    if (!jedis.exists(user.concat(USER_ACCOUNT))) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        double amount = objIn.readDouble();
                        Transaction transaction = new Transaction(SYSTEM, user, amount);
                        logger.info("New transaction ({}, {}, {}).", SYSTEM, user, amount);
                        jedis.rpush(GLOBAL_LEDGER, gson.toJson(transaction));
                        logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", SYSTEM, user, amount);
                        registerUserTransaction(user, transaction);
                        objOut.writeDouble(amount);
                    }
                    break;
                }
                case TRANSFER_MONEY: {
                    logger.debug("New TRANSFER_MONEY operation.");
                    Transaction transaction = (Transaction) objIn.readObject();
                    if (!jedis.exists(transaction.getOrigin().concat(USER_ACCOUNT)) || !jedis.exists(transaction.getDestination().concat(USER_ACCOUNT))) {
                        logger.info("Bad transaction ({}, {}, {})", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                        objOut.writeBoolean(false);
                    } else {
                        logger.info("Proposed transaction ({}, {}, {}).", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                        registerUserTransaction(transaction.getOrigin(), transaction);
                        registerUserTransaction(transaction.getDestination(), transaction);
                        jedis.rpush(GLOBAL_LEDGER, gson.toJson(transaction));
                        logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                        objOut.writeBoolean(true);
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
                        double balance = getBalance(user);
                        logger.info("User {} has {} coins.", user, balance);
                        objOut.writeBoolean(true);
                        objOut.writeDouble(balance);
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
                        List<Transaction> user_ledger = getLedger(user.concat(USER_LEDGER));
                        logger.info("User {} ledger found with length {}.", user, user_ledger);
                        objOut.writeBoolean(true);
                        objOut.writeObject(user_ledger);
                    }
                    break;
                }
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private List<Transaction> getLedger(String key) {
        List<Transaction> deserialized_ledger = new LinkedList<>();
        List<String> serialized_ledger = jedis.lrange(key, 0, -1);
        serialized_ledger.forEach((transaction) -> deserialized_ledger.add(gson.fromJson(transaction, Transaction.class)));
        return deserialized_ledger;
    }

    private double getBalance(String user) {
        double balance = 0;
        if (!jedis.exists(user.concat(USER_ACCOUNT)))
            return -1;
        List<String> ledger = jedis.lrange("", 0, 1);
        for (String json_t : ledger) {
            Transaction t = gson.fromJson(json_t, Transaction.class);
            if (t.getOrigin().equals(user))
                balance -= t.getAmount();
            else if (t.getDestination().equals(user))
                balance += t.getAmount();
        }
        return balance;
    }

    private void registerUserTransaction(String user, Transaction transaction) {
        jedis.lpush(user.concat(USER_LEDGER), gson.toJson(transaction));
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
