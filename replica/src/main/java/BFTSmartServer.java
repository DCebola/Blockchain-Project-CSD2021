import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;

import com.proxy.controllers.LedgerRequestType;
import com.proxy.controllers.Transaction;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.*;
import java.security.Security;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
public class BFTSmartServer extends DefaultSingleRecoverable {

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private final Logger logger;
    private final Map<String, List<Transaction>> client_ledgers;
    private final List<Transaction> global_ledgers;


    public BFTSmartServer(int id) {

        this.client_ledgers = new TreeMap<>();
        this.global_ledgers = new LinkedList<>();
        this.logger = LoggerFactory.getLogger("Replica " + id);
        new ServiceReplica(id, this, this);
    }

    public static void main(String[] args) {
        if (args.length == 1) {
            Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
            new BFTSmartServer(Integer.parseInt(args[0]));
        } else
            System.out.println("Usage: demo.map.MapServer <server id>");

    }

    @SuppressWarnings("unchecked")
    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            System.out.println("Hi------------------------------------------------------------");
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case OBTAIN_COINS: {
                    System.out.println("Hi-------------------------------Again-----------------------------");
                    logger.debug("New OBTAIN_COINS operation.");
                    String user = (String) objIn.readObject();
                    double amount = objIn.readDouble();
                    Transaction new_transaction = new Transaction(SYSTEM, user, amount);
                    logger.info("New transaction ({}, {}, {}).", SYSTEM, user, amount);
                    global_ledgers.add(new_transaction);
                    logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", SYSTEM, user, amount);
                    registerUserTransaction(user, new_transaction);
                    objOut.writeDouble(amount);
                    break;
                }
                case TRANSFER_MONEY: {
                    logger.debug("New TRANSFER_MONEY operation.");
                    Transaction transaction = (Transaction) objIn.readObject();
                    logger.info("Proposed transaction ({}, {}, {}).", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                    registerUserTransaction(transaction.getOrigin(), transaction);
                    registerUserTransaction(transaction.getDestination(), transaction);
                    global_ledgers.add(transaction);
                    logger.debug("Transaction ({}, {}, {}) added to the global ledgers.", transaction.getOrigin(), transaction.getDestination(), transaction.getAmount());
                    objOut.writeBoolean(true);
                    break;
                }
                case CURRENT_AMOUNT: {
                    logger.debug("New CURRENT_AMOUNT operation.");
                    String user = (String) objIn.readObject();
                    double balance = getBalance(user);
                    if (balance < 0) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
                        logger.info("User {} has {} coins.", user, balance);
                        objOut.writeBoolean(true);
                        objOut.writeDouble(balance);
                    }
                    break;
                }
                case GLOBAL_LEDGER:
                    logger.debug("New GLOBAL_LEDGER operation.");
                    objOut.writeObject(global_ledgers);
                    break;
                case CLIENT_LEDGER: {
                    logger.debug("New CLIENT_LEDGER operation.");
                    String user = (String) objIn.readObject();
                    List<Transaction> user_ledger = client_ledgers.get(user);
                    if (user_ledger == null) {
                        logger.info("User {} does not exist", user);
                        objOut.writeBoolean(false);
                    } else {
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
            System.out.println("hiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii1");
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    private double getBalance(String user) {
        double balance = 0;
        List<Transaction> ledger = client_ledgers.get(user);
        if (ledger == null)
            return -1;
        for (Transaction t : ledger) {
            if (t.getOrigin().equals(user))
                balance -= t.getAmount();
            else if (t.getDestination().equals(user))
                balance += t.getAmount();
        }
        return balance;
    }

    //TODO: Exploitable for transactions from the system!!!
    private void registerUserTransaction(String user, Transaction transaction) {
        List<Transaction> c_ledgers = client_ledgers.get(user);
        if (c_ledgers == null) {
            c_ledgers = new LinkedList<>();
            client_ledgers.put(user, c_ledgers);
            logger.debug("First transaction of user {} added to personal ledger.", user);
        }
        c_ledgers.add(transaction);
        logger.debug("Transaction of user {} added to personal ledger.", user);
    }

    @SuppressWarnings("unchecked")
    @Override
    public byte[] appExecuteUnordered(byte[] bytes, MessageContext messageContext) {
        return new byte[0];
    }


    @SuppressWarnings("unchecked")
    @Override
    public void installSnapshot(byte[] bytes) {

    }

    @SuppressWarnings("unchecked")
    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
