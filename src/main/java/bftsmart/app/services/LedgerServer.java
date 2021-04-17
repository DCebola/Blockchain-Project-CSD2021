package main.java.bftsmart.app.services;

import main.java.bftsmart.app.counter.Test;
import main.java.bftsmart.app.map.MapRequestType;
import main.java.bftsmart.app.map.MapServer;
import main.java.bftsmart.app.models.Transaction;
import main.java.bftsmart.app.models.operations.bftsmart.LedgerRequestType;
import main.java.bftsmart.tom.MessageContext;
import main.java.bftsmart.tom.ServiceReplica;
import main.java.bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LedgerServer extends DefaultSingleRecoverable {

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private Map<String, List<Transaction>> client_ledgers;
    private List<Transaction> global_ledgers;

    private final Logger logger;

    public LedgerServer(int id) {
        this.client_ledgers = new TreeMap<>();
        this.global_ledgers = new LinkedList<>();
        this.logger = Logger.getLogger(LedgerServer.class.getName());
        new ServiceReplica(id, this, this);
    }


    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: main.java.bftsmart.app.services.LedgerServer <server id>");
            System.exit(-1);
        }
        Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
        new MapServer<String, String>(Integer.parseInt(args[0]));
    }

    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext msgCtx) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case OBTAIN_COINS:
                    String who = (String) objIn.readObject();
                    double amount = (double) objIn.readObject();
                    Transaction t = new Transaction(SYSTEM, who, amount);
                    global_ledgers.add(t);
                    List<Transaction> c_ledgers = client_ledgers.get(who);
                    if (c_ledgers == null) {
                        c_ledgers = new LinkedList<>();
                        c_ledgers.add(t);
                        client_ledgers.put(who, c_ledgers);
                    }
                    c_ledgers.add(t);
                    logger.info(String.format("Created transaction (%s, %s, %f)", t.getOrigin(), t.getDestination(), t.getAmount()));
                    objOut.writeDouble(amount);
                    break;
                case TRANSFER_MONEY:
                    break;
                case CURRENT_AMOUNT:
                    break;
                case GLOBAL_LEDGER:
                    break;
                case CLIENT_LEDGER:
                    break;
            }
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();

        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Occurred during operation execution", e);
            return ERROR_MSG.getBytes();
        }
    }

    private double getBalance(List<Transaction> transactions, String who) {
        double balance = 0;
        for (Transaction t : transactions) {
            if (t.getOrigin().equals(who))
                balance -= t.getAmount();
            else if (t.getDestination().equals(who))
                balance += t.getAmount();
        }
        return balance;
    }

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext msgCtx) {
        return new byte[0];
    }

    @Override
    public void installSnapshot(byte[] state) {

    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
