package csd.wa1.controllers;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class BFTSmartServer extends DefaultSingleRecoverable {

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private Map<String, List<Transaction>> client_ledgers;
    private List<Transaction> global_ledgers;


    public BFTSmartServer(int id) {
        this.client_ledgers = new TreeMap<>();
        this.global_ledgers = new LinkedList<>();
        new ServiceReplica(id,this,this);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: demo.map.MapServer <server id>");
            System.exit(-1);
        }
        Security.addProvider(new BouncyCastleProvider()); //Added bouncy castle provider
        new BFTSmartServer(Integer.parseInt(args[0]));
    }

    @SuppressWarnings("unchecked")
    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            System.out.println("Hello");
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            LedgerRequestType reqType = (LedgerRequestType) objIn.readObject();
            switch (reqType) {
                case OBTAIN_COINS:
                    System.out.println("Hi");
                    String who = (String) objIn.readObject();
                    double amount = objIn.readDouble();
                    System.out.println("Who: " + who + "\nAmount: " + amount);
                    Transaction t = new Transaction(SYSTEM, who, amount);
                    global_ledgers.add(t);
                    List<Transaction> c_ledgers = client_ledgers.get(who);
                    if (c_ledgers == null) {
                        c_ledgers = new LinkedList<>();
                        c_ledgers.add(t);
                        client_ledgers.put(who, c_ledgers);
                    }
                    c_ledgers.add(t);
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
            return ERROR_MSG.getBytes();
        }
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
