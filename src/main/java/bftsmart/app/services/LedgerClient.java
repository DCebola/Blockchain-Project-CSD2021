package main.java.bftsmart.app.services;

import main.java.bftsmart.app.models.operations.REST.ObtainCoinsResponse;
import main.java.bftsmart.app.models.operations.REST.TransferMoneyArgs;
import main.java.bftsmart.app.models.operations.bftsmart.LedgerRequestType;
import main.java.bftsmart.tom.ServiceProxy;

import javax.inject.Singleton;
import javax.ws.rs.core.Response;
import java.io.*;


@Singleton
public class LedgerClient implements LedgerService {

    ServiceProxy serviceProxy;

    public LedgerClient(int clientId) {
        serviceProxy = new ServiceProxy(clientId);
    }

    public LedgerClient() {
        serviceProxy = null;
    }


    @Override
    public Response obtainCoins(String who, double amount) {
        try {
            System.out.println("Who: " + who + "\nAmount: " + amount);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(LedgerRequestType.OBTAIN_COINS);
            objOut.writeObject(who);
            objOut.writeDouble(amount);
            objOut.flush();
            byteOut.flush();
            System.out.println("Helllllllo");
            byte[] reply = serviceProxy.invokeOrdered(byteOut.toByteArray());

            ByteArrayInputStream byteIn = new ByteArrayInputStream(reply);
            ObjectInput objIn = new ObjectInputStream(byteIn);

            return Response
                    .status(Response.Status.OK)
                    .entity(new ObtainCoinsResponse(objIn.readDouble()))
                    .build();

        } catch (IOException e) {
            System.out.println("Exception in obtain coins op: " + e.getMessage());
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("Bad request.")
                    .build();
        }
    }


    @Override
    public Response transferMoney(String from, TransferMoneyArgs transferMoneyArgs) {
        return Response
                .status(Response.Status.OK)
                .entity("")
                .build();
    }

    @Override
    public Response currentAmount(String who) {
        return Response
                .status(Response.Status.OK)
                .entity("")
                .build();
    }

    @Override
    public Response ledgerOfGlobalTransactions(double amount) {
        return Response
                .status(Response.Status.OK)
                .entity(amount)
                .build();
    }

    @Override
    public Response ledgerOfClientTransactions(String who) {
        return Response
                .status(Response.Status.OK)
                .entity("")
                .build();
    }

    /*
    @Override
    public double currentAmount(String who) {
        System.out.println("current amount: " + who);
        return 100;
    }

    @Override
    public List<Transaction> ledgerOfGlobalTransactions() {
        System.out.println("ledgers");
        return null;
    }

    @Override
    public List<Transaction> ledgerOfClientTransactions(String who) {
        System.out.println("ledgers");
        return null;
    }*/
}
