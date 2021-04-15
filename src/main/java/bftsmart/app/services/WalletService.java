package main.java.bftsmart.app.services;

import main.java.bftsmart.app.models.Transaction;
import main.java.bftsmart.app.models.TransferMoneyArgs;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;

@Path(WalletService.PATH)
public interface WalletService {

    String PATH = "/wallets";

    @POST
    @Path("/{owner}/obtainCoins")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    double obtainCoins(@PathParam("owner") String who, double amount);

    @POST
    @Path("/{owner}/transfer")
    @Consumes(MediaType.APPLICATION_JSON)
    void transferMoney(@PathParam("owner") String from, TransferMoneyArgs transferMoneyArgs);

    @GET
    @Path("/{owner}/balance")
    @Produces(MediaType.APPLICATION_JSON)
    double currentAmount(@PathParam("owner") String who);

    @GET
    @Path("/ledger")
    @Produces(MediaType.APPLICATION_JSON)
    List<Transaction> ledgerOfGlobalTransactions();

    @GET
    @Path("/ledger/{owner}")
    @Produces(MediaType.APPLICATION_JSON)
    List<Transaction> ledgerOfClientTransactions(@PathParam("owner") String who);







}
