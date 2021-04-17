package main.java.bftsmart.app.services;

import main.java.bftsmart.app.models.Transaction;
import main.java.bftsmart.app.models.operations.REST.TransferMoneyArgs;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

@Path(LedgerService.PATH)
public interface LedgerService {

    String PATH = "/wallets";

    @POST
    @Path("/{owner}/obtainCoins")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    Response obtainCoins(@PathParam("owner") String who, double amount);

    @POST
    @Path("/{owner}/transfer")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    Response transferMoney(@PathParam("owner") String from, TransferMoneyArgs transferMoneyArgs);

    @GET
    @Path("/{owner}/balance")
    @Produces(MediaType.APPLICATION_JSON)
    Response currentAmount(@PathParam("owner") String who);

    @GET
    @Path("/ledger")
    @Produces(MediaType.APPLICATION_JSON)
    Response ledgerOfGlobalTransactions();

    @GET
    @Path("/ledger/{owner}")
    @Produces(MediaType.APPLICATION_JSON)
    Response ledgerOfClientTransactions(@PathParam("owner") String who);







}
