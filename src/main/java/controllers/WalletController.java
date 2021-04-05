package main.java.controllers;

import main.java.models.Transaction;
import main.java.models.TransferMoneyArgs;
import main.java.models.Wallet;

import javax.inject.Singleton;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;


@Singleton
public class WalletController implements WalletService {

    private List<Transaction> ledger;
    private Map<String,List<Transaction>> userLedger;
    private Map<String, Wallet> wallets;

    public WalletController() {
        ledger = new LinkedList<>();
        userLedger = new HashMap<>();
    }


    @Override
    public double obtainCoins(String who, double amount) {
        Wallet wallet = wallets.get(who);
        return wallet.getBalance();
    }


    @Override
    public void transferMoney(String from, TransferMoneyArgs transferMoneyArgs) {
        Transaction transaction = new Transaction(from,transferMoneyArgs.getTo(),transferMoneyArgs.getAmount());
        ledger.add(transaction);
    }

    @Override
    public double currentAmount(String who) {
        return 100;
    }

    @Override
    public List<Transaction> ledgerOfGlobalTransactions() {
        return null;
    }

    @Override
    public List<Transaction> ledgerOfClientTransactions(String who) {
        return null;
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
