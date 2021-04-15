package main.java.bftsmart.app.models;

public class TransferMoneyArgs {

    private String to;
    private double amount;

    public TransferMoneyArgs(String from, String to, double amount) {
        this.to = to;
        this.amount = amount;

    }

    public String getTo() {
        return to;
    }

    public double getAmount() {
        return amount;
    }
}
