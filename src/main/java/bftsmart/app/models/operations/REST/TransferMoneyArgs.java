package main.java.bftsmart.app.models.operations.REST;

public class TransferMoneyArgs {

    private final String to;
    private final double amount;

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
