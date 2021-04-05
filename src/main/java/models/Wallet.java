package main.java.models;

public class Wallet {

    private int balance;
    private String username;
    private String pwd;

    public Wallet(int balance, String username, String pwd) {
        this.balance = balance;
        this.username = username;
        this.pwd = pwd;
    }

    public void setBalance(int balance) {
        this.balance = balance;
    }

    public int getBalance() {
        return balance;
    }

    public String getUsername() {
        return username;
    }

    public String getPwd() {
        return pwd;
    }
}
