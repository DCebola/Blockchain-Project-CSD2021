package main.java.bftsmart.app.models;

public class User {

    private String userID;
    private String password;
    private String username;
    private Wallet wallet;

    public User(String userID, String password, String username, Wallet wallet) {
        this.userID = userID;
        this.password = password;
        this.username = username;
        this.wallet = wallet;
    }




}
