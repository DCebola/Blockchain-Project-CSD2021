package com.clients;

import com.google.gson.Gson;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Scanner;


public class RestClient {

    private static final String REGISTER_URL = "https://127.0.0.1:9001/register/%s";
    private static final String OBTAIN_COINS_URL = "https://127.0.0.1:9001/%s/obtainCoins";
    private static final String TRANSFER_MONEY_URL = "https://127.0.0.1:9001/transferMoney";
    private static final String BALANCE_URL = "https://127.0.0.1:9001/%s/balance";
    private static final String LEDGER_OF_GLOBAL_TRANSACTIONS = "https://127.0.0.1:9001/ledger";
    private static final String LEDGER_OF_CLIENT_TRANSACTIONS = "https://127.0.0.1:9001/%s/ledger";


    private static final int REGISTER = 0;
    private static final int INIT_SESSION = 1;
    private static final int OBTAIN_COINS = 2;
    private static final int TRANSFER_MONEY = 3;
    private static final int CURRENT_AMOUNT = 4;
    private static final int GLOBAL_LEDGER = 5;
    private static final int CLIENT_LEDGER = 6;
    private static final int QUIT = 7;

    private static final String HASH_ALGORITHM = "SHA-256";


    private static Gson gson;
    private static Session currentSession;

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, KeyManagementException {
        Security.addProvider(new BouncyCastleProvider());
        gson = new Gson();
        SSLContextBuilder builder = new SSLContextBuilder();
        KeyStore ksTrust = KeyStore.getInstance(KeyStore.getDefaultType());
        ksTrust.load(new FileInputStream("src/main/resources/truststore.jks"), "truststorePass".toCharArray());
        builder.loadTrustMaterial(ksTrust, new TrustSelfSignedStrategy());
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                builder.build(),
                new String[]{"TLSv1.3"},
                new String[]{"TLS_AES_256_GCM_SHA384"},
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());

        CloseableHttpClient httpClient
                = HttpClients.custom()
                .setSSLHostnameVerifier(new NoopHostnameVerifier())
                .setSSLSocketFactory(sslsf)
                .build();
        HttpComponentsClientHttpRequestFactory requestFactory
                = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        Scanner in = new Scanner(System.in);
        int command = -1;
        while (command != QUIT) {
            printSession();
            printOps();
            command = in.nextInt();
            switch (command) {
                case REGISTER:
                    register(requestFactory, in);
                    break;
                case INIT_SESSION:
                    setSession(in);
                    break;
                case OBTAIN_COINS:
                    callObtainCoins(requestFactory, in);
                    break;
                case TRANSFER_MONEY:
                    transferMoney(requestFactory, in);
                    break;
                case CURRENT_AMOUNT:
                    balance(requestFactory, in);
                    break;
                case GLOBAL_LEDGER:
                    ledgerOfGlobalTransactions(requestFactory, in);
                    break;
                case CLIENT_LEDGER:
                    ledgerOfClientTransactions(requestFactory, in);
                    break;
            }
        }
    }

    private static void setSession(Scanner in) {
        System.out.print("Insert username: ");
        String user = in.next();
        in.nextLine();
        System.out.print("Insert password: ");
        char[] password = in.next().toCharArray();
        in.nextLine();
        try {
            currentSession = new Session(user, password);
        } catch (UnrecoverableKeyException | CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void printSession() {
        if (currentSession == null)
            System.out.println("[No session active]");
        else
            System.out.println("[Current session: " + currentSession.getUsername() + "]");
    }

    private static void printOps() {
        System.out.println("0 - Register");
        System.out.println("1 - Change Session");
        System.out.println("2 - Obtain Coins");
        System.out.println("3 - Transfer Money");
        System.out.println("4 - Current Amount");
        System.out.println("5 - Global Ledger");
        System.out.println("6 - Client Ledger");
        System.out.println("7 - Quit");
        System.out.print("> ");
    }

    private static KeyStore getKeyStore(String user, char[] password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream is = new FileInputStream("src/main/resources/".concat(user).concat("_keystore.jks"));
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password);
        return keystore;
    }

    private static void register(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            HttpEntity<RegisterUserMsgBody> request = new HttpEntity<>(new RegisterUserMsgBody(currentSession.getPublicKey().getEncoded(),
                    currentSession.getSigAlg(), currentSession.getPublicKey().getAlgorithm(), currentSession.getHashAlgorithm()));
            ResponseEntity<Void> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(REGISTER_URL, currentSession.getUsername()), HttpMethod.POST, request, Void.class);
            System.out.println(response.getStatusCodeValue() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void balance(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            String msgToBeHashed = gson.toJson(LedgerRequestType.CURRENT_AMOUNT.name());
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<String> signedBody = new SignedBody<>("", sigBytes);
            HttpEntity<SignedBody<String>> request = new HttpEntity<>(signedBody);
            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(BALANCE_URL, currentSession.getUsername()), HttpMethod.POST, request, Double.class);
            System.out.println(response.getStatusCodeValue() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void transferMoney(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            System.out.print("Insert destination: ");
            String destination = in.next();
            in.nextLine();
            System.out.print("Insert amount: ");
            double amount = in.nextDouble();

            Transaction t = new Transaction(currentSession.username, destination, amount);
            String msgToBeHashed = gson.toJson(LedgerRequestType.TRANSFER_MONEY.name()).concat(gson.toJson(t));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Transaction> signedBody = new SignedBody<>(t, sigBytes);
            HttpEntity<SignedBody<Transaction>> request = new HttpEntity<>(signedBody);


            ResponseEntity<Void> response
                    = new RestTemplate(requestFactory).exchange(
                    TRANSFER_MONEY_URL, HttpMethod.POST, request, Void.class);
            System.out.println(response.getStatusCodeValue());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void callObtainCoins(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            System.out.print("Insert amount: ");
            double amount = in.nextDouble();
            String msgToBeHashed = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Double> signedBody = new SignedBody<>(amount, sigBytes);
            HttpEntity<SignedBody<Double>> request = new HttpEntity<>(signedBody);

            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_COINS_URL, currentSession.getUsername()), HttpMethod.POST, request, Double.class);
            System.out.println(response.getStatusCode() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void ledgerOfGlobalTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    LEDGER_OF_GLOBAL_TRANSACTIONS, HttpMethod.GET, null, Ledger.class);

            for (SignedTransaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.println(t.getOrigin() + " " + t.getDestination() + " " + t.getAmount() + " " + t.getSignature());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfClientTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                setSession(in);
            String msgToBeHashed = gson.toJson(LedgerRequestType.CLIENT_LEDGER.name());
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<String> signedBody = new SignedBody<>("", sigBytes);
            HttpEntity<SignedBody<String>> request = new HttpEntity<>(signedBody);
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_CLIENT_TRANSACTIONS, currentSession.getUsername()), HttpMethod.POST, request, Ledger.class);

            for (SignedTransaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.println(t.getOrigin() + " " + t.getDestination() + " " + t.getAmount() + " " + t.getSignature());
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }


    }

    private static byte[] generateSignature(byte[] msg) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(currentSession.getSigAlg());
        signature.initSign(currentSession.getPrivateKey(), new SecureRandom());
        signature.update(msg);
        return signature.sign();
    }

    private static byte[] generateHash(byte[] msg) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance(currentSession.getHashAlgorithm());
        hash.update(msg);
        return hash.digest();
    }

    private static class Session {
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final String sigAlg;
        private final String hashAlgorithm;
        private final String username;
        private final char[] password;

        public Session(String username, char[] password) throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
            this.username = username;
            this.password = password;
            KeyStore keystore = getKeyStore(username, password);
            X509Certificate cert = (X509Certificate) keystore.getCertificate(username);
            this.publicKey = cert.getPublicKey();
            this.privateKey = (PrivateKey) keystore.getKey(username, password);
            this.sigAlg = cert.getSigAlgName();
            this.hashAlgorithm = HASH_ALGORITHM;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public String getSigAlg() {
            return sigAlg;
        }

        public String getUsername() {
            return username;
        }

        public char[] getPassword() {
            return password;
        }

        public String getHashAlgorithm() {
            return hashAlgorithm;
        }
    }
}




