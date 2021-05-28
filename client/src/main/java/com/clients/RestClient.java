package com.clients;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.Scanner;


public class RestClient {

    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";

    private static final String REGISTER_URL = "https://127.0.0.1:%s/register/%s";
    private static final String OBTAIN_COINS_URL = "https://127.0.0.1:%s/%s/obtainCoins";
    private static final String TRANSFER_MONEY_URL = "https://127.0.0.1:%s/transferMoney";
    private static final String BALANCE_URL = "https://127.0.0.1:%s/%s/balance";
    private static final String LEDGER_OF_GLOBAL_TRANSACTIONS_URL = "https://127.0.0.1:%s/ledger";
    private static final String LEDGER_OF_CLIENT_TRANSACTIONS_URL = "https://127.0.0.1:%s/%s/ledger";
    private static final String REQUEST_NONCE_URL = "https://127.0.0.1:%s/nonce/%s";
    private static final String VERIFY_OPERATION = "https://127.0.0.1:%s/verifyOp";

    private static final int REGISTER = 0;
    private static final int REQUEST_NONCE = 1;
    private static final int OBTAIN_COINS = 2;
    private static final int TRANSFER_MONEY = 3;
    private static final int CURRENT_AMOUNT = 4;
    private static final int GLOBAL_LEDGER = 5;
    private static final int CLIENT_LEDGER = 6;
    private static final int VERIFY_OP = 7;
    private static final int QUIT = 8;

    private static final String HASH_ALGORITHM = "SHA-256";


    private static Gson gson;
    private static Base64 base64;
    private static Session currentSession;
    private static String port = "9001";
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(DATE_FORMATTER);

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, KeyManagementException, SignatureException, InvalidKeyException {
        if (args.length > 0)
            port = args[0];

        Security.addProvider(new BouncyCastleProvider());
        gson = new Gson();
        base64 = new Base64(true);
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
                case REQUEST_NONCE:
                    requestNonce(requestFactory, in);
                    break;
                case OBTAIN_COINS:
                    callObtainCoins(requestFactory, in);
                    break;
                case TRANSFER_MONEY:
                    transferMoney(requestFactory, in);
                    break;
                case CURRENT_AMOUNT:
                    balance(requestFactory);
                    break;
                case GLOBAL_LEDGER:
                    ledgerOfGlobalTransactions(requestFactory);
                    break;
                case CLIENT_LEDGER:
                    ledgerOfClientTransactions(requestFactory, in);
                    break;
                case VERIFY_OP:
                    verifyOp(requestFactory);
                    break;
                case QUIT:
                    in.close();
                    break;
                default:
                    command = QUIT;
                    in.close();
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
        System.out.println("1 - Request Nonce");
        System.out.println("2 - Obtain Coins");
        System.out.println("3 - Transfer Money");
        System.out.println("4 - Current Amount");
        System.out.println("5 - Global Ledger");
        System.out.println("6 - Client Ledger");
        System.out.println("7 - Verify op");
        System.out.println("8 - Quit");
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
            setSession(in);
            HttpEntity<RegisterKeyMsgBody> request = new HttpEntity<>(new RegisterKeyMsgBody(currentSession.getPublicKey().getEncoded(),
                    currentSession.getSigAlg(), currentSession.getPublicKey().getAlgorithm(), currentSession.getHashAlgorithm()));
            ResponseEntity<String> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(REGISTER_URL, port, base64.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, String.class);
            System.out.println(response.getStatusCodeValue() + "\n");
            String nonce = response.getBody();
            System.out.println("Nonce: " + nonce);
            currentSession.setNonce(nonce);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void requestNonce(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        setSession(in);
        String msgToBeHashed = gson.toJson(LedgerRequestType.GET_NONCE.name().concat(base64.encodeAsString(currentSession.getPublicKey().getEncoded())));
        byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

        SignedBody<String> signedBody = new SignedBody<>("", sigBytes, null);
        HttpEntity<SignedBody<String>> request = new HttpEntity<>(signedBody);
        ResponseEntity<String> response
                = new RestTemplate(requestFactory).exchange(
                String.format(REQUEST_NONCE_URL, port, base64.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, String.class);
        String nonce = response.getBody();
        System.out.println("Nonce: " + nonce);
        currentSession.setNonce(nonce);
    }


    private static void balance(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(BALANCE_URL, port, base64.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.GET, null, Double.class);

            if (response.getStatusCode().is2xxSuccessful())
                System.out.println("Balance: " + response.getBody());

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void callObtainCoins(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);

            System.out.print("Insert amount: ");
            double amount = in.nextDouble();
            String msgToBeHashed = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount).concat(currentSession.getNonce()).concat(currentDate));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Double> signedBody = new SignedBody<>(amount, sigBytes, currentDate);
            HttpEntity<SignedBody<Double>> request = new HttpEntity<>(signedBody);

            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_COINS_URL, port, base64.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, ValidTransaction.class);
            System.out.println(response.getStatusCode() + "\n" + response.getBody());
            if (response.getStatusCode().is2xxSuccessful()) {
                currentSession.setNonce(Integer.toString(Integer.parseInt(currentSession.getNonce()) + 1));
                System.out.println("New Nonce: " + currentSession.getNonce());
                System.out.println(gson.toJson(response.getBody()));
                currentSession.setLastOp(gson.toJson(response.getBody()));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void transferMoney(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {

        try {
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);
            System.out.print("Insert destination: ");
            String destination = in.next();
            in.nextLine();
            System.out.print("Insert amount: ");
            double amount = in.nextDouble();

            Transaction t = new Transaction(base64.encodeAsString(currentSession.getPublicKey().getEncoded()), destination, amount, currentDate);
            String msgToBeHashed = gson.toJson(LedgerRequestType.TRANSFER_MONEY.name()).concat(gson.toJson(t).concat(currentSession.getNonce()).concat(currentDate));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Transaction> signedBody = new SignedBody<>(t, sigBytes, currentDate);
            HttpEntity<SignedBody<Transaction>> request = new HttpEntity<>(signedBody);


            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(TRANSFER_MONEY_URL, port), HttpMethod.POST, request, ValidTransaction.class);
            System.out.println(response.getStatusCodeValue());
            if (response.getStatusCode().is2xxSuccessful()) {
                currentSession.setNonce(Integer.toString(Integer.parseInt(currentSession.getNonce()) + 1));
                System.out.println(currentSession.getNonce());
                System.out.println(gson.toJson(response.getBody()));
                currentSession.setLastOp(gson.toJson(response.getBody()));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfGlobalTransactions(HttpComponentsClientHttpRequestFactory requestFactory) {
        String start = "2021-05-17 00:16:00";
        String end = "2021-05-17 00:17:52";
        DateInterval dateInterval = new DateInterval(start, end);
        HttpEntity<DateInterval> request = new HttpEntity<>(dateInterval);
        try {
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_GLOBAL_TRANSACTIONS_URL, port), HttpMethod.POST, request, Ledger.class);

            for (ValidTransaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.println(gson.toJson(t));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfClientTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        String start = "2021-05-17 00:16:00";
        String end = "2021-05-17 00:17:52";
        DateInterval dateInterval = new DateInterval(start, end);
        HttpEntity<DateInterval> request = new HttpEntity<>(dateInterval);
        try {
            if (currentSession == null)
                setSession(in);
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_CLIENT_TRANSACTIONS_URL, port, base64.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, Ledger.class);

            for (ValidTransaction t : Objects.requireNonNull(response.getBody()).getTransactions())
                System.out.println(gson.toJson(t));

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void verifyOp(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            if (currentSession != null && !currentSession.getLastOp().equals("")) {
                //TODO: Use ID for verification
                HttpEntity<String> request = new HttpEntity<>(currentSession.getLastOp());
                ResponseEntity<SignedTransaction> response
                        = new RestTemplate(requestFactory).exchange(
                        String.format(VERIFY_OPERATION, port), HttpMethod.POST, request, SignedTransaction.class);

                SignedTransaction t = response.getBody();
                if (t != null)
                    System.out.println(t.getOrigin() + " " + t.getDestination() + " " + t.getAmount() + " " + t.getSignature());
                else
                    System.out.println("No operation returned");


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
        private String nonce;
        private String lastOp;

        public Session(String username, char[] password) throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
            this.nonce = "";
            this.username = username;
            this.password = password;
            KeyStore keystore = getKeyStore(username, password);
            X509Certificate cert = (X509Certificate) keystore.getCertificate(username);
            this.publicKey = cert.getPublicKey();
            this.privateKey = (PrivateKey) keystore.getKey(username, password);
            this.sigAlg = cert.getSigAlgName();
            this.hashAlgorithm = HASH_ALGORITHM;
            this.lastOp = "";
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

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getLastOp() {
            return lastOp;
        }

        public void setLastOp(String lastOp) {
            this.lastOp = lastOp;
        }

    }
}




