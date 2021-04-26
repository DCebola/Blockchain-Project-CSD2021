package com.clients;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;


public class RestClient {

    private static final String REGISTER_URL = "https://localhost:8443/register/%s";
    private static final String OBTAIN_COINS_URL = "https://localhost:8443/%s/obtainCoins";
    private static final String TRANSFER_MONEY_URL = "https://localhost:8443/transferMoney";
    private static final String BALANCE_URL = "https://localhost:8443/%s/balance";
    private static final String LEDGER_OF_GLOBAL_TRANSACTIONS = "https://localhost:8443/ledger";
    private static final String LEDGER_OF_CLIENT_TRANSACTIONS = "https://localhost:8443/%s/ledger";


    private static final int REGISTER = 0;
    private static final int OBTAIN_COINS = 1;
    private static final int TRANSFER_MONEY = 2;
    private static final int CURRENT_AMOUNT = 3;
    private static final int GLOBAL_LEDGER = 4;
    private static final int CLIENT_LEDGER = 5;
    private static final int QUIT = 6;

    private static Gson gson;

    public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        gson = new Gson();
        FileInputStream is = new FileInputStream("src/main/resources/client4_keystore.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "client4Pass".toCharArray());
        String alias = "client4";
        Key privateKey = keystore.getKey(alias, "client4Pass".toCharArray());

        if (privateKey instanceof PrivateKey) {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();

            byte[] publicKeyBytes = publicKey.getEncoded();

            Signature signature = Signature.getInstance(cert.getSigAlgName());
            System.out.println(cert.getSigAlgName());
            signature.initSign((PrivateKey) privateKey, new SecureRandom());
            //System.out.println(Utils.toHex(privateKey.getEncoded()));

            byte[] message = "Hello".getBytes();

            signature.update(message);
            byte[] sigBytes = signature.sign();
            System.out.println(sigBytes.length);
            message = "Hello1".getBytes();

            //sigBytes[2] ^= '0' ^ '9';
            System.out.println(sigBytes.length);

            publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Base64 base64 = new Base64();
            String encodedString = new String(base64.encode(publicKeyBytes));



            System.out.println(Utils.toHex(publicKeyBytes));
            System.out.println("-------------------------------------");
            System.out.println(Utils.toHex(base64.decode(encodedString)));



            Gson gson = new Gson();
            //KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey))
            String publicKeyString = gson.toJson(publicKey.getEncoded());

            publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(gson.fromJson(publicKeyString,byte[].class)));


            signature.initVerify(publicKey);
            signature.update(message);
            try {
                if (signature.verify(sigBytes)) {
                    System.out.println("\nAssinatura validada - reconhecida");
                } else {
                    System.out.println("\nAssinatura nao reconhecida");
                }
            } catch (SignatureException e) {
                System.out.println("Signature not recognized");
            }

        }

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                SSLContexts.createDefault(),
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
            printOps();
            command = in.nextInt();
            switch (command) {
                case REGISTER:
                    register(requestFactory, in);
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
                    ledgerOfGlobalTransactions(requestFactory);
                    break;
                case CLIENT_LEDGER:
                    ledgerOfClientTransactions(requestFactory, in);
                    break;
            }
        }
    }

    private static KeyStore getKeyStore(String user, char[] password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream is = new FileInputStream("src/main/resources/".concat(user).concat("_keystore.jks"));
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password);
        return keystore;
    }

    private static void register(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            System.out.println("Insert username: ");
            String user = in.next();
            in.nextLine();
            System.out.println("Insert password: ");
            char[] password = in.next().toCharArray();
            in.nextLine();
            KeyStore keystore = getKeyStore(user, password);
            X509Certificate cert = (X509Certificate) keystore.getCertificate(user);

            System.out.println(Utils.toHex(cert.getPublicKey().getEncoded()));

            HttpEntity<RegisterUserMsgBody> request = new HttpEntity<>(new RegisterUserMsgBody(cert.getPublicKey().getEncoded(), cert.getSigAlgName()));
            ResponseEntity<Void> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(REGISTER_URL, user), HttpMethod.POST, request, Void.class);
            System.out.println(response.getStatusCodeValue() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void printOps() {
        System.out.println("0- Register");
        System.out.println("1- Obtain Coins");
        System.out.println("2- Transfer Money");
        System.out.println("3- Current Amount");
        System.out.println("4- Global Ledger");
        System.out.println("5- Client Ledger");
        System.out.println("6- Quit");
    }

    private static void balance(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            System.out.println("Insert user: ");
            String user = in.next();
            in.nextLine();
            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(BALANCE_URL, user), HttpMethod.GET, null, Double.class);
            System.out.println(response.getStatusCodeValue() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void transferMoney(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            System.out.println("Insert origin: ");
            String origin = in.next();
            in.nextLine();
            System.out.println("Insert destination: ");
            String destination = in.next();
            in.nextLine();
            System.out.println("Insert amount: ");
            double amount = in.nextDouble();
            Transaction t = new Transaction(origin, destination, amount);

            HttpEntity<Transaction> request = new HttpEntity<>(t);
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
            String op = "OBTAIN_COINS";
            System.out.println("Insert username: ");
            String user = in.next();
            in.nextLine();
            System.out.println("Insert password: ");
            char[] password = in.next().toCharArray();
            in.nextLine();
            System.out.println("Insert amount: ");
            double amount = in.nextDouble();
            KeyStore keystore = getKeyStore(user, password);
            X509Certificate cert = (X509Certificate) keystore.getCertificate(user);
            System.out.println(Utils.toHex(cert.getPublicKey().getEncoded()));
            Signature signature = Signature.getInstance(cert.getSigAlgName());

            PrivateKey privateKey = (PrivateKey) keystore.getKey(user,password);
            String msgToBeSigned = gson.toJson(op).concat(gson.toJson(amount));

            signature.initSign(privateKey, new SecureRandom());
            signature.update(msgToBeSigned.getBytes());
            byte[] sigBytes = signature.sign();

            SignedBody signedBody = new SignedBody(amount,sigBytes);
            System.out.println("hello1");
            HttpEntity<SignedBody> request = new HttpEntity<>(signedBody);
            System.out.println("hello1");
            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_COINS_URL, user), HttpMethod.POST, request, Double.class);
            System.out.println(response.getStatusCode() + "\n" + response.getBody());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfGlobalTransactions(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    LEDGER_OF_GLOBAL_TRANSACTIONS, HttpMethod.GET, null, Ledger.class);

            for (Transaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.println(t.getOrigin() + " " + t.getDestination() + " " + t.getAmount());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfClientTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner
            in) {
        System.out.println("Insert client: ");
        String client = in.next();
        in.nextLine();
        try {
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_CLIENT_TRANSACTIONS, client), HttpMethod.GET, null, Ledger.class);

            for (Transaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.println(t.getOrigin() + " " + t.getDestination() + " " + t.getAmount());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }

}




