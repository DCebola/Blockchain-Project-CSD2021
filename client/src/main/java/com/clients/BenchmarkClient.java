package com.clients;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base32;
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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

public class BenchmarkClient {
    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";
    private static final String GENESIS_DATE = "2021-01-01 01:01:01";
    private static final String PROOF_OF_WORK_CHALLENGE = "0000000000000000";
    private static final String SYSTEM = "SYSTEM";

    private static final String REGISTER_URL = "https://127.0.0.1:%s/register/%s";
    private static final String OBTAIN_COINS_URL = "https://127.0.0.1:%s/%s/obtainCoins";
    private static final String TRANSFER_MONEY_URL = "https://127.0.0.1:%s/transferMoney";
    private static final String BALANCE_URL = "https://127.0.0.1:%s/%s/balance";
    private static final String LEDGER_OF_GLOBAL_TRANSACTIONS_URL = "https://127.0.0.1:%s/ledger";
    private static final String LEDGER_OF_CLIENT_TRANSACTIONS_URL = "https://127.0.0.1:%s/%s/ledger";
    private static final String REQUEST_NONCE_URL = "https://127.0.0.1:%s/nonce/%s";
    private static final String VERIFY_OPERATION = "https://127.0.0.1:%s/verify/%s";
    private static final String OBTAIN_LAST_BLOCK_URL = "https://127.0.0.1:%s/lastBlock";
    private static final String MINE_TRANSACTIONS_URL = "https://127.0.0.1:%s/pendingTransactions/%s";
    private static final String SEND_MINED_BLOCK_URL = "https://127.0.0.1:%s/mine";

    private static final String REGISTER = "REGISTER";
    private static final String REQUEST_NONCE = "REQUEST_NONCE";
    private static final String OBTAIN_COINS = "OBTAIN_COINS";
    private static final String TRANSFER_MONEY = "TRANSFER_MONEY";
    private static final String CURRENT_AMOUNT = "CURRENT_AMOUNT";
    private static final String GLOBAL_LEDGER = "GLOBAL_LEDGER";
    private static final String CLIENT_LEDGER = "CLIENT_LEDGER";
    private static final String VERIFY_OP = "VERIFY_OP";
    private static final String OBTAIN_LAST_BLOCK = "OBTAIN_LAST_BLOCK";
    private static final String MINE_TRANSACTIONS = "MINE_TRANSACTIONS";
    private static final String SEND_MINED_BLOCK = "SEND_MINED_BLOCK";
    private static final String QUIT = "QUIT";

    private static final String CLIENT_1 = "client1";
    private static final String CLIENT_1_PASS = "client1Pass";
    private static final String CLIENT = "client";
    private static final String PASS = "Pass";

    private static final String ALL = "ALL";
    private static final String UP_TO = "UP_TO";
    private static final String IN_BETWEEN = "IN_BETWEEN";

    private static final String HASH_ALGORITHM = "SHA-256";

    /*
    REQUEST_NONCE
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS 200
    OBTAIN_COINS
    MINE_TRANSACTIONS 2
    TRANSFER_MONEY 200
    GLOBAL_LEDGER ALL
    GLOBAL_LEDGER UP_TO 2022-01-01,01:01:01
    GLOBAL_LEDGER IN_BETWEEN 2021-01-01,01:01:01 2022-01-01,01:01:01
    CLIENT_LEDGER IN_BETWEEN 2021-01-01,01:01:01 2022-01-01,01:01:01
    CLIENT_LEDGER ALL
    CLIENT_LEDGER UP_TO 2022-01-01,01:01:01
    OBTAIN_LAST_BLOCK
     */


    private static Gson gson;
    private static Base32 base32;
    private static BenchmarkClient.Session currentSession;
    private static String port = "9001";
    private static DateTimeFormatter dateTimeFormatter;

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, KeyManagementException, SignatureException, InvalidKeyException {
        port = args[0];
        String client = "";
        char[] clientPassword = null;
        if(args.length > 2) {
            client = args[2];
            clientPassword = args[3].toCharArray();
        }

        Security.addProvider(new BouncyCastleProvider());
        gson = new Gson();
        base32 = new Base32();
        dateTimeFormatter = DateTimeFormatter.ofPattern(DATE_FORMATTER);
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

        BufferedReader buf = new BufferedReader(new FileReader("src/main/resources/".concat(args[1])));

        String line = buf.readLine();
        while(line != null) {
            String[] opInfo = line.split(" ");
            switch (opInfo[0]) {
                case REGISTER:
                    register(requestFactory,opInfo[1], opInfo[2].toCharArray());
                    break;
                case REQUEST_NONCE:
                    requestNonce(requestFactory,client, clientPassword);
                    break;
                case OBTAIN_COINS:
                    callObtainCoins(requestFactory, Double.parseDouble(opInfo[1]));
                    break;
                case TRANSFER_MONEY:
                    transferMoney(requestFactory, Double.parseDouble(opInfo[1]));
                    break;
                case CURRENT_AMOUNT:
                    balance(requestFactory);
                    break;
                case GLOBAL_LEDGER:
                    ledgerOfGlobalTransactions(requestFactory, opInfo);
                    break;
                case CLIENT_LEDGER:
                    ledgerOfClientTransactions(requestFactory, opInfo);
                    break;
                case VERIFY_OP:
                    verify(requestFactory, in);
                    break;
                case OBTAIN_LAST_BLOCK:
                    obtainLastBlock(requestFactory);
                    break;
                case MINE_TRANSACTIONS:
                    mineTransactions(requestFactory, Integer.parseInt(opInfo[1]));
                    break;
            }
            line = buf.readLine();
        }
    }

    private static void setSession(String client, char[] password) {
        try {
            currentSession = new BenchmarkClient.Session(client, password);
        } catch (UnrecoverableKeyException | CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static String getPublicKey(String user, char[] password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keystore = getKeyStore(user, password);
        X509Certificate cert = (X509Certificate) keystore.getCertificate(user);
        System.out.println(base32.encodeAsString(cert.getPublicKey().getEncoded()));
        return base32.encodeAsString(cert.getPublicKey().getEncoded());
    }

    private static String obtainClientPubKey(String client) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        String publicKey;
        String clientNum = client.substring(client.length() - 1);
        if (Integer.parseInt(clientNum) == 5)
            return getPublicKey(CLIENT_1, CLIENT_1_PASS.toCharArray());
        else {
            clientNum = Integer.toString(Integer.parseInt(clientNum) + 1);
            return getPublicKey(CLIENT.concat(clientNum), CLIENT.concat(clientNum).concat(PASS).toCharArray());
        }
    }


    private static KeyStore getKeyStore(String user, char[] password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream is = new FileInputStream("src/main/resources/".concat(user).concat("_keystore.jks"));
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password);
        return keystore;
    }

    private static void register(HttpComponentsClientHttpRequestFactory requestFactory, String client, char[] password) {
        try {
            setSession(client,password);
            HttpEntity<RegisterKeyMsgBody> request = new HttpEntity<>(
                    new RegisterKeyMsgBody(currentSession.getSigAlg(), currentSession.getPublicKey().getAlgorithm(), currentSession.getHashAlgorithm()));
            ResponseEntity<String> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(REGISTER_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, String.class);
            System.out.println(response.getStatusCodeValue() + "\n");
            String nonce = response.getBody();
            System.out.println("Nonce: " + nonce);
            currentSession.setNonce(nonce);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void requestNonce(HttpComponentsClientHttpRequestFactory requestFactory, String client, char[] password) {
        try {
            setSession(client,password);
            String msgToBeHashed = gson.toJson(LedgerRequestType.GET_NONCE.name().concat(base32.encodeAsString(currentSession.getPublicKey().getEncoded())));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<String> signedBody = new SignedBody<>("", sigBytes, null);
            HttpEntity<SignedBody<String>> request = new HttpEntity<>(signedBody);
            ResponseEntity<String> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(REQUEST_NONCE_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, String.class);
            String nonce = response.getBody();
            System.out.println("Nonce: " + nonce);
            currentSession.setNonce(nonce);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void balance(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            ResponseEntity<Double> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(BALANCE_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.GET, null, Double.class);

            if (response.getStatusCode().is2xxSuccessful())
                System.out.println("Balance: " + response.getBody());

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void callObtainCoins(HttpComponentsClientHttpRequestFactory requestFactory, double amount) {
        try {
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);
            String msgToBeHashed = gson.toJson(LedgerRequestType.OBTAIN_COINS.name()).concat(gson.toJson(amount).concat(currentSession.getNonce()).concat(currentDate));
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Double> signedBody = new SignedBody<>(amount, sigBytes, currentDate);
            HttpEntity<SignedBody<Double>> request = new HttpEntity<>(signedBody);
            System.out.println(base32.encodeAsString(currentSession.getPublicKey().getEncoded()));
            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_COINS_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, ValidTransaction.class);
            System.out.println(response.getStatusCode());
            if (response.getStatusCode().is2xxSuccessful()) {
                currentSession.setNonce(Integer.toString(Integer.parseInt(currentSession.getNonce()) + 1));
                System.out.println("New Nonce: " + currentSession.getNonce());
                System.out.printf("[ %s ]\n", response.getBody());
                currentSession.saveTransaction(response.getBody());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void transferMoney(HttpComponentsClientHttpRequestFactory requestFactory, double amount) {
        try {
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);
            String destination = obtainClientPubKey(currentSession.getUsername());
            Transaction t = new Transaction(base32.encodeAsString(currentSession.getPublicKey().getEncoded()), destination, amount, currentDate);
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
                System.out.printf("[ %s ]\n", response.getBody());
                currentSession.saveTransaction(response.getBody());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfGlobalTransactions(HttpComponentsClientHttpRequestFactory requestFactory, String[] opInfo) {
        try {
            DateInterval dateInterval = getDateInterval(opInfo);
            HttpEntity<DateInterval> request = new HttpEntity<>(dateInterval);
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_GLOBAL_TRANSACTIONS_URL, port), HttpMethod.POST, request, Ledger.class);

            for (ValidTransaction t : Objects.requireNonNull(response.getBody()).getTransactions()) {
                System.out.printf("[ %s ]\n", t);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfClientTransactions(HttpComponentsClientHttpRequestFactory requestFactory, String[] opInfo ) {
        try {
            DateInterval dateInterval = getDateInterval(opInfo);
            HttpEntity<DateInterval> request = new HttpEntity<>(dateInterval);
            ResponseEntity<Ledger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(LEDGER_OF_CLIENT_TRANSACTIONS_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, Ledger.class);

            for (ValidTransaction t : Objects.requireNonNull(response.getBody()).getTransactions())
                System.out.printf("[ %s ]\n", t);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static Block obtainLastBlock(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            ResponseEntity<Block> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_LAST_BLOCK_URL,port),
                    HttpMethod.GET, null, Block.class);
            if(response.getStatusCode().is2xxSuccessful()) {
                Block block = response.getBody();
                System.out.println(gson.toJson(block));
                return block;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    private static void mineTransactions(HttpComponentsClientHttpRequestFactory requestFactory, int numberTransactions) {
        try {
            ResponseEntity<LastBlockWithMiningInfo> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(MINE_TRANSACTIONS_URL, port, numberTransactions),
                    HttpMethod.GET, null, LastBlockWithMiningInfo.class);
            if(response.getBody() != null) {
                Block lastMinedBlock = response.getBody().getLastMinedBlock();
                byte[] hashedResult = hashBlock(lastMinedBlock.getBlockHeader());
                String leftMostByte = Integer.toBinaryString(hashedResult[0] & 255 | 256).substring(1);
                String secondLeftMostByte = Integer.toBinaryString(hashedResult[1] & 255 | 256).substring(1);
                String mostSignificantBytes = leftMostByte.concat(secondLeftMostByte);
                BlockHeader blockHeader = response.getBody().getBlockHeader();
                if(mostSignificantBytes.equals(PROOF_OF_WORK_CHALLENGE) && base32.encodeAsString(hashedResult).equals(blockHeader.getPreviousHash())) {
                    System.out.println("The mined block received is valid");
                    blockHeader.setWhoSigned(base32.encodeAsString(currentSession.getPublicKey().getEncoded()));
                    BlockHeader finalBlock = startProofOfWork(blockHeader);
                    sendMinedBlock(requestFactory,finalBlock);
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void sendMinedBlock(HttpComponentsClientHttpRequestFactory requestFactory, BlockHeader blockHeader) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String currentDate = LocalDateTime.now().format(dateTimeFormatter);
        Transaction reward = new Transaction(SYSTEM,blockHeader.getWhoSigned(),20,currentDate);
        BlockHeaderAndReward blockHeaderAndReward = new BlockHeaderAndReward(blockHeader,reward);
        String msgToBeHashed = gson.toJson(LedgerRequestType.SEND_MINED_BLOCK.name()).concat(gson.toJson(blockHeaderAndReward).concat(currentSession.getNonce()));
        byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));
        SignedBody<BlockHeaderAndReward> signedBody = new SignedBody<>(blockHeaderAndReward,sigBytes,null);
        HttpEntity<SignedBody<BlockHeaderAndReward>> request = new HttpEntity<>(signedBody);
        ResponseEntity<BlockAndReward> response
                = new RestTemplate(requestFactory).exchange(
                String.format(SEND_MINED_BLOCK_URL, port), HttpMethod.POST, request, BlockAndReward.class);
        if (response.getStatusCode().is2xxSuccessful())
            currentSession.setNonce(Integer.toString(Integer.parseInt(currentSession.getNonce())+1));
        System.out.println(gson.toJson(response.getBody()));
    }

    private static BlockHeader startProofOfWork(BlockHeader blockHeader) throws NoSuchAlgorithmException {
        boolean proofOfWorkComplete = false;
        Random random = new Random();
        while (!proofOfWorkComplete) {
            int work = random.nextInt();
            blockHeader.setWork(work);
            byte[] hashedResult = hashBlock(blockHeader);
            String leftMostByte = Integer.toBinaryString(hashedResult[0] & 255 | 256).substring(1);
            String secondLeftMostByte = Integer.toBinaryString(hashedResult[1] & 255 | 256).substring(1);
            String mostSignificantBytes = leftMostByte.concat(secondLeftMostByte);
            if (mostSignificantBytes.equals(PROOF_OF_WORK_CHALLENGE)) {
                System.out.println("Proof of work complete");
                proofOfWorkComplete = true;
                String hashedResult1And0s = "";
                for(byte b: hashedResult)
                    hashedResult1And0s=hashedResult1And0s.concat(Integer.toBinaryString(b & 255 | 256).substring(1));
                System.out.println(hashedResult1And0s);
            } else
                System.out.println(mostSignificantBytes);
        }
        return blockHeader;
    }

    private static byte[] hashBlock(BlockHeader blockHeader) throws NoSuchAlgorithmException {
        byte[] block = gson.toJson(blockHeader).getBytes();
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(block);
        return hash.digest();
    }

    private static DateInterval getDateInterval(String[] opInfo) {
        String start = GENESIS_DATE;
        String end = GENESIS_DATE;
        String rangeOption = opInfo[1];
        switch (rangeOption) {
            case ALL:
                end = LocalDateTime.now().format(dateTimeFormatter);
                break;
            case UP_TO:
                end = parseDate(opInfo[2]);
                break;
            case IN_BETWEEN:
                start = parseDate(opInfo[2]);
                end = parseDate(opInfo[3]);
                break;
        }
        return new DateInterval(start, end);
    }

    private static String parseDate(String date) {
        String[] d = date.split(",");
        date = d[0].concat(" ").concat(d[1]);
        System.out.println(date);
        try {
            dateTimeFormatter.parse(date);
            return date;
        } catch (DateTimeParseException e) {
            System.out.printf("Bad date. Use the following format [%s]\n> ", DATE_FORMATTER);
        }
        return null;
    }

    private static void verify(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            String id = getTransactionId(in);
            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(VERIFY_OPERATION, port, id),
                    HttpMethod.GET, null, ValidTransaction.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Transaction verified.");
                System.out.println(response.getBody());
            } else
                System.out.println("Transaction not found.");

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static String getTransactionId(Scanner in) {
        System.out.println("Select transaction to verify:");
        List<ValidTransaction> lTransactions = currentSession.getTransactions();
        int i = 0;
        for (ValidTransaction t : lTransactions) {
            System.out.printf("%d - %s.\n", i, t.getId());
            ++i;
        }
        System.out.printf("%d - Other [ID].\n> ", i);
        int option;
        String id = "";
        while (true) {
            option = in.nextInt();
            in.nextLine();
            if (option == 0 && lTransactions.isEmpty() || !lTransactions.isEmpty() && option == lTransactions.size()) {
                System.out.print("Specify the ID: ");
                id = in.next();
                in.nextLine();
                return id;
            } else if (option < lTransactions.size()) {
                return lTransactions.get(option).getId();
            }
            System.out.print("Invalid option.\n> ");
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
        private List<ValidTransaction> transactions;

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
            this.transactions = new LinkedList<>();
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

        public List<ValidTransaction> getTransactions() {
            return transactions;
        }

        public void saveTransaction(ValidTransaction t) {
            this.transactions.add(t);
        }

    }
}
