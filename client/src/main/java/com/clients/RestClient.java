package com.clients;

import com.clients.mlib.HomoAdd;
import com.clients.mlib.PaillierKey;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;


public class RestClient {

    private static final String DATE_FORMATTER = "yyyy-MM-dd HH:mm:ss";
    private static final String FIRST_DATE = "2021-01-01 01:01:01";
    private static final String SYSTEM = "SYSTEM";
    private static final String HOMOMORPHIC_INFO_CONFIG = "_homomorphic_info.config";
    private static final String CONFIGS_DIRECTORY = "src/main/resources/";

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
    private static final String TRANSFER_MONEY_WITH_PRIVACY_URL = "https://127.0.0.1:%s/privacyTransfer";

    private static final int REGISTER = 0;
    private static final int REQUEST_NONCE = 1;
    private static final int OBTAIN_COINS = 2;
    private static final int TRANSFER_MONEY = 3;
    private static final int CURRENT_AMOUNT = 4;
    private static final int GLOBAL_LEDGER = 5;
    private static final int CLIENT_LEDGER = 6;
    private static final int VERIFY_OP = 7;
    private static final int OBTAIN_LAST_BLOCK = 8;
    private static final int MINE_TRANSACTIONS = 9;
    private static final int TRANSFER_MONEY_WITH_PRIVACY = 10;
    private static final int QUIT = 11;


    private static final int ALL = 0;
    private static final int UP_TO = 1;
    private static final int IN_BETWEEN = 2;

    private static String hash_algorithm;
    private static String challenge;
    private static BigInteger reward;

    private static Gson gson;
    private static Base32 base32;
    private static Session currentSession;
    private static String port;
    private static DateTimeFormatter dateTimeFormatter;

    public static void main(String[] args) throws Exception {

        Properties properties = new Properties();
        properties.load(new FileInputStream("src/main/resources/client.config"));
        port = args[0];
        hash_algorithm = properties.getProperty("hash_algorithm");
        challenge = properties.getProperty("challenge");
        reward = new BigInteger(properties.getProperty("mining_reward"));
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
                properties.getProperty("tls_version").split(","),
                properties.getProperty("tls_ciphersuite").split(","),
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
                    balance(requestFactory, in);
                    break;
                case GLOBAL_LEDGER:
                    ledgerOfGlobalTransactions(requestFactory, in);
                    break;
                case CLIENT_LEDGER:
                    ledgerOfClientTransactions(requestFactory, in);
                    break;
                case VERIFY_OP:
                    verify(requestFactory, in);
                    break;
                case OBTAIN_LAST_BLOCK:
                    obtainLastBlock(requestFactory);
                    break;
                case MINE_TRANSACTIONS:
                    mineTransactions(requestFactory, in);
                    break;
                case TRANSFER_MONEY_WITH_PRIVACY:
                    transferMoneyWithPrivacy(requestFactory,in);
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

    private static void setSession(Scanner in) throws IOException {
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

    private static PaillierKey createHomomorphicKey(Properties properties) {
        BigInteger p = new BigInteger(properties.getProperty("p"));
        BigInteger q = new BigInteger(properties.getProperty("q"));
        BigInteger lambda = new BigInteger(properties.getProperty("lambda"));
        BigInteger n = new BigInteger(properties.getProperty("n"));
        BigInteger nsquare = new BigInteger(properties.getProperty("nsquare"));
        BigInteger g = new BigInteger(properties.getProperty("g"));
        BigInteger mu = new BigInteger(properties.getProperty("mu"));
        return new PaillierKey(p,q,lambda,n,nsquare,g,mu);
    }

    private static void printSession() {
        if (currentSession == null)
            System.out.println("[No session active]");
        else
            System.out.println("[Current session: " + base32.encodeAsString(currentSession.getPublicKey().getEncoded()) + "]\n" + currentSession.getNonce());
    }

    private static void printOps() {
        System.out.println("0 - Register");
        System.out.println("1 - Change session");
        System.out.println("2 - Obtain Coins");
        System.out.println("3 - Transfer Money");
        System.out.println("4 - Current Amount");
        System.out.println("5 - Global Ledger");
        System.out.println("6 - Client Ledger");
        System.out.println("7 - Verify transaction");
        System.out.println("8 - Obtain last block");
        System.out.println("9 - Mine transactions");
        System.out.println("10 - Transfer money with privacy");
        System.out.println("11 - Quit");
        System.out.print("> ");
    }

    private static KeyStore getKeyStore(String user, char[] password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        FileInputStream is = new FileInputStream("src/main/resources/".concat(user).concat("_keystore.jks"));
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password);
        return keystore;
    }

    private static void register(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            setSession(in);
            PaillierKey pk = currentSession.getPk();
            BigInteger encryptedZero = HomoAdd.encrypt(new BigInteger("0"),pk);
            BigInteger pkNSquare = pk.getNsquare();
            HttpEntity<RegisterKeyMsgBody> request = new HttpEntity<>(
                    new RegisterKeyMsgBody(currentSession.getSigAlg(), currentSession.getPublicKey().getAlgorithm(), currentSession.getHashAlgorithm(),encryptedZero,pkNSquare));
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

    private static void requestNonce(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            setSession(in);
            String msgToBeHashed = LedgerRequestType.GET_NONCE.name().concat(base32.encodeAsString(currentSession.getPublicKey().getEncoded()));
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


    private static void balance(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
            ResponseEntity<BigInteger> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(BALANCE_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.GET, null, BigInteger.class);

            if (response.getStatusCode().is2xxSuccessful())
                System.out.println("Balance: " + response.getBody());

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void callObtainCoins(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);
            System.out.print("Insert amount: ");
            BigInteger amount = new BigInteger(Integer.toString(in.nextInt()));
            String msgToBeHashed = LedgerRequestType.OBTAIN_COINS.name().concat(gson.toJson(amount)).concat(currentSession.getNonce()).concat(currentDate);
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<BigInteger> signedBody = new SignedBody<>(amount, sigBytes, currentDate);
            HttpEntity<SignedBody<BigInteger>> request = new HttpEntity<>(signedBody);

            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_COINS_URL, port, base32.encodeAsString(currentSession.getPublicKey().getEncoded())), HttpMethod.POST, request, ValidTransaction.class);
            processResponseWithTransaction(response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void processResponseWithTransaction(ResponseEntity<ValidTransaction> response) {
        System.out.println(response.getStatusCodeValue());
        if (response.getStatusCode().is2xxSuccessful()) {
            currentSession.setNonce(Integer.toString(Integer.parseInt(currentSession.getNonce()) + 1));
            System.out.println(currentSession.getNonce());
            System.out.printf("[ %s ]\n", response.getBody());
            currentSession.saveTransaction(response.getBody());
        }
    }

    private static void transferMoneyWithPrivacy(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) throws Exception {
        if(currentSession == null)
            requestNonce(requestFactory,in);

        String currentDate = LocalDateTime.now().format(dateTimeFormatter);
        System.out.print("Insert destination: ");
        String origin = base32.encodeAsString(currentSession.getPublicKey().getEncoded());
        String destination = in.next();
        in.nextLine();
        System.out.print("Insert amount: ");
        BigInteger amount = new BigInteger(Integer.toString(in.nextInt()));
        BigInteger encryptedAmount = HomoAdd.encrypt(amount,currentSession.getPk());
        String secretValue = encryptWithDestinationPublicKey(destination,amount);

        Transaction t = new Transaction(
                origin,
                destination,
                null,
                currentDate,
                encryptedAmount,
                origin,
                null);

        TransactionPlusSecretValue transactionPlusSecretValue = new TransactionPlusSecretValue(t,secretValue);
        String msgToBeHashed = LedgerRequestType.TRANSFER_MONEY_WITH_PRIVACY.name().
                concat(gson.toJson(t)).concat(secretValue).concat(currentSession.getNonce()).concat(currentDate);

        byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));
        SignedBody<TransactionPlusSecretValue> signedBody = new SignedBody<>(transactionPlusSecretValue,sigBytes,currentDate);
        HttpEntity<SignedBody<TransactionPlusSecretValue>> request = new HttpEntity<>(signedBody);
        ResponseEntity<ValidTransaction> response
                = new RestTemplate(requestFactory).exchange(
                String.format(TRANSFER_MONEY_WITH_PRIVACY_URL, port), HttpMethod.POST, request, ValidTransaction.class);
        processResponseWithTransaction(response);
    }

    private static void transferMoney(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
            String currentDate = LocalDateTime.now().format(dateTimeFormatter);
            System.out.print("Insert destination: ");
            String destination = in.next();
            in.nextLine();
            System.out.print("Insert amount: ");
            BigInteger amount = new BigInteger(Integer.toString(in.nextInt()));

            Transaction t = new Transaction(base32.encodeAsString(currentSession.getPublicKey().getEncoded()), destination, amount, currentDate,null,null,null);
            String msgToBeHashed = LedgerRequestType.TRANSFER_MONEY.name().concat(gson.toJson(t)).concat(currentSession.getNonce()).concat(currentDate);
            System.out.println(msgToBeHashed);
            byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));

            SignedBody<Transaction> signedBody = new SignedBody<>(t, sigBytes, currentDate);
            HttpEntity<SignedBody<Transaction>> request = new HttpEntity<>(signedBody);
            ResponseEntity<ValidTransaction> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(TRANSFER_MONEY_URL, port), HttpMethod.POST, request, ValidTransaction.class);
            processResponseWithTransaction(response);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void ledgerOfGlobalTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            DateInterval dateInterval = getDateInterval(in);
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

    private static void ledgerOfClientTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
            DateInterval dateInterval = getDateInterval(in);
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

    private static void obtainLastBlock(HttpComponentsClientHttpRequestFactory requestFactory) {
        try {
            ResponseEntity<Block> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(OBTAIN_LAST_BLOCK_URL, port),
                    HttpMethod.GET, null, Block.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                Block block = response.getBody();
                System.out.println(gson.toJson(block));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void mineTransactions(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
            System.out.print("Specify the number of transactions you want: ");
            int numberTransactions = in.nextInt();
            in.nextLine();
            ResponseEntity<BlockHeader> response
                    = new RestTemplate(requestFactory).exchange(
                    String.format(MINE_TRANSACTIONS_URL, port, numberTransactions),
                    HttpMethod.GET, null, BlockHeader.class);
            if (response.getBody() != null) {
                BlockHeader blockHeader = response.getBody();
                blockHeader.setAuthor(base32.encodeAsString(currentSession.getPublicKey().getEncoded()));
                BlockHeader finalBlock = generateProofOfWork(blockHeader);
                sendMinedBlock(requestFactory, finalBlock);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void sendMinedBlock(HttpComponentsClientHttpRequestFactory requestFactory, BlockHeader blockHeader) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String currentDate = LocalDateTime.now().format(dateTimeFormatter);
        Transaction reward = new Transaction(SYSTEM, blockHeader.getAuthor(), RestClient.reward, currentDate,null,null,null);
        BlockHeaderAndReward blockHeaderAndReward = new BlockHeaderAndReward(blockHeader, reward);
        String msgToBeHashed = LedgerRequestType.SEND_MINED_BLOCK.name().concat(gson.toJson(blockHeaderAndReward)).concat(currentSession.getNonce());
        System.out.println(msgToBeHashed);
        byte[] sigBytes = generateSignature(generateHash(msgToBeHashed.getBytes()));
        SignedBody<BlockHeaderAndReward> signedBody = new SignedBody<>(blockHeaderAndReward, sigBytes, null);
        System.out.println(gson.toJson(signedBody.getContent()));
        HttpEntity<SignedBody<BlockHeaderAndReward>> request = new HttpEntity<>(signedBody);
        ResponseEntity<ValidTransaction> response
                = new RestTemplate(requestFactory).exchange(
                String.format(SEND_MINED_BLOCK_URL, port), HttpMethod.POST, request, ValidTransaction.class);
        processResponseWithTransaction(response);
    }


    private static BlockHeader generateProofOfWork(BlockHeader blockHeader) throws NoSuchAlgorithmException {
        Random random = new Random();
        while (true) {
            int proof = random.nextInt();
            blockHeader.setProof(proof);
            byte[] PoW = hashBlock(blockHeader);
            String mostSignificantBytes = Utils.getMostSignificantBytes((challenge.length() / Byte.SIZE), PoW);
            if (mostSignificantBytes.equals(challenge)) {
                System.out.println("Proof of work complete");
                String bits = "";
                for (byte b : PoW)
                    bits = bits.concat(Integer.toBinaryString(b & 255 | 256).substring(1));
                System.out.println(bits);
                return blockHeader;
            } else
                System.out.println(mostSignificantBytes);
        }
    }

    private static byte[] hashBlock(BlockHeader blockHeader) throws NoSuchAlgorithmException {
        byte[] block = gson.toJson(blockHeader).getBytes();
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(block);
        return hash.digest();
    }

    private static DateInterval getDateInterval(Scanner in) {
        System.out.println("Select the range option:");
        System.out.println("0 - All transactions.");
        System.out.println("1 - All transactions before [date].");
        System.out.println("2 - All transactions in [date-interval].");
        System.out.print("> ");
        int rangeOption = in.nextInt();
        in.nextLine();
        String start = FIRST_DATE;
        String end = FIRST_DATE;
        switch (rangeOption) {
            case ALL:
                end = LocalDateTime.now().format(dateTimeFormatter);
                break;
            case UP_TO:
                System.out.printf("Specify the END DATE in the following format [%s]\nDate: ", DATE_FORMATTER);
                end = parseDate(in);
                break;
            case IN_BETWEEN:
                System.out.printf("Specify the START DATE in the following format [%s]\nDate: ", DATE_FORMATTER);
                start = parseDate(in);
                System.out.printf("Specify the END DATE in the following format [%s]\nDate: ", DATE_FORMATTER);
                end = parseDate(in);
                break;
        }
        return new DateInterval(start, end);
    }

    private static String parseDate(Scanner in) {
        String date;
        while (true) {
            try {
                date = in.nextLine();
                dateTimeFormatter.parse(date);
                return date;
            } catch (DateTimeParseException e) {
                System.out.printf("Bad date. Use the following format [%s]\n> ", DATE_FORMATTER);
            }
        }
    }

    private static void verify(HttpComponentsClientHttpRequestFactory requestFactory, Scanner in) {
        try {
            if (currentSession == null)
                requestNonce(requestFactory, in);
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

    private static String encryptWithDestinationPublicKey(String pubKey, BigInteger amount) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(base32.decode(pubKey)));
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipheredText = encryptCipher.doFinal(amount.toString().getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipheredText);
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
        private PaillierKey pk;

        public Session(String username, char[] password) throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
            Properties properties = new Properties();
            properties.load(new FileInputStream(CONFIGS_DIRECTORY.concat(username).concat(HOMOMORPHIC_INFO_CONFIG)));
            this.pk = createHomomorphicKey(properties);
            this.nonce = "";
            this.username = username;
            this.password = password;
            KeyStore keystore = getKeyStore(username, password);
            X509Certificate cert = (X509Certificate) keystore.getCertificate(username);
            this.publicKey = cert.getPublicKey();
            this.privateKey = (PrivateKey) keystore.getKey(username, password);
            this.sigAlg = cert.getSigAlgName();
            this.hashAlgorithm = hash_algorithm;
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

        public PaillierKey getPk() {
            return pk;
        }

    }
}




