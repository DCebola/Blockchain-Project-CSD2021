import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultSingleRecoverable;
import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.Properties;

public class BFTSmartSandbox extends DefaultSingleRecoverable {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String INITIAL_NONCE = "0";
    private static final String NO_NONCE = "-1";

    private static final String SYSTEM = "SYSTEM";
    private static final String ERROR_MSG = "ERROR";
    private static final String PENDING_TRANSACTIONS = "PENDING-TRANSACTIONS";
    private static final String PENDING_REWARD = "PENDING-REWARDS";
    private static final String BLOCK_CHAIN = "BLOCK-CHAIN";


    private static final int KEY_ALGORITHM = 0;
    private static final int SIGNATURE_ALGORITHM = 1;
    private static final int HASH_ALGORITHM = 2;
    private static final int WALLET_NONCE = 3;
    private static final int TRANSACTION_ID_SIZE = 20;

    private static final String NORMAL_TRANSACTION_ID_PREFIX = "0xT";
    private static final String REWARD_TRANSACTION_ID_PREFIX = "0xTB";

    private final Logger logger;
    private Jedis jedis;
    private final Gson gson;
    private final Base32 base32;
    private final int id;
    private final JedisPool jedisPool;
    private final String hash_algorithm;

    public BFTSmartSandbox(int id) throws IOException {
        this.id = id;
        this.logger = LoggerFactory.getLogger(this.getClass().getName());
        this.base32 = new Base32();
        this.gson = new Gson();
        Properties properties = new Properties();
        properties.load(new FileInputStream("config/replica.config"));
        this.hash_algorithm = properties.getProperty("hash_algorithm");

        String redisPort = properties.getProperty("redis_port");
        String redis_ip = "172.18.30.".concat(Integer.toString(id));
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMaxTotal(Integer.parseInt(properties.getProperty("max_total")));
        jedisPoolConfig.setMaxIdle(Integer.parseInt(properties.getProperty("max_idle")));
        jedisPoolConfig.setMinIdle(Integer.parseInt(properties.getProperty("min_idle")));
        this.jedisPool = new JedisPool(jedisPoolConfig, redis_ip, Integer.parseInt(redisPort)); //TODO: ENABLE TLS

        new ServiceReplica(id, this, this);

    }

    /****************************************++**** Ordered requests **************************************************/

    @Override
    public byte[] appExecuteOrdered(byte[] command, MessageContext messageContext) {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(command);
            ObjectInput objIn = new ObjectInputStream(byteIn);
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutput objOut = new ObjectOutputStream(byteOut);
            /*
            LedgerRequestType reqType = (SandboxRequestType) objIn.readObject();
            switch (reqType) {
                case UPDATE_STATE:
                    break;
                case TEST_CONTRACT:
                    break;
            }*/
            objOut.flush();
            byteOut.flush();
            return byteOut.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return ERROR_MSG.getBytes();
        }
    }

    /******************************************** Unordered requests **************************************************/

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext messageContext) {
        return new byte[]{};
    }

    /************************************************ Auxiliary methods ***********************************************/

    /************************************************ Auxiliary Response methods **************************************/

    private void writeReplicaDecision(ObjectOutput objOut, byte[] hash, boolean decision) throws IOException {
        objOut.writeInt(id);
        objOut.writeObject(hash);
        objOut.writeBoolean(decision);
    }

    /*** Ordered requests' responses **/


    /*** Unordered requests' responses **/


    /************************************************* Snapshot methods ***********************************************/

    @Override
    public void installSnapshot(byte[] bytes) {

    }

    @Override
    public byte[] getSnapshot() {
        return new byte[0];
    }
}
