package main.java.bftsmart.app;


import ch.qos.logback.core.net.ssl.SSL;
import com.sun.net.httpserver.HttpServer;
import main.java.bftsmart.app.services.WalletController;
import main.java.bftsmart.app.services.WalletService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.io.FileInputStream;

import javax.net.ssl.*;
import java.net.InetAddress;
import java.net.URI;


public class RESTServer {

    public static void main(String[] args) throws Exception {
        if (args.length == 2) {
            Properties server_config = new Properties();
            server_config.load(new FileInputStream(args[1])); // "/resources/configs/server.properties"
            String address = InetAddress.getLocalHost().getHostAddress();
            int port = Integer.parseInt(server_config.getProperty("port").split(",")[Integer.parseInt(args[0])]);
            String serverURI = String.format("https://%s:%s/rest", address, port);
            System.out.println(serverURI);
            HttpsURLConnection.setDefaultHostnameVerifier(new myHostnameVerifier());
            ResourceConfig config = new ResourceConfig();
            WalletService wallet = new WalletController();
            config.register(wallet.getClass());

            Security.addProvider(new BouncyCastleProvider());
            SSLContext sc = createSSLContext(server_config);
            SSLEngine engine = sc.createSSLEngine();
            engine.setEnabledCipherSuites(server_config.getProperty("ciphersuites").split(","));
            engine.setEnabledProtocols(new String[]{server_config.getProperty("ssl_protocol_version")});
            engine.setUseClientMode(Boolean.getBoolean(server_config.getProperty("client_mode")));
            engine.setNeedClientAuth(Boolean.getBoolean(server_config.getProperty("client_auth")));

            JdkHttpServerFactory.createHttpServer(URI.create(serverURI), config, sc);
        } else {
            System.out.println("Usage: RestServer <server-id> <config-path>");
        }

    }

    private static SSLContext createSSLContext(Properties config) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        SSLContext sslContext = SSLContext.getInstance(config.getProperty("ssl_context"));
        KeyStore ksKeys = KeyStore.getInstance(config.getProperty("keystore_type"));
        KeyStore ksTrust = KeyStore.getInstance(config.getProperty("truststore_type"));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(config.getProperty("key_manager_type"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(config.getProperty("trust_manager_type"));
        ksKeys.load(new FileInputStream(config.getProperty("keystore")), config.getProperty("keystore_pass").toCharArray());
        ksTrust.load(new FileInputStream(config.getProperty("truststore")), config.getProperty("truststore_pass").toCharArray());
        kmf.init(ksKeys, config.getProperty("keystore_pass").toCharArray());
        tmf.init(ksTrust);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    private static class myHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }

}