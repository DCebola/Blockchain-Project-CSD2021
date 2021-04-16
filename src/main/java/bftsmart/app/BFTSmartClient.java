package main.java.bftsmart.app;


import ch.qos.logback.core.net.ssl.SSL;
import com.sun.net.httpserver.HttpServer;
import main.java.bftsmart.app.services.WalletController;
import main.java.bftsmart.app.services.WalletService;
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


public class BFTSmartClient {
    public static final int CONNECTION_TIMEOUT = 30000;
    public static final int REPLY_TIMEOUT = 30000;
    public static final int MAX_RETRIES = 3;
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {

        Properties properties = new Properties();
        properties.load(new FileInputStream("./resources/configs/server.properties"));
        String address = InetAddress.getLocalHost().getHostAddress();
        int port = Integer.parseInt(properties.getProperty("port"));
        String serverURI = String.format("https://%s:%s/rest", address, port);
        System.out.println(serverURI);

        /*
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.createSSLEngine().setNeedClientAuth(false);
        */

        //Todo: Create SSLSession & SSLContext

        HttpsURLConnection.setDefaultHostnameVerifier(new myHostnameVerifier());
        //Create wallet resource
        ResourceConfig config = new ResourceConfig();
        WalletService wallet = new WalletController();
        config.register(wallet.getClass());
        JdkHttpServerFactory.createHttpServer(URI.create(serverURI), config, createSSLContext());

    }

    private static SSLContext createSSLContext() throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        KeyStore ksKeys = KeyStore.getInstance("JKS");
        KeyStore ksTrust = KeyStore.getInstance("JKS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        ksKeys.load(new FileInputStream("resources/server.ks"),"password".toCharArray());
        ksTrust.load(new FileInputStream("resources/truststore.ks"), "changeit".toCharArray());
        kmf.init(ksKeys, "password".toCharArray());
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
    }

    private static class myHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }

}