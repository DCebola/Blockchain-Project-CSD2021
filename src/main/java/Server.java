package main.java;


import main.java.controllers.WalletController;
import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.util.Properties;
import java.io.FileInputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.net.InetAddress;
import java.net.URI;


public class Server {
    public static final int CONNECTION_TIMEOUT = 30000;
    public static final int REPLY_TIMEOUT = 30000;
    public static final int MAX_RETRIES = 3;
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        properties.load(new FileInputStream("./resources/configs/server.properties"));
        String address = InetAddress.getLocalHost().getHostAddress();
        String hostName = InetAddress.getLocalHost().getHostName();
        int port = Integer.parseInt(properties.getProperty("port"));
        String serverURI = String.format("https://%s:%s/rest", address, port);
        System.out.println(serverURI);


        //Todo: Create SSLSession & SSLContext
        HttpsURLConnection.setDefaultHostnameVerifier(new myHostnameVerifier());
        //Create wallet resource
        ResourceConfig config = new ResourceConfig();
        WalletController walletController = new WalletController();
        config.register(walletController);
        JdkHttpServerFactory.createHttpServer(URI.create(serverURI), config, SSLContext.getDefault());
    }

    private static class myHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }

}