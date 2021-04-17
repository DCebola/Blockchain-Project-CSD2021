package main.java.bftsmart.app.clients;

import main.java.bftsmart.app.services.*;
import org.glassfish.jersey.client.ClientConfig;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class CurrentAmountClient {

    public static void main(String[] args) throws UnknownHostException {
        System.out.println("hi");
        String address = InetAddress.getLocalHost().getHostAddress();
        int port = 8080;
        String serverURI = "https://127.0.1.1:8080/rest";
        System.out.println(serverURI);




        ClientConfig config = new ClientConfig();
        Client client = ClientBuilder.newClient(config);
        HttpsURLConnection.setDefaultHostnameVerifier(new myHostnameVerifier());
        WebTarget target = client.target(serverURI).path(LedgerService.PATH).path("/").path("owner").path("/balance");
        System.out.println(target.getUri());
        Response r = target.request().accept(MediaType.APPLICATION_JSON).get();
        if(r.getStatus() == Response.Status.OK.getStatusCode())
            System.out.println("Success, obtained message with id: " + r.readEntity(Integer.class));
        else
            System.out.println("Error, HTTP error status " + r.getStatus());;


    }

    private static class myHostnameVerifier implements HostnameVerifier {

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return true;
        }
    }

}
