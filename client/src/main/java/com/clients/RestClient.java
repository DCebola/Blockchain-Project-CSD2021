package com.clients;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class RestClient {

    private static final String OBTAIN_COINS_API = "https://localhost:8443/who/obtainCoins";

    public static void main(String[] args) {
        callObtainCoinsAPI();
    }


    private static void callObtainCoinsAPI() {

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

        HttpEntity<Double> request = new HttpEntity<>(50.0);
        ResponseEntity<Double> response
                = new RestTemplate(requestFactory).exchange(
                OBTAIN_COINS_API, HttpMethod.POST, request, Double.class);
        System.out.println(response.getBody());
        //assertThat(response.getStatusCode().value(), equalTo(200));
    }

}
