java Djdk.tls.client.protocols="TLSv1.3" Dhttps.protocols="TLSv1.3" -Djavax.net.ssl.trustStore=".target/resources/truststore.ks" -Djavax.net.ssl.trustStorePassword="changeit" -Djava.security.properties=".target/config/java.security" -Dlogback.configurationFile=".target/config/logback.xml" -cp target/wa-1-server.jar $@

