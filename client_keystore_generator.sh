keytool -genkey -alias client1 -keyalg RSA -keypass keyPass1 -keysize 3072 -keystore keystore.jks -storepass storePass -dname "CN=FCT, OU=DI, O=CSD, L=ALMADA, ST=PRAGAL, C=CA"
keytool -genkey -alias client2 -keyalg RSA -keypass keyPass2 -keysize 3072 -keystore keystore.jks -storepass storePass -dname "CN=FCT, OU=DI, O=CSD, L=ALMADA, ST=PRAGAL, C=CA"
keytool -genkey -alias client3 -keyalg RSA -keypass keyPass3 -keysize 3072 -keystore keystore.jks -storepass storePass -dname "CN=FCT, OU=DI, O=CSD, L=ALMADA, ST=PRAGAL, C=CA"

