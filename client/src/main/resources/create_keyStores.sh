#keytool -genkey -alias client1 -keyalg RSA -keysize 3072 -keystore client1_keystore.jks -storepass client1Pass -dname "CN=FCT, OU=DI, L=ALMADA"
#keytool -genkey -alias client2 -keyalg RSA -keysize 3072 -keystore client2_keystore.jks -storepass client2Pass -dname "CN=FCT, OU=DI, L=ALMADA"
#keytool -genkey -alias client3 -keyalg RSA -keysize 3072 -keystore client3_keystore.jks -storepass client3Pass -dname "CN=FCT, OU=DI, L=ALMADA"

keytool -genkey -alias client1 -keyalg EC -groupname secp384r1 -keystore client1_keystore.jks -storepass client1Pass -dname "CN=FCT, OU=DI, L=ALMADA"
keytool -genkey -alias client2 -keyalg EC -groupname secp384r1 -keystore client2_keystore.jks -storepass client2Pass -dname "CN=FCT, OU=DI, L=ALMADA"
keytool -genkey -alias client3 -keyalg EC -groupname secp384r1 -keystore client3_keystore.jks -storepass client3Pass -dname "CN=FCT, OU=DI, L=ALMADA"
keytool -genkey -alias client4 -keyalg EC -groupname secp384r1 -keystore client4_keystore.jks -storepass client4Pass -dname "CN=FCT, OU=DI, L=ALMADA"
