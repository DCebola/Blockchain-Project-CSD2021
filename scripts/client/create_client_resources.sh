#!/bin/sh
NUM_CLIENTS=$1
KEY_TYPE=$2
HASH_ALG=$3

if [ "$#" -ne 3 ]; then
    echo "Usage: create_client_resources <num_clients> <key_type> <hash_algorithm>"
    exit 1
fi

cd ./client

#yes | keytool -import -file ./tomcat.cer -alias serverCA -keystore truststore.jks -storepass truststorePass

# Create keystores
for i in `seq $NUM_CLIENTS`; do
	alias="client${i}"
	keystore="${alias}_keystore.jks"
	pass="${alias}Pass"
	if [ "$KEY_TYPE" = "RSA" ]; then
		keytool -genkey -alias $alias -keyalg RSA -keysize 3072 -keystore $keystore -storepass $pass -dname "CN=FCT, OU=DI, L=ALMADA"
	elif [ "$KEY_TYPE" = "ECDSA" ]; then
		keytool -genkey -alias $alias -keyalg EC -groupname secp384r1 -keystore $keystore -storepass $pass -dname "CN=FCT, OU=DI, L=ALMADA"
	fi
	echo Created keypair for client$i 
done

cp *.jks ../../client/src/main/resources
rm client*
echo "server.port=8080" > application.properties
echo "hash_algorithm=${HASH_ALG}" >> application.properties
mv application.properties ../../client/src/main/resources

cd ..
