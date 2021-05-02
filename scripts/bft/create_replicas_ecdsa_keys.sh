#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: create_replicas_ecdsa_keys <num_replicas>"
    exit 1
fi

mkdir ecdsakeys
for $1 in `seq $NUM_CLIENTS`; do
	java -Djava.security.properties "../../replica/config/java.security" -Dlogback.configurationFile="../../replica/config/logback.xml" -cp ../../replica/target/replica-jar-with-dependencies.jar bftsmart.tom.util.ECDSAKeyPairGenerator $i secp384r1
