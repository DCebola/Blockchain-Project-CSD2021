#!/bin/sh
if [ "$#" -e 0 ]; then
    echo "Usage: create_configs.sh <n_faults> [-tls <key_type>]"
    exit 1
fi

F=$1
N=$((3*$F+1))
KEY_TYPE=$3

cd ./bft
cp host.template host.config
cp system.template system.config
mkdir ecdsakeys

for i in `seq $N`; do
    echo "${i} 172.28.20.${i} 11000 11001" >> host.config
    java -Djava.security.properties "../../replica/config/java.security" -Dlogback.configurationFile="../../replica/config/logback.xml" -cp ../../replica/target/replica-jar-with-dependencies.jar bftsmart.tom.util.ECDSAKeyPairGenerator $i secp384r1
done

echo "redis_port=8080" > redis.config
echo "system.initial.view = $(seq -s ' ' 1 $N)" >> system.config
echo "system.servers.num = ${N}" >> system.config
echo "system.servers.f = ${F}" >> system.config


if ["$#" -e 3 ]; then
    echo "system.ssltls = true" >> system.config
    echo "system.ssltls.protocol_version = TLSv1.2" >> system.config
    if [ "$KEY_TYPE" = "RSA" ]; then
        keytool -genkey -keyalg RSA -keysize 2048 -alias bftsmartRSA -keypass MySeCreT_2hMOygBwY  -keystore ./RSA_KeyPair_2048.pkcs12 -dname "CN=BFT-SMaRT"
        keytool -importkeystore -srckeystore ./RSA_KeyPair_2048.pkcs12 -destkeystore ./RSA_KeyPair_2048.pkcs12 -deststoretype pkcs12
        echo "system.ssltls.key_store_file=RSA_KeyPair_2048.pkcs12" >> system.config
        echo "system.ssltls.enabled_ciphers = TLS_RSA_WITH_AES_128_GCM_SHA256," >> system.config
    elif [ "$KEY_TYPE" = "ECDSA" ]; then
        keytool -genkey -keyalg EC -keysize 384 -alias bftsmartEC -keypass MySeCreT_2hMOygBwY  -keystore ./ecKeyPair_384.pkcs12 -dname "CN=BFT-SMaRT"
        keytool -importkeystore -srckeystore ./ecKeyPair_384.pkcs12 -destkeystore ./ecKeyPair_384.pkcs12 -deststoretype pkcs12  
        echo "system.ssltls.key_store_file=EC_KeyPair_384.pkcs12" >> system.config
        echo "system.ssltls.enabled_ciphers = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," >> system.config
    fi
fi

cp host.config ../../proxy/config
cp system.config ../../proxy/config
mv *.config ../../replica/config

cd ..












