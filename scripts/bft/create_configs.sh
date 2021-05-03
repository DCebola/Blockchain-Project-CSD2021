#!/bin/sh
if [ $# -eq 0 ]; then
    echo "Usage: create_configs.sh <n_faults> [-tls <key_type>]"
    exit 1
fi

F=$1
N=$((3*$F+1))
KEY_TYPE=$3

cd ./bft
mkdir -p ../../replica/config
mkdir -p ../../proxy/config
cp hosts.template hosts.config
cp system.template system.config

echo "redis_port=6379" > redis.config
echo "system.initial.view = $(seq -s ',' 0 $(( $N - 1 )) )" >> system.config
echo "system.servers.num = ${N}" >> system.config
echo "system.servers.f = ${F}" >> system.config

for i in `seq 0 $(( $N - 1 ))`; do
    echo "${i} 172.18.20.$(( $i + 1 )) 11000 11001" >> hosts.config
done

cp hosts.config ../../replica/config
mv hosts.config ../../proxy/config

if [ $# -eq 3 ]; then
    echo "system.ssltls = true" >> system.config
    echo "system.ssltls.protocol_version = TLSv1.2" >> system.config
    mkdir -p ../../replica/config/keysSSL_TLS
    mkdir -p ../../proxy/config/keysSSL_TLS
    if [ "$KEY_TYPE" = "RSA" ]; then
        cp keysSSL_TLS/RSA* ../../replica/config/keysSSL_TLS
        cp keysSSL_TLS/RSA* ../../proxy/config/keysSSL_TLS
        echo "system.ssltls.key_store_file=RSA_KeyPair_2048.pkcs12" >> system.config
        echo "system.ssltls.enabled_ciphers = TLS_RSA_WITH_AES_128_GCM_SHA256," >> system.config
    elif [ "$KEY_TYPE" = "ECDSA" ]; then
        cp keysSSL_TLS/EC* ../../replica/config/keysSSL_TLS
        cp keysSSL_TLS/EC* ../../proxy/config/keysSSL_TLS
        echo "system.ssltls.key_store_file = EC_KeyPair_384.pkcs12" >> system.config
        echo "system.ssltls.enabled_ciphers = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," >> system.config
    fi
fi

cp system.config ../../replica/config
mv redis.config ../../replica/config
cp logback_replica.xml logback.xml
mv logback.xml ../../replica/config

mv system.config ../../proxy/config
cp logback_proxy.xml logback.xml
mv logback.xml ../../proxy/config

cd ..









